/**
 * Dev-only automation bridge.
 *
 * Lets an external test driver (see ../../automation/) drive the running app:
 * the app connects OUT to a local WebSocket hub and executes JSON commands
 * (eval / click / type / waitFor / query / console) against the live DOM.
 *
 * SECURITY: this module must never ship in a release build. It is only
 * imported from main.tsx when `import.meta.env.DEV` or
 * `VITE_ACCORD_AUTOMATION === '1'` (build-time constants — Vite dead-code
 * eliminates the dynamic import in production builds). scripts/release.sh
 * additionally asserts the marker string below is absent from dist/.
 * The hub is bound to 127.0.0.1 and exists only while a driver runs.
 */

export const AUTOMATION_MARKER = "__ACCORD_AUTOMATION_BRIDGE__";

const PORT = 9631;
const RECONNECT_MS = 2000;

type Cmd = {
  id: number;
  cmd: string;
  args?: Record<string, unknown>;
};

// ---- console / error capture (from module load) ----

type LogEntry = { level: string; text: string; ts: number };
const logBuffer: LogEntry[] = [];
const MAX_LOG = 500;

function pushLog(level: string, parts: unknown[]) {
  const text = parts
    .map((p) => {
      if (typeof p === "string") return p;
      if (p instanceof Error)
        return `${p.name}: ${p.message}\n${(p.stack || "").split("\n").slice(1, 4).join("\n")}`;
      try {
        const s = JSON.stringify(p);
        // JSON.stringify flattens DOMException/Error-likes to {}
        return s === "{}" && p && typeof p === "object" ? String(p) : s;
      } catch {
        return String(p);
      }
    })
    .join(" ");
  logBuffer.push({ level, text, ts: Date.now() });
  if (logBuffer.length > MAX_LOG) logBuffer.shift();
}

for (const level of ["log", "warn", "error", "info"] as const) {
  const orig = console[level].bind(console);
  console[level] = (...args: unknown[]) => {
    pushLog(level, args);
    orig(...args);
  };
}
window.addEventListener("error", (e) =>
  pushLog("window-error", [e.message, e.filename, e.lineno])
);
window.addEventListener("unhandledrejection", (e) =>
  pushLog("unhandled-rejection", [String(e.reason)])
);

// ---- DOM helpers ----

function findAll(selector: string): Element[] {
  return Array.from(document.querySelectorAll(selector));
}

/** Find element by CSS selector, or by `text=Visible Label` (any element). */
function find(target: string): Element | null {
  if (target.startsWith("text=")) {
    const wanted = target.slice(5).trim();
    const all = findAll("body *");
    // Innermost exact match first (no child of it also matches exactly),
    // then innermost short-enough partial match.
    const exact = all.filter((el) => (el.textContent || "").trim() === wanted);
    const innerExact = exact.filter(
      (el) => !exact.some((other) => other !== el && el.contains(other))
    );
    if (innerExact.length) return innerExact[0];
    const partial = all.filter((el) => {
      const txt = (el.textContent || "").trim();
      return txt.includes(wanted) && txt.length < wanted.length + 80;
    });
    const innerPartial = partial.filter(
      (el) => !partial.some((other) => other !== el && el.contains(other))
    );
    return innerPartial[0] || null;
  }
  return document.querySelector(target);
}

function isVisible(el: Element): boolean {
  const r = (el as HTMLElement).getBoundingClientRect();
  return r.width > 0 && r.height > 0;
}

function click(target: string): string {
  const el = find(target);
  if (!el) throw new Error(`click: no element for ${target}`);
  (el as HTMLElement).click();
  return describe(el);
}

/** React-compatible typing: use the native value setter so React's onChange fires. */
function type(target: string, text: string): string {
  const el = find(target);
  if (!el) throw new Error(`type: no element for ${target}`);
  const input = el as HTMLInputElement | HTMLTextAreaElement;
  const proto =
    input.tagName === "TEXTAREA"
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")!.set!;
  input.focus();
  setter.call(input, text);
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return describe(input);
}

/** Press a key on a target (or the active element). Enough for Enter-to-send. */
function press(key: string, target?: string): void {
  const el = (target ? find(target) : document.activeElement) as HTMLElement | null;
  if (!el) throw new Error(`press: no element`);
  const opts = { key, bubbles: true, cancelable: true };
  el.dispatchEvent(new KeyboardEvent("keydown", opts));
  el.dispatchEvent(new KeyboardEvent("keyup", opts));
}

function describe(el: Element): string {
  const id = el.id ? `#${el.id}` : "";
  const cls = el.className && typeof el.className === "string"
    ? "." + el.className.trim().split(/\s+/).slice(0, 3).join(".")
    : "";
  const txt = (el.textContent || "").trim().slice(0, 60);
  return `<${el.tagName.toLowerCase()}${id}${cls}> "${txt}"`;
}

function query(selector: string): unknown[] {
  return findAll(selector).map((el) => ({
    desc: describe(el),
    text: (el.textContent || "").trim().slice(0, 200),
    visible: isVisible(el),
    value: (el as HTMLInputElement).value ?? undefined,
  }));
}

function waitFor(
  target: string,
  timeoutMs: number,
  gone: boolean
): Promise<string> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const tick = () => {
      const el = find(target);
      const present = el !== null && isVisible(el);
      if (present !== gone) {
        resolve(el ? describe(el) : "gone");
        return;
      }
      if (Date.now() - start > timeoutMs) {
        reject(
          new Error(
            `waitFor timeout (${timeoutMs}ms): ${target} ${gone ? "still present" : "not found"}`
          )
        );
        return;
      }
      setTimeout(tick, 100);
    };
    tick();
  });
}

// ---- command dispatch ----

async function execute(cmd: Cmd): Promise<unknown> {
  const a = cmd.args || {};
  switch (cmd.cmd) {
    case "ping":
      return "pong";
    // No eval/Function command: Tauri's CSP (script-src 'self' + hashes) forbids
    // dynamic code even in dev builds, and structured commands keep the surface
    // auditable. Add new commands here as testing needs grow.
    case "storage": {
      const key = String(a.key);
      switch (a.action) {
        case "get":
          return localStorage.getItem(key);
        case "set":
          localStorage.setItem(key, String(a.value));
          return "ok";
        case "remove":
          localStorage.removeItem(key);
          return "ok";
        case "keys":
          return Object.keys(localStorage);
        default:
          throw new Error(`storage: unknown action ${a.action}`);
      }
    }
    case "click":
      return click(String(a.target));
    case "type":
      return type(String(a.target), String(a.text));
    case "press":
      press(String(a.key), a.target ? String(a.target) : undefined);
      return "ok";
    case "query":
      return query(String(a.selector));
    case "waitFor":
      return await waitFor(
        String(a.target),
        Number(a.timeoutMs ?? 10000),
        Boolean(a.gone)
      );
    case "snapshot": {
      const html = document.body.outerHTML;
      const max = Number(a.maxLen ?? 100_000);
      return html.length > max ? html.slice(0, max) + "…[truncated]" : html;
    }
    case "console": {
      const since = Number(a.since ?? 0);
      return logBuffer.filter((e) => e.ts > since);
    }
    case "title":
      return { title: document.title, url: location.href, origin: location.origin };
    case "http": {
      // Network probe from inside the webview (CSP/CORS/mixed-content behave
      // exactly as they do for app code, unlike an external curl).
      try {
        const resp = await fetch(String(a.url), {
          method: String(a.method ?? "GET"),
          headers: a.body ? { "Content-Type": "application/json" } : undefined,
          body: a.body ? String(a.body) : undefined,
        });
        const body = await resp.text();
        return { status: resp.status, body: body.slice(0, 500) };
      } catch (e) {
        return { error: String(e) };
      }
    }
    default:
      throw new Error(`unknown cmd: ${cmd.cmd}`);
  }
}

// ---- hub connection (app dials out; retries while no driver is running) ----

const instanceId = crypto.randomUUID();
let ws: WebSocket | null = null;

function connect() {
  try {
    ws = new WebSocket(`ws://127.0.0.1:${PORT}`);
  } catch {
    setTimeout(connect, RECONNECT_MS);
    return;
  }
  ws.onopen = () => {
    ws!.send(
      JSON.stringify({
        hello: true,
        instanceId,
        marker: AUTOMATION_MARKER,
        title: document.title,
        userAgent: navigator.userAgent,
      })
    );
  };
  ws.onmessage = async (ev) => {
    let cmd: Cmd;
    try {
      cmd = JSON.parse(String(ev.data));
    } catch {
      return;
    }
    try {
      const result = await execute(cmd);
      ws!.send(JSON.stringify({ id: cmd.id, ok: true, result }));
    } catch (e) {
      ws!.send(
        JSON.stringify({ id: cmd.id, ok: false, error: String(e) })
      );
    }
  };
  ws.onclose = () => setTimeout(connect, RECONNECT_MS);
  ws.onerror = () => ws?.close();
}

connect();
console.info(`[automation] bridge active, instance ${instanceId}`);
