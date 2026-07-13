/**
 * Desktop automation driver.
 *
 * Counterpart to src/dev/automationBridge.ts: runs a WebSocket hub on
 * 127.0.0.1:9631, launches app instances with isolated XDG dirs, and hands
 * back an AppHandle per instance for scripting (click/type/waitFor/eval/...).
 *
 * Dev tooling only — never part of any build. See README.md for usage.
 */

import { WebSocketServer } from "ws";
import { spawn } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const PORT = 9631;

export class AutomationHub {
  constructor() {
    this.pending = []; // resolvers waiting for the next app connection
    this.wss = new WebSocketServer({ host: "127.0.0.1", port: PORT });
    this.wss.on("connection", (ws) => {
      ws.once("message", (data) => {
        let hello;
        try {
          hello = JSON.parse(String(data));
        } catch {
          return ws.close();
        }
        if (!hello.hello || !hello.instanceId) return ws.close();
        const handle = new AppHandle(ws, hello);
        const waiter = this.pending.shift();
        if (waiter) waiter(handle);
      });
    });
  }

  /** Resolves with an AppHandle when the next app instance connects. */
  nextConnection(timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error("timed out waiting for app to connect")),
        timeoutMs
      );
      this.pending.push((h) => {
        clearTimeout(timer);
        resolve(h);
      });
    });
  }

  /**
   * Spawn an app instance with an isolated profile (own XDG config/data/cache,
   * so localStorage, webview storage and ~/.config/accord don't collide) and
   * wait for its bridge to connect.
   *
   * opts.bin      — path to app binary or AppImage (required)
   * opts.profile  — profile name; same name = same persistent state across runs
   * opts.env      — extra env vars
   * opts.fresh    — wipe the profile dir before launch (default true)
   */
  async launch(opts) {
    const profile = opts.profile ?? "default";
    const root = join(tmpdir(), "accord-automation", profile);
    if (opts.fresh ?? true) rmSync(root, { recursive: true, force: true });
    for (const d of ["config", "data", "cache", "state"])
      mkdirSync(join(root, d), { recursive: true });

    const child = spawn(opts.bin, opts.args ?? [], {
      env: {
        ...process.env,
        XDG_CONFIG_HOME: join(root, "config"),
        XDG_DATA_HOME: join(root, "data"),
        XDG_CACHE_HOME: join(root, "cache"),
        XDG_STATE_HOME: join(root, "state"),
        WEBKIT_DISABLE_DMABUF_RENDERER: "1", // NVIDIA blank-window workaround
        ACCORD_MOCK_MEDIA: "1", // WebKit mock capture devices — voice without real mic
        APPIMAGE_EXTRACT_AND_RUN: "1",
        NO_STRIP: "1",
        ...opts.env,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    child.stdout.on("data", (d) => process.env.AUTOMATION_VERBOSE && process.stdout.write(`[${profile}] ${d}`));
    child.stderr.on("data", (d) => process.env.AUTOMATION_VERBOSE && process.stderr.write(`[${profile}] ${d}`));

    const handle = await this.nextConnection();
    handle.child = child;
    handle.profile = profile;
    handle.profileRoot = root;
    return handle;
  }

  close() {
    this.wss.close();
    for (const c of this.wss.clients) c.terminate();
  }
}

export class AppHandle {
  constructor(ws, hello) {
    this.ws = ws;
    this.instanceId = hello.instanceId;
    this.nextId = 1;
    this.inflight = new Map();
    ws.on("message", (data) => {
      let msg;
      try {
        msg = JSON.parse(String(data));
      } catch {
        return;
      }
      const p = this.inflight.get(msg.id);
      if (!p) return;
      this.inflight.delete(msg.id);
      msg.ok ? p.resolve(msg.result) : p.reject(new Error(msg.error));
    });
    ws.on("close", () => {
      for (const p of this.inflight.values())
        p.reject(new Error("app disconnected"));
      this.inflight.clear();
    });
  }

  send(cmd, args = {}, timeoutMs = 30000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.inflight.delete(id);
        reject(new Error(`command ${cmd} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.inflight.set(id, {
        resolve: (v) => (clearTimeout(timer), resolve(v)),
        reject: (e) => (clearTimeout(timer), reject(e)),
      });
      this.ws.send(JSON.stringify({ id, cmd, args }));
    });
  }

  // Targets: CSS selector, or "text=Visible Label".
  click(target) { return this.send("click", { target }); }
  type(target, text) { return this.send("type", { target, text }); }
  select(target, value) { return this.send("select", { target, value }); }
  press(key, target) { return this.send("press", { key, target }); }
  query(selector) { return this.send("query", { selector }); }
  waitFor(target, timeoutMs = 10000) { return this.send("waitFor", { target, timeoutMs }, timeoutMs + 5000); }
  waitGone(target, timeoutMs = 10000) { return this.send("waitFor", { target, timeoutMs, gone: true }, timeoutMs + 5000); }
  http(url, method, body) { return this.send("http", { url, method, body }); }
  storageGet(key) { return this.send("storage", { action: "get", key }); }
  storageSet(key, value) { return this.send("storage", { action: "set", key, value }); }
  storageKeys() { return this.send("storage", { action: "keys" }); }
  token() { return this.send("token"); }
  snapshot(maxLen) { return this.send("snapshot", { maxLen }); }
  console(since = 0) { return this.send("console", { since }); }
  title() { return this.send("title"); }

  async text(selector) {
    const els = await this.query(selector);
    return els.map((e) => e.text).join("\n");
  }

  kill() {
    if (this.child && !this.child.killed) this.child.kill("SIGTERM");
  }
}

/** Convenience assert for test scripts. */
export function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
}

export function step(name) {
  process.stdout.write(`\n== ${name}\n`);
}
