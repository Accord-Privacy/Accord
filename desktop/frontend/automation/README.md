# Desktop Automation Harness (dev only)

Drives the **real desktop app** (Tauri binary or AppImage) programmatically —
click, type, wait, eval, read console — via a dev-only WebSocket bridge.
Complements the browser Playwright e2e suite (`e2e/`), which cannot exercise
the Tauri shell (keyring, config commands, updater, WebKitGTK quirks).

## How it works

- `src/dev/automationBridge.ts` is imported by `main.tsx` **only** when
  `import.meta.env.DEV` or `VITE_ACCORD_AUTOMATION=1` — both build-time
  constants, so production builds tree-shake the module out entirely.
  `scripts/release.sh` additionally fails if the marker string
  `__ACCORD_AUTOMATION_BRIDGE__` appears in `frontend/dist`.
- The app dials out to `ws://127.0.0.1:9631` (retrying quietly); a driver
  script (`automation/driver.mjs`) runs the hub and sends JSON commands.
- Each launched instance gets isolated `XDG_*` dirs (own localStorage,
  webview data, `~/.config/accord`), so multi-client scenarios (two apps
  talking through the relay) work on one machine. Profiles live under
  `$TMPDIR/accord-automation/<profile>`; reuse a profile name with
  `fresh: false` to test persistence/re-login.
- `WEBKIT_DISABLE_DMABUF_RENDERER=1` is set automatically (NVIDIA workaround).

## Running

```bash
# 1. relay
./target/debug/accord-server --no-tls &

# 2. automation-enabled build (frontend with bridge + debug binary)
cd desktop/frontend
npm run auto:build

# 3. smoke test
npm run auto:smoke
```

Ad-hoc driving from a script:

```js
import { AutomationHub } from "./driver.mjs";
const hub = new AutomationHub();
const alice = await hub.launch({ bin, profile: "alice" });
const bob = await hub.launch({ bin, profile: "bob" });
await alice.click("text=Create Account");
await alice.storageGet("accord_server_url");
```

Handle API: `click(target)`, `type(target, text)`, `press(key, target?)`,
`waitFor/waitGone(target, ms)`, `query(sel)`, `text(sel)`,
`storageGet/Set/Keys`, `snapshot()`, `console()`, `title()`, `kill()`.
Targets are CSS selectors or `text=Visible Label`.

Note: there is deliberately no `eval` command — Tauri's CSP forbids dynamic
code (`script-src 'self'` + hashes) even in dev builds, and structured
commands keep the bridge auditable. Extend `automationBridge.ts` with new
commands as testing needs grow.

## Release safety

Three layers keep this out of user builds:

1. Build-time gate in `main.tsx` (dead-code eliminated unless dev/flagged).
2. `scripts/release.sh` greps `frontend/dist` for the marker and aborts.
3. Bridge binds only to localhost and merely *connects out* — there is no
   listener in the app; without a local hub it is inert even in dev.
