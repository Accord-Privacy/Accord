/**
 * Desktop smoke test: fresh identity → create node → send message, driven
 * through the automation bridge against the real desktop binary.
 *
 * Prereqs:
 *   - relay on :8080  (./target/debug/accord-server --no-tls)
 *   - automation-enabled app build (see automation/README.md)
 *
 * Usage:
 *   node automation/smoke.mjs <path-to-app-binary-or-AppImage>
 */

import { AutomationHub, assert, step } from "./driver.mjs";

const bin = process.argv[2];
if (!bin) {
  console.error("usage: node automation/smoke.mjs <app-binary-or-AppImage>");
  process.exit(1);
}

const USERNAME = `smoke_${Date.now().toString(36)}`;
const PASSWORD = "smoke-test-passw0rd!";
const NODE_NAME = "Smoke Node";
const MESSAGE = `hello from automation ${Date.now()}`;

const hub = new AutomationHub();
let app;

try {
  step("launch app (fresh profile)");
  app = await hub.launch({ bin, profile: "smoke", fresh: true });
  console.log("connected:", app.instanceId);

  step("skip onboarding tour + wait for setup wizard");
  await app.storageSet("accord-onboarding-complete", "true");
  await app.waitFor("text=Create Account", 15000);

  step("create account");
  await app.click("text=Create Account");
  await app.waitFor('input[placeholder*="Choose a username"]', 5000);
  await app.type('input[placeholder*="Choose a username"]', USERNAME);
  await app.type('input[placeholder*="How others will see you"]', USERNAME);
  await app.type('input[placeholder*="Choose a password"]', PASSWORD);
  await app.type('input[placeholder*="Confirm your password"]', PASSWORD);
  await app.click("button.btn-green");

  step("mnemonic step");
  await app.waitFor("text=Backup Your Recovery Phrase", 15000);
  const mnemonic = (await app.text(".auth-info-box")).trim();
  assert(mnemonic.split(/\s+/).length >= 12, "mnemonic has 12+ words");
  console.log("clicked:", await app.click("text=I've saved my recovery phrase"));

  step("authenticated app layout");
  await app.waitGone(".auth-page", 15000);

  step("create node");
  await app.waitFor('[title="Join or Create Node"]', 10000);
  await app.click('[title="Join or Create Node"]');
  await app.waitFor("text=Join a Node", 5000);
  await app.click("text=Create a New Node");
  await app.waitFor('input[placeholder="My Community"]', 5000);
  await app.type('input[placeholder="My Community"]', NODE_NAME);
  await app.click("text=Create Node");
  await app.waitGone('input[placeholder="My Community"]', 10000);
  await app.waitFor(`text=${NODE_NAME}`, 10000);

  step("send message");
  await app.waitFor("textarea.message-input", 10000);
  await app.type("textarea.message-input", MESSAGE);
  await app.press("Enter", "textarea.message-input");
  await app.waitFor(`text=${MESSAGE}`, 10000);

  step("check for console errors");
  const logs = await app.console();
  const errors = logs.filter(
    (l) => l.level === "error" || l.level === "window-error"
  );
  if (errors.length) {
    console.log("console errors during run:");
    for (const e of errors) console.log(`  [${e.level}] ${e.text}`);
  }

  console.log("\nSMOKE PASS —", USERNAME, "created node + sent message");
  process.exitCode = 0;
} catch (e) {
  console.error("\nSMOKE FAIL:", e.message);
  if (app) {
    const snap = await app.snapshot(3000).catch(() => "(snapshot failed)");
    console.error("DOM head:", snap.slice(0, 3000));
    const logs = await app.console().catch(() => []);
    console.error("console tail:");
    for (const l of logs.slice(-15)) console.error(`  [${l.level}] ${l.text}`);
  }
  process.exitCode = 1;
} finally {
  app?.kill();
  hub.close();
}
