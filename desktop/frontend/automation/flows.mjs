/**
 * Reusable UI flows for automation scripts, mirroring the selectors the
 * Playwright e2e suite uses. Each takes an AppHandle from driver.mjs.
 */

import { assert } from "./driver.mjs";

/** Fresh-profile first-run: create an account and land in the main app. */
export async function createAccount(app, username, password) {
  await app.storageSet("accord-onboarding-complete", "true");
  await app.waitFor("text=Create Account", 15000);
  await app.click("text=Create Account");
  await app.waitFor('input[placeholder*="Choose a username"]', 5000);
  await app.type('input[placeholder*="Choose a username"]', username);
  await app.type('input[placeholder*="How others will see you"]', username);
  await app.type('input[placeholder*="Choose a password"]', password);
  await app.type('input[placeholder*="Confirm your password"]', password);
  await app.click("button.btn-green");
  await app.waitFor("text=Backup Your Recovery Phrase", 15000);
  const mnemonic = (await app.text(".auth-info-box")).trim();
  assert(mnemonic.split(/\s+/).length >= 12, "mnemonic has 12+ words");
  await app.click("text=I've saved my recovery phrase");
  await app.waitGone(".auth-page", 15000);
  return mnemonic;
}

export async function createNode(app, name) {
  await app.waitFor('[title="Join or Create Node"]', 10000);
  await app.click('[title="Join or Create Node"]');
  await app.waitFor("text=Create a New Node", 5000);
  await app.click("text=Create a New Node");
  await app.waitFor('input[placeholder="My Community"]', 5000);
  await app.type('input[placeholder="My Community"]', name);
  await app.click("text=Create Node");
  await app.waitGone('input[placeholder="My Community"]', 10000);
  await app.waitFor(`text=${name}`, 10000);
}

/** Open the server menu, read the invite link, close the modal. */
export async function getInviteLink(app) {
  await app.click(".server-header-button");
  await app.waitFor("text=Invite People", 5000);
  await app.click("text=Invite People");
  await app.waitFor(".invite-link-text:not(.invite-link-loading)", 10000);
  const invite = (await app.text(".invite-link-text")).trim();
  assert(invite.length > 0, "invite link non-empty");
  await app.press("Escape");
  await app.waitGone(".invite-link-text", 5000);
  return invite;
}

export async function joinNodeViaInvite(app, invite, nodeName) {
  await app.waitFor('[title="Join or Create Node"]', 10000);
  await app.click('[title="Join or Create Node"]');
  await app.waitFor('input[placeholder*="accord://"]', 5000);
  await app.type('input[placeholder*="accord://"]', invite);
  await app.click("text=Join Node");
  await app.waitFor(`text=${nodeName}`, 15000);
}

/** Send a message in the currently open text channel and wait for local echo. */
export async function sendMessage(app, text) {
  await app.waitFor("textarea.message-input", 10000);
  await app.type("textarea.message-input", text);
  await app.press("Enter", "textarea.message-input");
  await app.waitFor(`text=${text}`, 10000);
}

/** Fail the run if a client logged console/window errors (with optional allowlist). */
export async function assertNoConsoleErrors(app, label, allow = []) {
  const logs = await app.console();
  const errors = logs.filter(
    (l) =>
      (l.level === "error" || l.level === "window-error") &&
      !allow.some((pat) => l.text.includes(pat))
  );
  for (const e of errors) console.log(`  [${label}:${e.level}] ${e.text}`);
  assert(errors.length === 0, `${label} has no console errors`);
}
