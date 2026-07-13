/**
 * Duress password end-to-end:
 *  1. Create a real account, a node, and a message (real data on the device).
 *  2. Set a duress password in Settings → Danger zone.
 *  3. Log out, then log in with the DURESS password.
 *  4. Verify the real account was destroyed (node gone, duress config gone,
 *     real identity gone) and an empty decoy account is shown instead.
 *
 * Prereqs: relay on :8080, automation build. Usage: node automation/duress.mjs [bin]
 */

import { AutomationHub, assert, step } from './driver.mjs';
import { createAccount, createNode, sendMessage } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const RUN = Date.now().toString(36);
const USER = `real_${RUN}`;
const REAL_PW = 'real-account-passw0rd!';
const DURESS_PW = 'duress-passw0rd-9!';
const NODE = `SecretNode-${RUN}`;
const SECRET_MSG = `top secret ${RUN}`;

const hub = new AutomationHub();
let app;

try {
  step('create real account + node + message');
  app = await hub.launch({ bin, profile: 'duress', fresh: true });
  await createAccount(app, USER, REAL_PW);
  await createNode(app, NODE);
  await sendMessage(app, SECRET_MSG);
  const realId = await app.storageGet('accord_user_id');
  assert(realId, 'real account has a user id');

  step('set duress password (Settings → Danger zone)');
  await app.click('[title="Settings (Ctrl+,)"]');
  await app.waitFor('text=Danger zone', 8000);
  await app.type('input[placeholder="Set duress password"]', DURESS_PW);
  await app.click('text=Set');
  await app.waitFor('text=Duress password set', 8000);
  assert(await app.storageGet('accord_duress_v'), 'duress verifier stored');

  step('log out');
  await app.click("text=Log Out");
  await app.waitFor('text=Log In', 15000);

  step('log in with the DURESS password');
  await app.click('text=Log In');
  await app.waitFor('input[placeholder="Your username"]', 8000);
  await app.type('input[placeholder="Your username"]', USER);
  await app.type('input[placeholder="Your password"]', DURESS_PW);
  await app.click('button.btn-primary'); // the submit button, not the "Log In" title/heading

  step('decoy account is shown; real data is gone');
  // Authenticated (setup wizard gone) but empty: no SecretNode, no secret msg.
  await app.waitGone('input[placeholder="Your password"]', 15000);
  await app.waitFor('[title="Join or Create Node"]', 15000); // main app chrome
  await new Promise((r) => setTimeout(r, 1500));

  const nodeText = await app.text('.server-list');
  assert(!nodeText.includes(NODE) && !nodeText.includes(NODE[0] + '…'), 'decoy shows no real node');
  const bodyText = await app.text('.message-content');
  assert(!bodyText.includes(SECRET_MSG), 'decoy cannot see the secret message');

  // Duress config and the real identity must be gone after firing.
  assert(!(await app.storageGet('accord_duress_v')), 'duress verifier wiped after use');
  const newId = await app.storageGet('accord_user_id');
  assert(newId !== realId, 'not logged into the real account');

  console.log(`\nDURESS PASS — real account (${USER}, node ${NODE}) destroyed; empty decoy shown; duress config left no trace`);
  process.exitCode = 0;
} catch (e) {
  console.error('\nDURESS FAIL:', e.message);
  if (app) {
    const snap = await app.snapshot(2500).catch(() => '(snapshot failed)');
    console.error('DOM head:', snap.slice(0, 2000));
    const logs = await app.console().catch(() => []);
    for (const l of logs.slice(-8)) console.error(`  [${l.level}] ${l.text.split('\n')[0]}`);
  }
  process.exitCode = 1;
} finally {
  app?.kill();
  hub.close();
}
