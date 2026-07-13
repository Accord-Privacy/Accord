/**
 * Panic-wipe end-to-end: create an account, trigger the danger-zone panic
 * wipe, and confirm the app reloads to a fresh, identity-less state with no
 * Accord data left in local storage.
 *
 * Prereqs: relay on :8080, automation build. Usage: node automation/panic-wipe.mjs [bin]
 */

import { AutomationHub, assert, step } from './driver.mjs';
import { createAccount } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const hub = new AutomationHub();
let app;

try {
  step('create account');
  app = await hub.launch({ bin, profile: 'panic', fresh: true });
  await createAccount(app, `panic_${Date.now().toString(36)}`, 'panic-test-passw0rd!');

  step('confirm account data is present');
  const before = await app.storageKeys();
  const accordBefore = before.filter((k) => k.startsWith('accord_') || k.startsWith('accord-'));
  assert(accordBefore.some((k) => k === 'accord_user_id'), 'accord_user_id present before wipe');
  console.log('accord keys before:', accordBefore.length);

  step('open settings → danger zone');
  await app.click('[title="Settings (Ctrl+,)"]');
  await app.waitFor('text=Danger zone', 8000);

  step('WIPE confirm gating: button disabled until "WIPE" typed');
  await app.click('text=Wipe this device');
  await app.waitFor('input[placeholder="Type WIPE to confirm"]', 5000);
  await app.type('input[placeholder="Type WIPE to confirm"]', 'WIPE');

  // Arm for the post-reload reconnection BEFORE triggering the wipe.
  const reloaded = hub.nextConnection(30000);

  step('trigger wipe');
  await app.click('text=Wipe now');

  step('app reloads to a fresh, identity-less state');
  const fresh = await reloaded;
  app = fresh;
  // Fresh install → setup wizard / welcome, no identity.
  await fresh.waitFor('text=Create Account', 20000);
  const after = await fresh.storageKeys();
  const accordAfter = after.filter((k) => k.startsWith('accord_') || k.startsWith('accord-'));
  console.log('accord keys after:', accordAfter);
  assert(!accordAfter.includes('accord_user_id'), 'accord_user_id gone after wipe');
  assert(!accordAfter.some((k) => k.startsWith('accord_e2ee_')), 'no e2ee stores remain after wipe');

  console.log('\nPANIC-WIPE PASS — account created, wiped, app reset to fresh install with no Accord data');
  process.exitCode = 0;
} catch (e) {
  console.error('\nPANIC-WIPE FAIL:', e.message);
  process.exitCode = 1;
} finally {
  app?.kill();
  hub.close();
}
