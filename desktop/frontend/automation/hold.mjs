/**
 * Dev helper: launch the app, create an account + node + a few messages, then
 * hold the window open so it can be screenshotted / inspected by hand.
 * Usage: node automation/hold.mjs [bin] [seconds]
 */
import { AutomationHub, step } from './driver.mjs';
import { createAccount, createNode, sendMessage } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const secs = parseInt(process.argv[3] || '90', 10);
const RUN = Date.now().toString(36);
const hub = new AutomationHub();
let app;
try {
  step('launch + set up a realistic view');
  app = await hub.launch({ bin, profile: 'hold', fresh: true });
  await createAccount(app, `demo_${RUN}`, 'demo-passw0rd!');
  await createNode(app, `Design Review`);
  await sendMessage(app, 'Hey team — pushing the new build tonight.');
  await sendMessage(app, 'Nice, does it include the disappearing-messages UI?');
  await sendMessage(app, 'Yep, per-channel + node default. Screenshot protection too.');
  console.log(`\nHOLDING window open for ${secs}s (instance ${app.instanceId})`);
  await new Promise((r) => setTimeout(r, secs * 1000));
} catch (e) {
  console.error('HOLD error:', e.message);
} finally {
  app?.kill();
  hub.close();
}
