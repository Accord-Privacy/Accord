/**
 * Disappearing messages — retroactive "wipe-old" end-to-end.
 *
 *  1. Create an account + node, send two messages (visible locally + on relay).
 *  2. Trigger the relay retroactive purge (POST /channels/:id/purge_before) the
 *     same way the NodeSettings "Disappearing Messages" control does — with a
 *     cutoff that covers both messages.
 *  3. Assert the relay deleted them (a fresh GET returns none) AND the live
 *     client dropped them from the UI via the messages_purged broadcast.
 *
 * The TTL math + read-time expiry filtering are covered by Rust unit tests;
 * this proves the client→relay→broadcast→client-drop loop.
 *
 * Prereqs: NEW relay on :8080 (--no-tls --disable-rate-limits), automation build.
 * Usage: node automation/disappearing.mjs [bin]
 */

import { AutomationHub, assert, step } from './driver.mjs';
import { createAccount, createNode, sendMessage } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const RUN = Date.now().toString(36);
const USER = `disap_${RUN}`;
const PW = 'disappearing-passw0rd!';
const NODE = `Ephemeral-${RUN}`;
const MSG1 = `secret one ${RUN}`;
const MSG2 = `secret two ${RUN}`;

const hub = new AutomationHub();
let app;

try {
  step('create account + node + two messages');
  app = await hub.launch({ bin, profile: 'disappearing', fresh: true });
  await createAccount(app, USER, PW);
  await createNode(app, NODE);
  await sendMessage(app, MSG1);
  await sendMessage(app, MSG2);

  const shown = await app.text('.message-content');
  assert(shown.includes(MSG1) && shown.includes(MSG2), 'both messages visible before purge');

  step('resolve token + channel id from the relay');
  const url = (await app.storageGet('accord_server_url')) || 'http://localhost:8080';
  const token = await app.token();
  assert(token, 'app has an auth token');

  const nodesResp = await app.http(`${url}/nodes?token=${token}`, 'GET');
  const nodes = JSON.parse(nodesResp.body);
  const node = nodes.find((n) => n.name === NODE) || nodes[0];
  assert(node, 'node listed on relay');

  const chResp = await app.http(`${url}/nodes/${node.id}/channels?token=${token}`, 'GET');
  const channels = JSON.parse(chResp.body);
  const channel = channels[0];
  assert(channel, 'channel listed on relay');

  const before = Math.floor(Date.now() / 1000) + 10; // cutoff after both messages
  step('purge the channel retroactively (wipe-old)');
  const purge = await app.http(
    `${url}/channels/${channel.id}/purge_before?token=${token}`,
    'POST',
    JSON.stringify({ before })
  );
  assert(purge.status === 200, `purge_before returned 200 (got ${purge.status}: ${purge.body})`);
  const purged = JSON.parse(purge.body);
  assert(purged.removed >= 2, `relay removed both messages (removed=${purged.removed})`);

  step('relay no longer serves the purged messages');
  const after = await app.http(`${url}/channels/${channel.id}/messages?token=${token}`, 'GET');
  assert(!after.body.includes(MSG1) && !after.body.includes(MSG2), 'relay history is empty of purged messages');

  step('live client dropped them via messages_purged');
  // Give the broadcast a moment to arrive and re-render.
  await new Promise((r) => setTimeout(r, 2000));
  const nowShown = await app.text('.message-content');
  assert(!nowShown.includes(MSG1) && !nowShown.includes(MSG2), 'UI dropped the purged messages');

  console.log(`\nDISAPPEARING PASS — wipe-old removed both messages on the relay and live in the client (removed=${purged.removed})`);
  process.exitCode = 0;
} catch (e) {
  console.error('\nDISAPPEARING FAIL:', e.message);
  if (app) {
    const logs = await app.console().catch(() => []);
    for (const l of logs.slice(-8)) console.error(`  [${l.level}] ${l.text.split('\n')[0]}`);
  }
  process.exitCode = 1;
} finally {
  app?.kill();
  hub.close();
}
