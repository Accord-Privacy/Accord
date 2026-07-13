/**
 * Disappearing-messages policy DISTRIBUTION — two perspectives (admin + member).
 *
 *  1. alice creates a node; bob joins (and receives the node's NMK).
 *  2. alice sets the node's disappearing-messages default in Node Settings.
 *  3. Assert the relay stored an opaque encrypted_settings blob (never plaintext).
 *  4. bob re-opens the node → his client decrypts the policy and adopts it, so
 *     his local retention store now matches alice's without her ever telling him.
 *
 * Proves the admin→NMK→relay→member loop end-to-end. Prereqs: NEW relay on :8080
 * (--no-tls --disable-rate-limits), automation build.
 */

import { AutomationHub, assert, step } from './driver.mjs';
import { createAccount, createNode, getInviteLink, joinNodeViaInvite } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const RUN = Date.now().toString(36);
const NODE = `Ephemeral-${RUN}`;
const TTL = 86400; // "24 hours" preset

const hub = new AutomationHub();
let alice, bob;

try {
  step('alice creates node; bob joins (gets NMK)');
  alice = await hub.launch({ bin, profile: 'disap-alice', fresh: true });
  await createAccount(alice, `alice_${RUN}`, 'alice-passw0rd!');
  await createNode(alice, NODE);
  const invite = await getInviteLink(alice);

  bob = await hub.launch({ bin, profile: 'disap-bob', fresh: true });
  await createAccount(bob, `bob_${RUN}`, 'bob-passw0rd!');
  await joinNodeViaInvite(bob, invite, NODE);

  const url = (await alice.storageGet('accord_server_url')) || 'http://localhost:8080';
  const aliceToken = await alice.token();
  const nodesResp = await alice.http(`${url}/nodes?token=${aliceToken}`, 'GET');
  const node = JSON.parse(nodesResp.body).find((n) => n.name === NODE);
  assert(node, 'node listed on relay');

  step('alice sets node disappearing + screenshot policy (Node Settings → Moderation)');
  await alice.click('.server-header-button');
  await alice.waitFor('text=Node Settings', 8000);
  await alice.click('text=Node Settings');
  await alice.waitFor('text=Moderation', 8000);
  await alice.click('text=Moderation');
  await alice.waitFor('text=Disappearing Messages', 8000);
  await alice.select('.ns-retention-node', String(TTL));
  await alice.waitFor('text=Node disappearing-messages default set', 8000);
  await alice.select('.ns-screenshot-node', 'on');
  await alice.waitFor('text=Screenshot protection on for this node', 8000);

  assert(
    (await alice.storageGet(`accord_retention_node_${node.id}`)) === String(TTL),
    'alice stored the node retention locally'
  );
  assert(
    (await alice.storageGet(`accord_ssprotect_node_${node.id}`)) === '1',
    'alice stored screenshot protection locally'
  );

  step('relay stored an opaque encrypted_settings blob (not plaintext)');
  const metaResp = await alice.http(`${url}/api/nodes/${node.id}/metadata/encrypted?token=${aliceToken}`, 'GET');
  const meta = JSON.parse(metaResp.body);
  const blob = meta.node?.encrypted_settings;
  assert(blob && blob.length > 0, 'relay has an encrypted_settings blob');
  assert(!blob.includes(String(TTL)), 'blob does not leak the TTL in cleartext');

  step('bob adopts the distributed policy live (metadata_updated broadcast)');
  // Poll bob's local store until BOTH policy fields arrive (broadcast → decrypt → apply).
  let ret = null;
  let ss = null;
  for (let i = 0; i < 20; i++) {
    ret = await bob.storageGet(`accord_retention_node_${node.id}`);
    ss = await bob.storageGet(`accord_ssprotect_node_${node.id}`);
    if (ret === String(TTL) && ss === '1') break;
    await new Promise((r) => setTimeout(r, 500));
  }
  assert(ret === String(TTL), `bob adopted the node retention (${ret})`);
  assert(ss === '1', `bob adopted screenshot protection (${ss})`);

  console.log(`\nDISAPPEARING-POLICY PASS — alice set retention ${TTL}s + screenshot protection; relay stored only ciphertext; bob decrypted + adopted both`);
  process.exitCode = 0;
} catch (e) {
  console.error('\nDISAPPEARING-POLICY FAIL:', e.message);
  for (const [name, app] of [['alice', alice], ['bob', bob]]) {
    if (!app) continue;
    const logs = await app.console().catch(() => []);
    for (const l of logs.slice(-6)) console.error(`  [${name}:${l.level}] ${l.text.split('\n')[0]}`);
  }
  process.exitCode = 1;
} finally {
  alice?.kill();
  bob?.kill();
  hub.close();
}
