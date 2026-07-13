/**
 * Read-gated message composer — end-to-end through the actual popover UI.
 *
 *  1. Alice creates a node; Bob joins.
 *  2. Alice opens the retention popover (clock button), picks a duration and
 *     selects Bob as a required reader, then sends a message.
 *  3. Assert Bob receives it AND both clients render the "read-gated" badge
 *     (proves the gate params rode the wire: composer -> ws -> relay broadcast).
 *
 * The relay's gate resolution + per-device local expiry are covered by Rust and
 * vitest unit tests; this proves the composer -> relay -> render loop.
 *
 * Prereqs: NEW relay on :8080 (--no-tls --disable-rate-limits), automation build.
 * Usage: node automation/read-gate.mjs [bin]
 */

import { AutomationHub, assert, step } from './driver.mjs';
import { createAccount, createNode, getInviteLink, joinNodeViaInvite } from './flows.mjs';

const bin = process.argv[2] || '../../target/debug/accord-desktop';
const RUN = Date.now().toString(36);
const PW = 'read-gate-passw0rd!';
const NODE = `Gated-${RUN}`;
const ALICE = `alice_${RUN}`;
const BOB = `bob_${RUN}`;
const MSG = `gated secret ${RUN}`;

const hub = new AutomationHub();
let alice, bob;

try {
  step('alice creates node, bob joins');
  alice = await hub.launch({ bin, profile: 'alice', fresh: true });
  await createAccount(alice, ALICE, PW);
  await createNode(alice, NODE);
  const invite = await getInviteLink(alice);

  bob = await hub.launch({ bin, profile: 'bob', fresh: true });
  await createAccount(bob, BOB, PW);
  await joinNodeViaInvite(bob, invite, NODE);
  // Let bob's membership + sender-key exchange settle so alice can pick him.
  await new Promise((r) => setTimeout(r, 2500));

  step('alice opens the retention popover and gates the message on bob');
  await alice.click('.input-icon-btn');
  await alice.waitFor('.retention-popover');
  await alice.click('text=5 min');
  await alice.click(`text=${BOB}`);
  // Click back into the composer to dismiss the popover; the gate selection persists.
  await alice.click('.message-input');

  step('alice sends the gated message');
  await alice.type('.message-input', MSG);
  await alice.press('Enter', '.message-input');

  step('bob receives it');
  await bob.waitFor(`text=${MSG}`, 20000);

  step('both clients render the read-gated badge');
  await alice.waitFor('.message-ephemeral-badge--gated', 8000);
  await bob.waitFor('.message-ephemeral-badge--gated', 8000);

  console.log(`\nREAD-GATE PASS — gated message delivered and badged on both clients (gated on ${BOB})`);
  process.exitCode = 0;
} catch (e) {
  console.error('\nREAD-GATE FAIL:', e.message);
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
