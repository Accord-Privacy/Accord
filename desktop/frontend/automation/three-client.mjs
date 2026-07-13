/**
 * Three-perspective test: Alice, Bob, and Carol as separate desktop instances.
 * Proves sender-key channel E2EE fans out to TWO joiners (the 3-way case that
 * read-gated / per-recipient features depend on), in every direction.
 *
 *  1. Alice creates a node + invite; Bob and Carol both join.
 *  2. A message from each of the three decrypts for the other two.
 *  3. No unexplained console errors.
 *
 * Prereqs: relay on :8080 (--no-tls --disable-rate-limits), automation build.
 * Usage:   node automation/three-client.mjs [app-binary]
 */

import { AutomationHub, assert, step } from "./driver.mjs";
import {
  createAccount,
  createNode,
  getInviteLink,
  joinNodeViaInvite,
  sendMessage,
  assertNoConsoleErrors,
} from "./flows.mjs";

const bin = process.argv[2] || "../../target/debug/accord-desktop";
const RUN = Date.now().toString(36);
const PW = "three-client-passw0rd!";
const NODE = `Trio ${RUN}`;
const ALICE = `alice_${RUN}`;
const BOB = `bob_${RUN}`;
const CAROL = `carol_${RUN}`;

const hub = new AutomationHub();
let alice, bob, carol;

/** Assert a message authored by one client is visible to the given recipients. */
async function fanout(author, authorName, text, recipients) {
  await sendMessage(author, text);
  for (const [name, app] of recipients) {
    await app.waitFor(`text=${text}`, 20000).catch(() => {
      throw new Error(`${name} never received ${authorName}'s message "${text}"`);
    });
  }
}

try {
  step("alice creates node + invite");
  alice = await hub.launch({ bin, profile: "alice", fresh: true });
  await createAccount(alice, ALICE, PW);
  await createNode(alice, NODE);
  const invite = await getInviteLink(alice);

  step("bob joins");
  bob = await hub.launch({ bin, profile: "bob", fresh: true });
  await createAccount(bob, BOB, PW);
  await joinNodeViaInvite(bob, invite, NODE);

  step("carol joins");
  carol = await hub.launch({ bin, profile: "carol", fresh: true });
  await createAccount(carol, CAROL, PW);
  await joinNodeViaInvite(carol, invite, NODE);

  // Let the third member's sender-key exchange settle before asserting fan-out.
  await new Promise((r) => setTimeout(r, 2000));

  step("channel E2EE: alice -> bob + carol");
  await fanout(alice, "alice", `alice to all ${RUN}`, [["bob", bob], ["carol", carol]]);

  step("channel E2EE: bob -> alice + carol");
  await fanout(bob, "bob", `bob to all ${RUN}`, [["alice", alice], ["carol", carol]]);

  step("channel E2EE: carol -> alice + bob");
  await fanout(carol, "carol", `carol to all ${RUN}`, [["alice", alice], ["bob", bob]]);

  step("console error audit");
  await assertNoConsoleErrors(alice, "alice");
  await assertNoConsoleErrors(bob, "bob");
  await assertNoConsoleErrors(carol, "carol");

  console.log(`\nTHREE-CLIENT PASS — ${ALICE}, ${BOB}, ${CAROL}: 3-way channel E2EE in every direction`);
  process.exitCode = 0;
} catch (e) {
  console.error("\nTHREE-CLIENT FAIL:", e.message);
  for (const [name, app] of [["alice", alice], ["bob", bob], ["carol", carol]]) {
    if (!app) continue;
    const logs = await app.console().catch(() => []);
    for (const l of logs.slice(-6)) console.error(`  [${name}:${l.level}] ${l.text.split("\n")[0]}`);
  }
  process.exitCode = 1;
} finally {
  alice?.kill();
  bob?.kill();
  carol?.kill();
  hub.close();
}
