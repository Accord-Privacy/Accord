/**
 * Two-perspective test: Alice and Bob as separate desktop app instances.
 *
 *  1. Alice creates account + node, invites Bob; Bob creates account + joins.
 *  2. Channel messages decrypt in both directions (sender-key E2EE).
 *  3. DMs both directions (Double Ratchet E2EE).
 *  4. Voice channel: both join, each sees the other as participant.
 *  5. No unexplained console errors on either side.
 *
 * Prereqs: relay on :8080, automation build (npm run auto:build).
 * Usage:   node automation/two-client.mjs [app-binary]
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
const PASSWORD = "two-client-passw0rd!";
const NODE_NAME = `Duo ${RUN}`;
const ALICE = `alice_${RUN}`;
const BOB = `bob_${RUN}`;
const MSG_A = `alice channel msg ${RUN}`;
const MSG_B = `bob channel msg ${RUN}`;
const DM_A = `alice dm secret ${RUN}`;
const DM_B = `bob dm reply ${RUN}`;
const VOICE_CHANNEL = "war-room";

const hub = new AutomationHub();
let alice, bob;

try {
  step("launch alice + create account/node/invite");
  alice = await hub.launch({ bin, profile: "alice", fresh: true });
  await createAccount(alice, ALICE, PASSWORD);
  await createNode(alice, NODE_NAME);
  const invite = await getInviteLink(alice);
  console.log("invite:", invite);

  step("launch bob + join node");
  bob = await hub.launch({ bin, profile: "bob", fresh: true });
  await createAccount(bob, BOB, PASSWORD);
  await joinNodeViaInvite(bob, invite, NODE_NAME);

  step("channel E2EE: alice -> bob");
  await sendMessage(alice, MSG_A);
  await bob.waitFor(`text=${MSG_A}`, 20000);

  step("channel E2EE: bob -> alice");
  // Bob may need to select the #general channel after joining
  await sendMessage(bob, MSG_B);
  await alice.waitFor(`text=${MSG_B}`, 20000);

  step("friends: alice's DM attempt sends a friend request");
  await alice.click(".dm-header-add-btn");
  await alice.waitFor(".dm-search-input", 5000);
  await alice.type(".dm-search-input", BOB);
  await alice.waitFor(".dm-create-item", 5000);
  await alice.click(".dm-create-item");
  await alice.waitFor("text=Friend request sent", 10000);

  step("friends: bob accepts (request appears via poll)");
  await bob.waitFor(".friend-request-row", 25000);
  await bob.click(".friend-request-row .btn-green");
  await bob.waitGone(".friend-request-row", 10000);

  step("DM: alice opens DM with bob (now friends)");
  await alice.click(".dm-header-add-btn");
  await alice.waitFor(".dm-search-input", 5000);
  await alice.type(".dm-search-input", BOB);
  await alice.waitFor(".dm-create-item", 5000);
  await alice.click(".dm-create-item");
  await alice.waitFor(".dm-item", 10000);
  await sendMessage(alice, DM_A);

  step("DM: bob receives and replies");
  await bob.waitFor(".dm-item", 20000);
  await bob.click(".dm-item");
  await bob.waitFor(`text=${DM_A}`, 20000);
  await sendMessage(bob, DM_B);

  step("DM: alice sees bob's reply");
  await alice.waitFor(`text=${DM_B}`, 20000);

  step("voice: alice creates voice channel");
  // Back to the node (alice is in the DM view; click node name in server list)
  await alice.click(`[title="${NODE_NAME}"]`).catch(async () => {
    // fallback: server icons carry the node name text
    await alice.click(`text=${NODE_NAME}`);
  });
  await alice.waitFor('[title="Create Channel"]', 10000);
  await alice.click('[title="Create Channel"]');
  await alice.waitFor('input[placeholder="Channel name"]', 5000);
  await alice.type('input[placeholder="Channel name"]', VOICE_CHANNEL);
  await alice.click('[title="Voice Channel"]');
  await alice.click("text=Create");
  await alice.waitFor(`text=${VOICE_CHANNEL}`, 10000);

  step("voice: both join");
  await alice.click(`text=${VOICE_CHANNEL}`);
  await bob.click(`[title="${NODE_NAME}"]`).catch(async () => {
    await bob.click(`text=${NODE_NAME}`);
  });
  await bob.waitFor(`text=${VOICE_CHANNEL}`, 10000);
  await bob.click(`text=${VOICE_CHANNEL}`);

  step("voice: each sees both participants");
  await alice.waitFor(".voice-channel-users", 15000);
  await bob.waitFor(".voice-channel-users", 15000);
  // Participant propagation is event-driven; poll until both sides show 2.
  let seenByAlice = "", seenByBob = "";
  for (let i = 0; i < 15; i++) {
    const [a, b] = await Promise.all([
      alice.query(".voice-channel-user"),
      bob.query(".voice-channel-user"),
    ]);
    seenByAlice = a.map((e) => e.text).join(" | ");
    seenByBob = b.map((e) => e.text).join(" | ");
    if (a.length >= 2 && b.length >= 2) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  console.log("alice sees:", JSON.stringify(seenByAlice));
  console.log("bob sees:", JSON.stringify(seenByBob));
  assert(seenByAlice.includes(BOB), "alice sees bob in voice");
  assert(seenByBob.includes(ALICE), "bob sees alice in voice");

  step("console error audit");
  await assertNoConsoleErrors(alice, "alice");
  await assertNoConsoleErrors(bob, "bob");

  console.log(`\nTWO-CLIENT PASS — ${ALICE} & ${BOB}: node, channel E2EE both ways, DMs both ways, voice presence`);
  process.exitCode = 0;
} catch (e) {
  console.error("\nTWO-CLIENT FAIL:", e.message);
  for (const [name, app] of [["alice", alice], ["bob", bob]]) {
    if (!app) continue;
    const snap = await app.snapshot(2500).catch(() => "(snapshot failed)");
    console.error(`--- ${name} DOM head:`, snap.slice(0, 2500));
    const logs = await app.console().catch(() => []);
    for (const l of logs) console.error(`  [${name}:${l.level}] ${l.text.split("\n")[0]}`);
  }
  process.exitCode = 1;
} finally {
  alice?.kill();
  bob?.kill();
  hub.close();
}
