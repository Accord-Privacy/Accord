/**
 * SPEC-03 §10.3, the four tests that track the documented residual risks
 * (§9.2, §9.3) against headless clients and the real relay:
 *
 * - X-1 (I+HRP, tagged spec05): a prekey bundle substituted for a pair with
 *   no session is intercepted today (until SPEC-05 pins identities).
 * - X-2 (I): a ghost member seated by the relay receives keys today (until
 *   SPEC-06), and is shown with its own short id; when it copies the display
 *   name of a member in the call, both are marked as duplicates.
 * - X-3 (I+HRP): delayed delivery; each marker plays at most once, only in
 *   the same call, in order, also for screen video.
 * - X-4 (I+HRP): screen-share sizes and timing reveal on-screen activity
 *   (Q16, OD-111).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { RelayProcess } from '../../src/__integration__/relay';
import { E2EEManager } from '../../src/e2ee';
import { encodeControlPayloadFor } from '../../src/e2ee/plaintext';
import { RELAY_AVAILABLE, allSecure, buildWorld, disposeWorld, joinAll, startRelay, type VoiceWorld } from './world';
import { callBody, sleep, waitFor } from './hc';
import { clientBody, typeOf, type HrpMessage } from './hrp';
import { byId, duplicatesPlayed, relayMessagesTo } from './common';
import { openWithAny, wireFrame } from './wire';
import { duplicateNameKeys, memberDisplayName, nameKey } from '../../src/voice/displayNames';

const suite = RELAY_AVAILABLE ? describe : describe.skip;

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

suite('SPEC-03 §10.3 residual-risk tests (X-1 to X-4)', () => {
  let relay: RelayProcess;
  let w: VoiceWorld | undefined;

  beforeAll(async () => {
    relay = await startRelay();
  });

  afterEach(async () => {
    await disposeWorld(w);
    w = undefined;
  });

  afterAll(async () => {
    await relay?.dispose();
  });

  it('X-1 (I+HRP, tagged spec05; today): with no session, a relay that substitutes B\'s prekey bundle intercepts A\'s call key and reads A\'s audio (the documented residual of §9.2 item 1)', async () => {
    w = await buildWorld(relay, ['x', 'y']);
    const [a, b] = byId(w.by.x, w.by.y);
    for (const hc of w.hcs) hc.startAudio();
    const relayIdentity = new E2EEManager();
    const relayBundle = relayIdentity.initialize();
    const relayInst = crypto.getRandomValues(new Uint8Array(16));
    // A asks the relay for B's bundle and gets the relay's own.
    w.hrp.addHttpRule(req => (req.token === a.client.token && req.method === 'GET' && req.path === `/keys/bundle/${b.userId}`
      ? { status: 200, json: { user_id: b.userId, identity_key: b64(relayBundle.identityKey), signed_prekey: b64(relayBundle.signedPrekey), one_time_prekey: relayBundle.oneTimePrekey ? b64(relayBundle.oneTimePrekey) : null } }
      : undefined));
    const stolen: Array<{ epoch: number; key: Uint8Array; inst: string }> = [];
    const channel = w.voiceChannel;
    // The relay answers A as B, over the session A opened with the relay's identity.
    w.hrp.addRule('c2s', m => {
      if (m.conn.userId !== a.userId || typeOf(m) !== 'VoiceKeyExchange') return undefined;
      const body = clientBody(m)!;
      if (body.target_user_id !== b.userId) return undefined;
      const env = Buffer.from(String(body.wrapped_key).slice(5), 'base64').toString('utf8');
      let plaintext: string;
      try {
        plaintext = relayIdentity.decryptEnvelope(a.userId, env);
      } catch {
        return 'drop';
      }
      const call = callBody(plaintext);
      if (call?.type === 'call_hello') {
        const hello = encodeControlPayloadFor('voice', { type: 'call_hello', v: 1, from: b.userId, ch: channel, inst: b64(relayInst), to_inst: call.inst });
        const reply = relayIdentity.encryptEnvelope(a.userId, hello);
        w!.hrp.inject(a.userId, 's2c', { type: 'voice_key_exchange', from: b.userId, channel_id: channel, wrapped_key: 'acv1:' + Buffer.from(reply).toString('base64'), sender_ssrc: 0, key_generation: 0 });
      }
      if (call?.type === 'call_key') {
        stolen.push({ epoch: call.epoch, key: Uint8Array.from(Buffer.from(call.key, 'base64')), inst: call.inst });
        const ack = encodeControlPayloadFor('voice', { type: 'call_key_ack', v: 1, from: b.userId, ch: channel, inst: b64(relayInst), to_inst: call.inst, epoch: call.epoch });
        const reply = relayIdentity.encryptEnvelope(a.userId, ack);
        w!.hrp.inject(a.userId, 's2c', { type: 'voice_key_exchange', from: b.userId, channel_id: channel, wrapped_key: 'acv1:' + Buffer.from(reply).toString('base64'), sender_ssrc: 0, key_generation: 0 });
      }
      return 'drop';
    });
    await joinAll(w, [b, a]);
    await waitFor('the relay holds A\'s call key', () => stolen.length > 0, 20_000);
    await sleep(1000);
    // Today the interception succeeds: A's frames to B open with the stolen key.
    const frames = relayMessagesTo(w.hrp, b, 'srtp_voice_packet').filter(m => m.json?.from === a.userId).slice(-20);
    expect(frames.length).toBeGreaterThan(0);
    const keys = stolen.map(s => ({ from: a.userId, inst: s.inst, epoch: s.epoch, secret: s.key, at: 0, skipped: false }));
    let opened = 0;
    for (const m of frames) if (await openWithAny(wireFrame(m)!, keys)) opened++;
    expect(opened).toBeGreaterThan(0);
    // A shows B as Secure: nothing tells A (the residual SPEC-05 closes with pinned identities).
    expect(a.participant(b)?.outbound).toBe('secure');
  });

  it('X-2 (I, today): a ghost member the relay seats directly in its database joins the call, receives keys, is shown with its own short id, and is marked as a duplicate with the member whose display name it copies', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'ghost'], { outsiders: ['ghost'] });
    const { alice, bob, ghost } = w.by;
    // The relay operator seats an account it holds the keys of (C006), without any invite.
    relay.sql("INSERT INTO node_members (node_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)", [w.nodeId, ghost.userId, Math.floor(Date.now() / 1000)]);
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob, ghost], 300);
    await allSecure([alice, bob, ghost]);
    expect(ghost.receivedKeys.some(k => k.from === alice.userId)).toBe(true);
    await ghost.hears(alice);
    const shown = alice.participant(ghost)!;
    expect(shown.shortId).toBe(ghost.userId.replace(/-/g, '').slice(0, 8));
    expect(shown.recipient).toBe(true);
    expect(alice.snapshot!.indicator).toBe('e2ee_not_verified');
    // The ghost copies B's display name (relay-controlled, C014; differing only in case and spacing).
    await alice.client.api.updateProfile({ display_name: 'Alice' }, alice.client.token);
    await bob.client.api.updateProfile({ display_name: 'Bob Builder' }, bob.client.token);
    await ghost.client.api.updateProfile({ display_name: ' bob builder' }, ghost.client.token);
    // A labels its call as the voice panel does (REQ-11): the member list's names, the short ids, and the duplicate mark.
    const members = await alice.client.api.getNodeMembers(w.nodeId, alice.client.token);
    const participants = alice.snapshot!.participants;
    expect(participants.map(p => p.userId).sort()).toEqual([bob.userId, ghost.userId].sort());
    const names = new Map(participants.map(p => [p.userId, memberDisplayName(members, p.userId, p.shortId)]));
    const selfName = memberDisplayName(members, alice.userId, 'You');
    expect(names.get(bob.userId)).toBe('Bob Builder');
    const marked = duplicateNameKeys([selfName, ...names.values()]);
    expect(marked.has(nameKey(names.get(bob.userId)!))).toBe(true);
    expect(marked.has(nameKey(names.get(ghost.userId)!))).toBe(true);
    expect(marked.has(nameKey(selfName))).toBe(false);
    // The short ids still tell them apart.
    expect(alice.participant(bob)!.shortId).not.toBe(shown.shortId);
  });

  it('X-3 (I+HRP): every call message, frame and fragment from S to B held for 20 s and then delivered in order plays and decodes each marker at most once, in order, in the same call', async () => {
    w = await buildWorld(relay, ['sam', 'bob', 'carol']);
    const { sam, bob, carol } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [sam, bob]);
    await allSecure([sam, bob]);
    await waitFor('S can share', () => sam.state.screen.control.kind === 'idle', 10_000);
    sam.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === sam.userId), 10_000);
    bob.watch(sam);
    await bob.decodes(sam, { count: 5 });
    const held: HrpMessage[] = [];
    let holding = true;
    const samHex = sam.userId.replace(/-/g, '');
    w.hrp.addRule('s2c', m => {
      if (!holding || m.conn.userId !== bob.userId) return undefined;
      const t = typeOf(m);
      const fromSam = (t === 'voice_key_exchange' || t === 'srtp_voice_packet') ? m.json?.from === sam.userId : t === 'SCREEN_DOWN' && Buffer.from(m.data.subarray(17, 33)).toString('hex') === samHex;
      if (!fromSam) return undefined;
      held.push(m);
      return 'drop';
    });
    await sleep(5000);
    await carol.joinVoice(w.voiceChannel, w.nodeId); // S rotates during the hold
    await sleep(15_000);
    holding = false;
    for (const m of held) w.hrp.deliver(m.conn, 's2c', m.opcode === 2 ? m.data : m.json!, false);
    await sleep(3000);
    expect(held.length).toBeGreaterThan(500);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
    const seqs = bob.decodedFrom(sam).map(m => m.seq);
    expect(seqs.length - new Set(seqs).size).toBe(0);
    expect(seqs.every((s, i) => i === 0 || s > seqs[i - 1])).toBe(true);
    // Every played frame of S at B decrypts under a key S distributed in this call (same instance).
    expect(bob.receivedKeys.filter(k => k.from === sam.userId).every(k => k.inst === sam.inst)).toBe(true);
  });

  it('X-4 (I+HRP): SCREEN_UP sizes and timing distinguish 10 s of a static picture from 10 s of small changes every 200 ms (the metadata residual of §9.3, Q16)', async () => {
    w = await buildWorld(relay, ['alice', 'bob']);
    const { alice, bob } = w.by;
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    alice.screen.outputSize = o => (o.key ? 8000 : 900);
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen({ fps: 5 });
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    await bob.decodes(alice, { count: 3 });
    alice.stopScreenSource();
    await sleep(1000);
    const s0 = Date.now();
    await sleep(10_000);
    alice.startScreenSource({ fps: 5 });
    const c0 = Date.now();
    await sleep(10_000);
    const ups = w.hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SCREEN_UP' });
    const staticPhase = ups.filter(m => m.at >= s0 && m.at < c0);
    const changing = ups.filter(m => m.at >= c0 + 500);
    // The relay sees almost nothing while the picture is static, and a steady stream while it changes.
    expect(staticPhase.length).toBeLessThanOrEqual(3);
    expect(changing.length).toBeGreaterThanOrEqual(30);
    const bytes = (ms: HrpMessage[]) => ms.reduce((n, m) => n + m.data.length, 0);
    expect(bytes(changing)).toBeGreaterThan(3 * bytes(staticPhase));
  });
});
