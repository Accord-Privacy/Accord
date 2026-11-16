/**
 * SPEC-03 §10.2: the integration (I) and hostile-relay (I+HRP) forms of the
 * per-requirement tests for calls, run with headless clients (`hc.ts`)
 * against the real relay through the hostile relay proxy (`hrp.ts`).
 *
 * Covered here: T-1 (I+HRP), T-4 (I+HRP), T-10 (I, tagged spec05: today's
 * expectation), T-13 (I+HRP), T-20 (I+HRP, deterministic loss and ACK
 * exhaustion), T-21 (I, outdated client; I, A1 with P2P reports and a
 * share), T-22 (I+HRP, audio and A1), T-38 (I+HRP, with A1), T-41 (I) and
 * T-45 (I). The U and F forms live with the modules (`src/voice/*.test.ts`,
 * `src/__tests__/VoiceChat*.test.tsx`); screen-sharing and regression
 * replays are in `screen.test.ts`, `regressions.test.ts` and
 * `residuals.test.ts`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { RelayProcess } from '../../src/__integration__/relay';
import { RELAY_AVAILABLE, allSecure, buildWorld, disposeWorld, joinAll, startRelay, type VoiceWorld } from './world';
import { classifyWire, sleep, waitFor } from './hc';
import { clientBody, typeOf, type HrpMessage } from './hrp';
import {
  binaryNeedles,
  byId,
  callMessagesFrom,
  clientMessagesFrom,
  connOf,
  dmChannel,
  establishSession,
  leaks,
  playedBetween,
  relayMessagesTo,
  secretNeedles,
  textNeedles,
} from './common';
import { MEDIA_KIND_AUDIO, b64, openWithAny, wireFrame } from './wire';
import { storageWrites } from './spies';

const suite = RELAY_AVAILABLE ? describe : describe.skip;

suite('SPEC-03 calls over the real relay (I, I+HRP)', () => {
  let relay: RelayProcess;
  let w: VoiceWorld | undefined;

  beforeAll(async () => {
    relay = await startRelay();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    await disposeWorld(w);
    w = undefined;
  });

  afterAll(async () => {
    await relay?.dispose();
  });

  it('T-1 (I+HRP): over 20 s of traffic with a join, a departure and a timer rotation, no epoch secret crosses the relay outside a call_key', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol'], { client: () => ({ callTimings: { rotationIntervalMs: 6000 } }) });
    const { alice, bob, carol } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    await sleep(2000);
    await carol.joinVoice(w.voiceChannel, w.nodeId);
    await allSecure([alice, bob, carol]);
    await sleep(3000);
    bob.leaveVoice();
    // The timer rotation (shortened to 6 s for the test) runs while A and C stay.
    await sleep(9000);
    await alice.hears(carol, { since: Date.now() - 1000 });

    const keys = w.hcs.flatMap(hc => hc.receivedKeys);
    expect(keys.length).toBeGreaterThanOrEqual(6);
    // Epochs beyond the first of each sender show the rotations happened.
    expect(Math.max(...keys.filter(k => k.from === alice.userId).map(k => k.epoch))).toBeGreaterThanOrEqual(2);

    // No secret in any form anywhere in the traffic (REST and WebSocket, both directions).
    expect(leaks(w.hrp.capturedChunks(), secretNeedles(w.hcs))).toEqual([]);

    // Every VoiceKeyExchange has a target and an acv1: value; no legacy VoicePacket at all.
    const vke = w.hrp.messages({ dir: 'c2s', type: 'VoiceKeyExchange' });
    expect(vke.length).toBeGreaterThan(0);
    for (const m of vke) {
      const body = clientBody(m)!;
      expect(typeof body.target_user_id).toBe('string');
      expect(String(body.wrapped_key).startsWith('acv1:')).toBe(true);
    }
    expect(w.hrp.messages({ dir: 'c2s', type: 'VoicePacket' })).toEqual([]);

    // Each key reached its receiver only in a call_key addressed to it.
    for (const hc of w.hcs) {
      for (const k of hc.receivedKeys) {
        const sent = vke.filter(m => m.conn.userId === k.from && clientBody(m)!.target_user_id === hc.userId);
        expect(sent.some(m => classifyWire(clientBody(m)!.wrapped_key)?.type === 'call_key')).toBe(true);
      }
    }

    // Hellos and acknowledgments carry no key material.
    const needles = secretNeedles(w.hcs);
    for (const hc of w.hcs) {
      for (const rec of hc.encrypted) {
        if (rec.type === 'call_key') continue;
        expect(rec.body.key).toBeUndefined();
        expect(leaks([Buffer.from(JSON.stringify(rec.body))], needles)).toEqual([]);
      }
    }
  });

  it('T-4 (I+HRP): a raw key injected under a current client\'s id is ignored; its audio keeps playing and the outdated note clears within 15 s', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol']);
    const { alice, bob, carol } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    const before = alice.receivedKeys.length;
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const injectedAt = Date.now();
    expect(w.hrp.inject(alice.userId, 's2c', {
      type: 'voice_key_exchange', from: bob.userId, channel_id: w.voiceChannel, wrapped_key: b64(raw), sender_ssrc: 0, key_generation: 0, timestamp: Math.floor(Date.now() / 1000),
    })).toBe(1);
    await waitFor('the outdated note', () => alice.participant(bob)?.notes.outdatedApp, 5000);
    // Nothing installed from it; B stays eligible and keeps playing.
    expect(alice.receivedKeys.length).toBe(before);
    expect(alice.participant(bob)?.ineligibleReason).toBeNull();
    await alice.hears(bob, { since: Date.now() });
    // A rotation makes B send A a call message; A accepts it and the note clears.
    await carol.joinVoice(w.voiceChannel, w.nodeId);
    await waitFor('the note clears', () => alice.participant(bob)?.notes.outdatedApp === false, 15_000);
    expect(Date.now() - injectedAt).toBeLessThan(15_000 + 2000);
    await alice.hears(bob, { since: Date.now() });
    // The raw key never became a key: nothing from it reached any key store.
    expect(alice.receivedKeys.every(k => Buffer.compare(Buffer.from(k.secret), Buffer.from(raw)) !== 0)).toBe(true);
  });

  it('T-13 (I+HRP): a CKM and a hello diverted into the DM path, a live Sender Key distribution and a pending distribution are never rendered, stored, logged or installed', async () => {
    w = await buildWorld(relay, ['alice', 'bob']);
    const { alice, bob } = w.by;
    const dm = await dmChannel(alice, bob, w.nodeId);
    // A session in both directions, so that B's hello reaches A whatever the id order (REQ-10).
    await establishSession(alice, bob, dm);
    const withheld: HrpMessage[] = [];
    const removeRule = w.hrp.addRule('s2c', m => {
      if (m.conn.userId !== bob.userId || typeOf(m) !== 'voice_key_exchange' || m.json?.from !== alice.userId) return undefined;
      withheld.push(m);
      return 'drop';
    });
    await joinAll(w, [bob, alice]);
    // Three hellos (first and retries) and three CKM transmissions (first and retransmissions).
    const kinds = () => withheld.map(m => classifyWire(m.json!.wrapped_key)?.type);
    await waitFor('three withheld hellos and keys', () =>
      kinds().filter(t => t === 'call_hello').length >= 3 && kinds().filter(t => t === 'call_key').length >= 3, 30_000);
    const hellos = withheld.filter(m => classifyWire(m.json!.wrapped_key)?.type === 'call_hello').slice(0, 3);
    const ckms = withheld.filter(m => classifyWire(m.json!.wrapped_key)?.type === 'call_key').slice(0, 3);
    const secrets = ckms.map(m => classifyWire(m.json!.wrapped_key)!.body.key as string);
    const secretBytes = secrets.map(s => Uint8Array.from(Buffer.from(s, 'base64')));
    const needles = [
      ...secretBytes.flatMap((s, i) => binaryNeedles(`ckm secret ${i}`, s)),
      ...textNeedles('call tag', '\u001eaccord-call\u001e'),
      ...textNeedles('call type', '"type":"call_key"'),
    ];
    expect(bob.participant(alice)?.inbound).toBe('waiting');

    const logged: string[] = [];
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
        logged.push(args.map(a => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === 'string' ? a : JSON.stringify(a))).join(' '));
      });
    }
    const storageBefore = storageWrites().length;
    const skBefore = JSON.stringify(bob.client.senderKeys.exportStore());
    const nmkBefore = JSON.stringify(bob.client.nmkSnapshot());
    const cacheBefore = bob.client.cacheMap.size;
    const receivedBefore = bob.client.received.length;
    const payloadOf = (m: HrpMessage) => String(m.json!.wrapped_key).slice('acv1:'.length);
    for (const [i, group] of [ckms, hellos].entries()) {
      // (i) a DM channel_message from A
      w.hrp.inject(bob.userId, 's2c', {
        type: 'channel_message', channel_id: dm, from: alice.userId, message_id: crypto.randomUUID(), encrypted_data: payloadOf(group[0]), is_dm: true, timestamp: Math.floor(Date.now() / 1000),
      });
      // (ii) a live sender_key_distribution
      w.hrp.inject(bob.userId, 's2c', {
        type: 'sender_key_distribution', from_user_id: alice.userId, channel_id: w.textChannel, payload: payloadOf(group[1]), distribution_id: `${crypto.randomUUID()}-${i}`,
      });
      // (iii) a pending_sender_keys entry
      w.hrp.inject(bob.userId, 's2c', {
        type: 'pending_sender_keys', distributions: [{ id: crypto.randomUUID(), from_user_id: alice.userId, channel_id: w.textChannel, encrypted_payload: payloadOf(group[2]), created_at: Math.floor(Date.now() / 1000) }],
      });
    }
    await waitFor('the DM path decoded both', () => bob.client.received.length >= receivedBefore + 2, 10_000);
    await sleep(500);

    // Nothing rendered: the display path hides control payloads (SPEC-02 REQ-53).
    const decoded = bob.client.received.slice(receivedBefore);
    expect(decoded.map(r => r.decoded.display)).toEqual(['hidden', 'hidden']);
    expect(decoded.every(r => r.message.content === '' || !r.message.content.includes('accord-call'))).toBe(true);
    // No own-message cache entry, no storage write with the secret, no Sender Key or NMK change, no key installed.
    expect(bob.client.cacheMap.size).toBe(cacheBefore);
    const writes = storageWrites().slice(storageBefore).map(s => Buffer.from(`${s.key}=${s.value}`));
    expect(leaks(writes, needles)).toEqual([]);
    expect(JSON.stringify(bob.client.senderKeys.exportStore())).toBe(skBefore);
    expect(JSON.stringify(bob.client.nmkSnapshot())).toBe(nmkBefore);
    expect(storageWrites().slice(storageBefore).filter(s => s.key.startsWith('accord_e2ee_nmk_'))).toEqual([]);
    expect(bob.receivedKeys).toEqual([]);
    expect(bob.participant(alice)?.inbound).toBe('waiting');
    // Nothing logged with the secret, the tag or the payload type.
    expect(leaks(logged.map(l => Buffer.from(l)), needles)).toEqual([]);
    vi.restoreAllMocks();

    // Released, A's next retransmission keys the call as usual.
    removeRule();
    await allSecure([alice, bob]);

    // The voice path discards an accord-keys payload, a content envelope and DM text from A.
    const ackBefore = bob.encrypted.filter(r => r.type === 'call_key_ack').length;
    const keysBefore = bob.receivedKeys.length;
    const plaintexts = [
      '\u001eaccord-keys\u001e{"type":"skdm","v":1}',
      JSON.stringify({ type: 'accord.content', v: 1, channel_id: w.voiceChannel, body: 'hello' }),
      'just some DM text',
    ];
    for (const pt of plaintexts) {
      const env = alice.client.e2ee.encryptEnvelope(bob.userId, pt);
      w.hrp.inject(bob.userId, 's2c', {
        type: 'voice_key_exchange', from: alice.userId, channel_id: w.voiceChannel, wrapped_key: 'acv1:' + Buffer.from(env).toString('base64'), sender_ssrc: 0, key_generation: 0,
      });
    }
    await sleep(1500);
    expect(bob.receivedKeys.length).toBe(keysBefore);
    expect(bob.encrypted.filter(r => r.type === 'call_key_ack').length).toBe(ackBefore);
    expect(bob.decrypted.filter(d => d.at > Date.now() - 1500).length).toBe(0);

    // Positive control: a genuine NMK distribution from A on the same live path does reach B's NMK store.
    const nmk = crypto.getRandomValues(new Uint8Array(32));
    const nmkEnv = alice.client.e2ee.encryptEnvelope(bob.userId, JSON.stringify({ type: 'nmk', node: w.nodeId, key: Buffer.from(nmk).toString('base64') }));
    w.hrp.inject(bob.userId, 's2c', { type: 'sender_key_distribution', from_user_id: alice.userId, channel_id: w.textChannel, payload: btoa(nmkEnv), distribution_id: crypto.randomUUID() });
    await waitFor('B stores the NMK', () => bob.client.nmkSnapshot()[w!.nodeId] === Buffer.from(nmk).toString('hex'), 5000);
  });

  it('T-20 (I+HRP, deterministic): first hello, first two keys and first ack of every pair dropped; three clients 1 s apart reach Secure within 15 s', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol']);
    const { alice, bob, carol } = w.by;
    const counts = new Map<string, number>();
    w.hrp.addRule('c2s', m => {
      if (typeOf(m) !== 'VoiceKeyExchange') return undefined;
      const body = clientBody(m)!;
      const call = classifyWire(body.wrapped_key);
      if (!call) return undefined;
      const id = call.type === 'call_hello' ? `${call.type}:${call.from}:${call.to}` : `${call.type}:${call.from}:${call.to}:${call.body.epoch}`;
      const n = (counts.get(id) ?? 0) + 1;
      counts.set(id, n);
      if (call.type === 'call_hello' && n === 1) return 'drop';
      if (call.type === 'call_key' && n <= 2) return 'drop';
      if (call.type === 'call_key_ack' && n === 1) return 'drop';
      return undefined;
    });
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob, carol], 1000);
    const lastJoin = Date.now();
    await allSecure([alice, bob, carol], 15_000);
    expect(Date.now() - lastJoin).toBeLessThanOrEqual(15_000);
    for (const a of w.hcs) for (const b of w.hcs) if (a !== b) await a.hears(b, { since: Date.now() - 500 });
    // No (sender, recipient, epoch) saw more than 6 CKM transmissions.
    for (const [id, n] of counts) if (id.startsWith('call_key:')) expect(n).toBeLessThanOrEqual(6);
    expect([...counts.keys()].some(id => id.startsWith('call_key:'))).toBe(true);
  });

  it('T-20 (I+HRP, exhaustion and recovery): every ACK from B to A dropped for 20 s; A spends its budget, recovers every 15 s, and A → B is Secure within 17 s after the drop ends', async () => {
    w = await buildWorld(relay, ['alice', 'bob']);
    const { alice, bob } = w.by;
    let dropping = true;
    const ckmTimes: number[] = [];
    w.hrp.addRule('c2s', m => {
      if (typeOf(m) !== 'VoiceKeyExchange') return undefined;
      const call = classifyWire(clientBody(m)!.wrapped_key);
      if (call?.type === 'call_key' && call.from === alice.userId) ckmTimes.push(Date.now());
      if (dropping && call?.type === 'call_key_ack' && call.from === bob.userId) return 'drop';
      return undefined;
    });
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob]);
    await waitFor('B keyed by A', () => bob.participant(alice)?.inbound === 'keyed', 10_000);
    await sleep(20_000);
    expect(alice.participant(bob)?.outbound).not.toBe('secure');
    // First transmission, 5 retransmissions 2 s apart, then recovery every 15 s: 7 by now at most.
    const inWindow = ckmTimes.length;
    expect(inWindow).toBeGreaterThanOrEqual(6);
    expect(inWindow).toBeLessThanOrEqual(8);
    const gaps = ckmTimes.slice(1).map((t, i) => t - ckmTimes[i]);
    expect(gaps.every(g => g >= 1900)).toBe(true);
    dropping = false;
    const dropEnded = Date.now();
    await waitFor('A → B secure', () => alice.participant(bob)?.outbound === 'secure', 17_500);
    expect(Date.now() - dropEnded).toBeLessThanOrEqual(17_500);
  });

  it('T-21 (I): ten calls with an outdated client that never decrypts call messages; A sends at most 32 of them, and P then decrypts A\'s DM', async () => {
    w = await buildWorld(relay, ['x', 'y'], {
      client: () => ({ callTimings: { helloRetryMs: [150, 300, 450], helloRecoveryMs: 300, sendMinGapMs: 100 } }),
    });
    const [a, p] = byId(w.by.x, w.by.y);
    const dm = await dmChannel(a, p, w.nodeId);
    // P emulates an outdated client: it joins the voice channel but has no voice code at all.
    p.ws.joinVoiceChannel(w.voiceChannel);
    for (let i = 0; i < 10; i++) {
      await a.joinVoice(w.voiceChannel, w.nodeId);
      await waitFor('A joined', () => a.state.phase === 'joined', 10_000);
      await sleep(1500);
      a.leaveVoice();
      await sleep(200);
    }
    const toP = callMessagesFrom(w.hrp, a).filter(c => c.body.target_user_id === p.userId);
    expect(toP.length).toBeGreaterThanOrEqual(30); // the cap was reached
    expect(toP.length).toBeLessThanOrEqual(32);
    const before = p.client.received.length;
    await a.client.send({ kind: 'dm', channelId: dm, peerId: p.userId }, 'after ten calls');
    const got = await p.client.waitForMessage(r => p.client.received.indexOf(r) >= before && r.channelId === dm);
    expect(got.decoded.display).toBe('content');
    expect(got.decoded.body).toBe('after ten calls');
  });

  it('T-21 (I, A1): four calls reported as p2p with an old P2P-mode client, one with a share and two rotations; A\'s DM and SKDM still decrypt at P, and the share adds no call message', async () => {
    w = await buildWorld(relay, ['x', 'y', 'bob'], {
      client: () => ({ callTimings: { helloRetryMs: [300, 600, 900], helloRecoveryMs: 1000, sendMinGapMs: 200, rotationIntervalMs: 5000 } }),
    });
    const [a, p] = byId(w.by.x, w.by.y);
    const bob = w.by.bob;
    const dm = await dmChannel(a, p, w.nodeId);
    // The relay (HRP) reports the channel as p2p to everyone, in join replies and as mode changes.
    w.hrp.addRule('s2c', m => {
      const t = typeOf(m);
      if ((t === 'voice_channel_joined' || t === 'voice_participants') && m.json) return { send: [{ ...m.json, voice_mode: 'p2p' }] };
      return undefined;
    });
    p.ws.joinVoiceChannel(w.voiceChannel);
    for (let i = 0; i < 4; i++) {
      await a.joinVoice(w.voiceChannel, w.nodeId);
      await waitFor('A joined', () => a.state.phase === 'joined', 10_000);
      for (const hc of [a, bob]) w.hrp.inject(hc.userId, 's2c', { type: 'voice_mode_changed', channel_id: w.voiceChannel, voice_mode: 'p2p', user_id: p.userId });
      if (i === 1) {
        // One call with a share watched by B, long enough for two timer rotations.
        bob.startAudio();
        a.startAudio();
        await bob.joinVoice(w.voiceChannel, w.nodeId);
        await allSecure([a, bob]);
        await waitFor('A can share', () => a.state.screen.control.kind === 'idle', 10_000);
        const t0 = Date.now();
        const epochBefore = a.snapshot!.newestEpoch!;
        expect(a.shareScreen()).toBe(true);
        await waitFor('B sees the tile', () => bob.state.screen.remote.some(r => r.sharerId === a.userId), 10_000);
        bob.watch(a);
        await bob.decodes(a, { count: 3 });
        await sleep(11_000);
        const epochs = a.snapshot!.newestEpoch! - epochBefore;
        expect(epochs).toBeGreaterThanOrEqual(2);
        a.stopSharing();
        const during = a.encrypted.filter(r => r.at >= t0);
        // Only the three call message types, and to B only the keys the rotations need.
        expect(new Set(during.map(r => r.type)).size).toBeLessThanOrEqual(3);
        expect(during.every(r => ['call_hello', 'call_key', 'call_key_ack'].includes(r.type))).toBe(true);
        const keysToBob = during.filter(r => r.type === 'call_key' && r.to === bob.userId);
        const perEpoch = new Map<number, number>();
        for (const r of keysToBob) perEpoch.set(r.body.epoch, (perEpoch.get(r.body.epoch) ?? 0) + 1);
        expect(perEpoch.size).toBeLessThanOrEqual(epochs);
        expect([...perEpoch.values()].every(n => n === 1)).toBe(true);
        bob.leaveVoice();
        bob.stopAudio();
        a.stopAudio();
      } else {
        await sleep(2500);
      }
      a.leaveVoice();
      await sleep(200);
    }
    expect(clientMessagesFrom(w.hrp, a, 'SetVoiceMode')).toEqual([]);
    const toP = callMessagesFrom(w.hrp, a).filter(c => c.body.target_user_id === p.userId);
    expect(toP.length).toBeLessThanOrEqual(32);
    // A's DM and Sender Key distribution decrypt at P.
    const before = p.client.received.length;
    await a.client.send({ kind: 'dm', channelId: dm, peerId: p.userId }, 'after p2p reports');
    const got = await p.client.waitForMessage(r => p.client.received.indexOf(r) >= before && r.channelId === dm);
    expect(got.decoded.body).toBe('after p2p reports');
    await a.client.shareSenderKey(w.textChannel, p.client);
    expect(p.client.senderKeys.hasPeerKey(w.textChannel, a.userId)).toBe(true);
  });

  it('T-22 (I+HRP): a closed socket ends the call; A rejoins with a new instance, sends nothing from before, stays muted, and peers play nothing from A until its new keys arrive', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol']);
    const { alice, bob, carol } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob, carol]);
    await allSecure([alice, bob, carol]);
    await bob.hears(alice);

    for (const muted of [false, true]) {
      if (muted) alice.setMuted(true);
      const oldInst = alice.inst;
      const oldConn = connOf(w.hrp, alice);
      const mark = w.hrp.mark();
      const closedAt = Date.now();
      w.hrp.closeConn(oldConn);
      const disc = await waitFor('A notices the disconnect', () => alice.states.find(s => s.at >= closedAt && s.state.phase === 'reconnecting'), 5000);
      expect(disc.state.call).toBeNull(); // keys and state erased
      expect(disc.state.instanceId).toBeNull();
      const rejoined = await waitFor('A rejoins', () => (alice.state.phase === 'joined' && alice.inst !== oldInst ? Date.now() : undefined), 20_000);
      // A sent no media while disconnected.
      expect(alice.sentFrames.filter(f => f.at > disc.at && f.at < rejoined - 2000).length).toBe(0);
      const newInst = alice.inst!;
      expect(newInst).not.toBe(oldInst);

      for (const peer of [bob, carol]) {
        const left = await waitFor('the relay told the peer', () => relayMessagesTo(w!.hrp, peer, 'voice_peer_left', mark).find(m => m.json?.user_id === alice.userId));
        if (!muted) {
          const installed = await waitFor('the peer installs A\'s new key', () => peer.receivedKeys.find(k => k.from === alice.userId && k.inst === newInst), 15_000);
          expect(playedBetween(peer, alice, left.at + 100, installed.at)).toBe(0);
          await peer.hears(alice, { since: installed.at });
        }
      }
      // Everything A sent on its new connection authenticates only under its new instance's keys.
      const fresh = w.hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SrtpVoicePacket', since: mark });
      const bobKeys = bob.receivedKeys.filter(k => k.from === alice.userId && k.inst === newInst);
      if (!muted) {
        expect(fresh.length).toBeGreaterThan(0);
        for (const m of fresh.slice(0, 50)) {
          const f = wireFrame(m)!;
          expect(f.kind).toBe(MEDIA_KIND_AUDIO);
          expect(await openWithAny({ ...f, from: alice.userId }, bobKeys)).not.toBeNull();
        }
      } else {
        // Muted before the disconnect: no frame after rejoining until unmuted.
        await sleep(2000);
        expect(w.hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SrtpVoicePacket', since: mark })).toEqual([]);
        const unmutedAt = Date.now();
        alice.setMuted(false);
        await bob.hears(alice, { since: unmutedAt });
      }
    }
  });

  it('T-22 (I+HRP, A1): a sharer\'s disconnect stops its capture and its share for good; a viewer\'s disconnect ends its watch', async () => {
    w = await buildWorld(relay, ['alice', 'bob']);
    const { alice, bob } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    await bob.decodes(alice, { count: 3 });

    const conn = connOf(w.hrp, alice);
    const mark = w.hrp.mark();
    w.hrp.closeConn(conn);
    await waitFor('A notices', () => alice.state.phase === 'reconnecting', 5000);
    expect(alice.screen.stream.allStopped).toBe(true);
    await waitFor('B\'s tile leaves', () => !bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    await waitFor('A rejoins', () => alice.state.phase === 'joined', 20_000);
    await allSecure([alice, bob]);
    await sleep(2000);
    // No SCREEN_UP and no ScreenShareStart from A after the disconnect: the user has not clicked again.
    expect(clientMessagesFrom(w.hrp, alice, 'SCREEN_UP', mark)).toEqual([]);
    expect(clientMessagesFrom(w.hrp, alice, 'ScreenShareStart', mark)).toEqual([]);
    expect(alice.state.screen.local?.state ?? 'idle').toBe('idle');

    // Now B, the viewer, loses its socket while watching a new share.
    alice.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    const seen = bob.decodedFrom(alice).length;
    await bob.decodes(alice, { count: 2, since: seen });
    const mark2 = w.hrp.mark();
    w.hrp.closeConn(connOf(w.hrp, bob));
    await waitFor('B rejoins', () => bob.state.phase === 'joined' && bob.state.screen.remote.some(r => r.sharerId === alice.userId), 20_000);
    await sleep(1500);
    expect(bob.state.screen.watching).toBe(0);
    expect(clientMessagesFrom(w.hrp, bob, 'ScreenWatch', mark2)).toEqual([]);
  });

  it('T-38 (I+HRP): a closed idle socket drops A from voice; the self-check rejoins with a new instance and reconciles V and the share list', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol', 'dave'], {
      client: name => (name === 'alice' ? { voiceTimings: { selfCheckFirstMs: 2000, selfCheckIntervalMs: 3000, selfCheckRejoinGapMs: 3000 } } : {}),
    });
    const { alice, bob, carol, dave } = w.by;
    await alice.openIdleSocket();
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob, carol]);
    await allSecure([alice, bob, carol]);
    const oldInst = alice.inst;
    const conns = w.hrp.connsOf(alice.userId);
    expect(conns.length).toBe(2);
    const idle = conns[conns.length - 1];
    const closedAt = Date.now();
    w.hrp.closeConn(idle);
    // The relay removes A from voice and tells only B and C (C154).
    await waitFor('peers told', () => relayMessagesTo(w!.hrp, bob, 'voice_peer_left').some(m => m.json?.user_id === alice.userId));
    const rejoined = await waitFor('A rejoins', () => (alice.inst !== oldInst && alice.state.phase === 'joined' ? Date.now() : undefined), 35_000);
    expect(rejoined - closedAt).toBeLessThanOrEqual(35_000);
    expect(alice.states.some(s => s.at >= closedAt && s.state.reconnecting)).toBe(true);
    await bob.hears(alice, { since: rejoined });
    await carol.hears(alice, { since: rejoined });

    // HRP drops voice_peer_joined(D) to A; the next self-check adds D.
    w.hrp.addRule('s2c', m => (m.conn.userId === alice.userId && typeOf(m) === 'voice_peer_joined' && m.json?.user_id === dave.userId ? 'drop' : undefined));
    await dave.joinVoice(w.voiceChannel, w.nodeId);
    await waitFor('A\'s self-check adds D', () => alice.snapshot?.participants.some(p => p.userId === dave.userId), 10_000);

    // A1: HRP drops screen_share_started(B) to A; the next self-check reply adds B's tile.
    w.hrp.addRule('s2c', m => (m.conn.userId === alice.userId && typeOf(m) === 'screen_share_started' && m.json?.user_id === bob.userId ? 'drop' : undefined));
    await waitFor('B can share', () => bob.state.screen.control.kind === 'idle', 10_000);
    bob.shareScreen();
    await waitFor('B shares', () => bob.state.screen.local?.state === 'sharing', 10_000);
    await waitFor('A\'s self-check adds B\'s tile', () => alice.state.screen.remote.some(r => r.sharerId === bob.userId), 10_000);
    bob.stopSharing();
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);

    // A shares; HRP omits A from the reply's screen_sharers: A ends its share with the stop message.
    let omitA = true;
    let listA = false;
    w.hrp.addRule('s2c', m => {
      if (m.conn.userId !== alice.userId || typeOf(m) !== 'voice_participants' || !m.json) return undefined;
      const sharers: string[] = Array.isArray(m.json.screen_sharers) ? m.json.screen_sharers : [];
      if (omitA) return { send: [{ ...m.json, screen_sharers: sharers.filter(s => s !== alice.userId) }] };
      if (listA) return { send: [{ ...m.json, screen_sharers: [...sharers.filter(s => s !== alice.userId), alice.userId] }] };
      return undefined;
    });
    alice.shareScreen();
    await waitFor('A sharing', () => alice.state.screen.local?.state === 'sharing', 10_000);
    await waitFor('A ends the share', () => alice.state.screen.local?.state === 'idle', 10_000);
    expect(alice.state.screen.notice?.code).toBe('stopped_by_relay');
    // A is idle; HRP lists A as a sharer: A sends ScreenShareStop.
    omitA = false;
    listA = true;
    const mark = w.hrp.mark();
    await waitFor('A sends ScreenShareStop', () => clientMessagesFrom(w!.hrp, alice, 'ScreenShareStop', mark).length > 0, 10_000);
  });

  it('T-41 (I): relay mode reports of p2p change nothing but the note; frames and fragments keep flowing under the same instance', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol'], {
      client: name => (name === 'alice' ? { voiceTimings: { selfCheckFirstMs: 1500, selfCheckIntervalMs: 2000 } } : {}),
    });
    const { alice, bob, carol } = w.by;
    let p2pJoin = true;
    let p2pSelfCheck = false;
    w.hrp.addRule('s2c', m => {
      if (m.conn.userId !== alice.userId || !m.json) return undefined;
      const t = typeOf(m);
      if (t === 'voice_channel_joined' && p2pJoin) return { send: [{ ...m.json, voice_mode: 'p2p' }] };
      if (t === 'voice_participants' && p2pSelfCheck) return { send: [{ ...m.json, voice_mode: 'p2p' }] };
      return undefined;
    });
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [bob, alice]);
    // The join reply said p2p: the note shows, nothing else changes.
    await waitFor('note on join', () => alice.state.relayReportsP2p, 10_000);
    await allSecure([alice, bob]);
    const inst = alice.inst;
    await waitFor('B can share', () => bob.state.screen.control.kind === 'idle', 10_000);
    bob.shareScreen();
    await waitFor('tile', () => alice.state.screen.remote.some(r => r.sharerId === bob.userId), 10_000);
    alice.watch(bob);
    await alice.decodes(bob, { count: 3 });
    p2pJoin = false;

    const report = async (msg: Record<string, unknown>) => {
      w!.hrp.inject(alice.userId, 's2c', msg);
      await sleep(1500);
      expect(alice.inst).toBe(inst);
      expect(alice.state.phase).toBe('joined');
      expect(alice.state.relayReportsP2p).toBe(msg.voice_mode === 'p2p');
      const since = Date.now();
      await alice.hears(bob, { since, count: 3 });
      await bob.hears(alice, { since, count: 3 });
      const seen = alice.decodedFrom(bob).length;
      await alice.decodes(bob, { count: 1, since: seen });
    };
    await report({ type: 'voice_mode_changed', channel_id: w.voiceChannel, voice_mode: 'p2p', user_id: carol.userId });
    // B has sent no call message since the report: its per-participant note shows.
    expect(alice.participant(bob)?.notes.olderAppP2p).toBe(true);
    await report({ type: 'voice_mode', channel_id: w.voiceChannel, voice_mode: 'p2p' });
    p2pSelfCheck = true;
    await sleep(2500);
    expect(alice.state.relayReportsP2p).toBe(true);
    expect(alice.inst).toBe(inst);
    p2pSelfCheck = false;
    // A call message from B after the report clears its note (C's join makes B rotate).
    await carol.joinVoice(w.voiceChannel, w.nodeId);
    await waitFor('B\'s note clears', () => alice.participant(bob)?.notes.olderAppP2p === false, 15_000);
    await report({ type: 'voice_mode_changed', channel_id: w.voiceChannel, voice_mode: 'relay', user_id: carol.userId });
    expect(alice.inst).toBe(inst);
    for (const hc of w.hcs) expect(clientMessagesFrom(w.hrp, hc, 'SetVoiceMode')).toEqual([]);
  });

  it('T-10 (I, tagged spec05; today): B, the higher id, sends a DM while A\'s first hello is in flight: both show the session-problem note and nothing from the other is played or rendered', async () => {
    w = await buildWorld(relay, ['x', 'y']);
    const [a, b] = byId(w.by.x, w.by.y);
    const dm = await dmChannel(a, b, w.nodeId);
    // Hold A's first call message to B until B's DM has gone out.
    const held: HrpMessage[] = [];
    let holding = true;
    w.hrp.addRule('c2s', m => {
      if (!holding || m.conn.userId !== a.userId || typeOf(m) !== 'VoiceKeyExchange') return undefined;
      held.push(m);
      return 'drop';
    });
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [b, a]);
    await waitFor('A\'s hello is in flight', () => held.length > 0, 10_000);
    const before = a.client.received.length;
    await b.client.send({ kind: 'dm', channelId: dm, peerId: a.userId }, 'racing hello');
    await sleep(500);
    holding = false;
    for (const m of held) w.hrp.deliver(m.conn, 'c2s', m.json!, false);
    await waitFor('both notes', () => a.participant(b)?.notes.sessionProblem && b.participant(a)?.notes.sessionProblem, 20_000);
    await sleep(3000);
    expect(a.playedFrom(b)).toEqual([]);
    expect(b.playedFrom(a)).toEqual([]);
    const dmAtA = a.client.received.slice(before).filter(r => r.channelId === dm);
    // B's DM did not decrypt at A: its plaintext is never shown (the decode path shows the
    // undecryptable payload as it arrived, SPEC-02's raw fallback, never a plaintext).
    expect(dmAtA.length).toBe(1);
    expect(dmAtA.every(r => r.decoded.source !== 'dr' && !r.decoded.body.includes('racing hello'))).toBe(true);
  });

  it('T-45 (I): a participant that joins during a share decrypts no fragment sealed before its first epoch, even when the relay replays them', async () => {
    w = await buildWorld(relay, ['alice', 'bob', 'carol']);
    const { alice, bob, carol } = w.by;
    for (const hc of w.hcs) hc.startAudio();
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    await bob.decodes(alice, { count: 10 });
    const earlier = relayMessagesTo(w.hrp, bob, 'SCREEN_DOWN');
    const earlierSeq = new Set(bob.decodedFrom(alice).map(m => m.seq));
    await carol.joinVoice(w.voiceChannel, w.nodeId);
    await allSecure([alice, bob, carol]);
    await waitFor('tile at C', () => carol.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    carol.watch(alice);
    await carol.decodes(alice, { count: 3 });
    for (const m of earlier) w.hrp.inject(carol.userId, 's2c', m.data);
    await sleep(2000);
    const carolSeqs = carol.decodedFrom(alice).map(m => m.seq);
    expect(carolSeqs.filter(s => earlierSeq.has(s))).toEqual([]);
    // With every key C ever received, none of the earlier fragments opens.
    for (const m of earlier.slice(0, 60)) {
      expect(await openWithAny(wireFrame(m)!, carol.receivedKeys)).toBeNull();
    }
    // Video and audio keys of every epoch C installed come from the same call_key (REQ-45): C's first key is newer than every earlier fragment's KID.
    const firstEpochAtC = Math.min(...carol.receivedKeys.filter(k => k.from === alice.userId).map(k => k.epoch));
    expect(earlier.every(m => (wireFrame(m) ? frameHeaderKid(wireFrame(m)!.bytes) < firstEpochAtC : true))).toBe(true);
  });
});

function frameHeaderKid(bytes: Uint8Array): number {
  // KID of the cleartext SFrame header (§6.2.2); a KID below 8 is in the config byte.
  const cfg = bytes[2];
  if ((cfg & 0x80) === 0) return (cfg >> 4) & 0x07;
  const n = ((cfg >> 4) & 0x07) + 1;
  let kid = 0;
  for (let i = 0; i < n; i++) kid = kid * 256 + bytes[3 + i];
  return kid;
}
