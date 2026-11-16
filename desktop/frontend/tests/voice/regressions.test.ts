/**
 * SPEC-03 §10.3: the regression tests that replay the review's attacks on
 * calls (C005, C116, C112, C216) against headless clients, the real relay
 * and the hostile relay proxy. Each would fail against bbf2f17's raw-key
 * client and passes with stage 0.
 *
 * Covered here: RG-C005-1 to RG-C005-4, RG-C116-1 to RG-C116-3, RG-C112-1
 * to RG-C112-4 and RG-C216-1 to RG-C216-8. RG-C260-1 is T-28 (D,
 * `src/__tests__/voice-docs.test.ts`). The screen-sharing replays (RG-C117,
 * RG-C003, RG-C027, RG-SCR) are in `screen.test.ts`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { RelayProcess } from '../../src/__integration__/relay';
import { E2EEManager } from '../../src/e2ee';
import { encodeControlPayloadFor } from '../../src/e2ee/plaintext';
import { U32_MAX } from '../../src/voice/screenFrame';
import { RELAY_AVAILABLE, allSecure, buildWorld, disposeWorld, joinAll, startRelay, type VoiceWorld } from './world';
import { HC, classifyWire, sleep, waitFor, type ReceivedKey } from './hc';
import { clientBody, typeOf, type HrpMessage } from './hrp';
import {
  ban,
  binaryNeedles,
  connOf,
  copyMediaTo,
  dmChannel,
  duplicatesPlayed,
  establishSession,
  eventTimes,
  heldEpochs,
  leaks,
  playedBetween,
  recordOf,
  relayMessagesTo,
  textNeedles,
} from './common';
import {
  MEDIA_KIND_AUDIO,
  MEDIA_KIND_VIDEO,
  b64,
  decodeWrappedCandidates,
  forgedFragmentPlaintext,
  frameHeader,
  instBytes,
  legacyDecrypt,
  legacyEncrypt,
  openWithAny,
  openWithBaseKey,
  pcmMarker,
  sealWith,
  syntheticVp8,
  wireFrame,
  type WireFrame,
} from './wire';
import { encodeScreenDown } from '../../src/voice/screenFrame';
import { storageWrites } from './spies';

const suite = RELAY_AVAILABLE ? describe : describe.skip;

/** The marker tag of every injected or forged frame. */
const FORGED = 777;

/** An audio frame `hc` sent, as the relay would see it. */
function sentAudio(hc: HC, channelId: string, bytes: Uint8Array): WireFrame {
  return { msg: undefined as never, kind: MEDIA_KIND_AUDIO, from: hc.userId, channelId, bytes };
}

/** The newest key `holder` received from `from`. */
function newestKey(holder: HC, from: HC): ReceivedKey {
  const keys = holder.receivedKeys.filter(k => k.from === from.userId);
  if (keys.length === 0) throw new Error(`${holder.name} holds no key from ${from.name}`);
  return keys.reduce((a, b) => (b.epoch > a.epoch || (b.epoch === a.epoch && b.at > a.at) ? b : a));
}

/** Withhold relay messages of `type` to `to` matching `pred`; returns the withheld list and a release function. */
function withhold(w: VoiceWorld, to: HC, pred: (m: HrpMessage) => boolean): { held: HrpMessage[]; stop: () => void } {
  const held: HrpMessage[] = [];
  const stop = w.hrp.addRule('s2c', m => {
    if (m.conn.userId !== to.userId || !pred(m)) return undefined;
    held.push(m);
    return 'drop';
  });
  return { held, stop };
}

/** Record the relay's audio frames from `from` to `to` (the frames a replay will use). */
function recordAudio(w: VoiceWorld, from: HC, to: HC): HrpMessage[] {
  const out: HrpMessage[] = [];
  w.hrp.addRule('s2c', m => {
    if (m.conn.userId === to.userId && typeOf(m) === 'srtp_voice_packet' && m.json?.from === from.userId) out.push(m);
    return undefined;
  });
  return out;
}

function callOf(m: HrpMessage) {
  return classifyWire(m.json?.wrapped_key);
}

function isCallFrom(m: HrpMessage, from: HC, type?: string): boolean {
  if (typeOf(m) !== 'voice_key_exchange' || m.json?.from !== from.userId) return false;
  return type === undefined || callOf(m)?.type === type;
}

async function forgedAudio(secret: Uint8Array, epoch: number, channelId: string, sender: HC, inst: string, n: number, ctrBase = 5_000_000): Promise<Record<string, unknown>> {
  const frame = await sealWith(secret, epoch, MEDIA_KIND_AUDIO, ctrBase + n, { channelId, senderId: sender.userId, inst: instBytes(inst) }, pcmMarker(FORGED, n));
  return { type: 'srtp_voice_packet', from: sender.userId, channel_id: channelId, packet_data: b64(frame), timestamp: Math.floor(Date.now() / 1000) };
}

suite('SPEC-03 §10.3 regression replays (calls)', () => {
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

  async function call(names: string[], opts: Parameters<typeof buildWorld>[2] = {}): Promise<VoiceWorld> {
    w = await buildWorld(relay, names, opts);
    for (const hc of w.hcs) hc.startAudio();
    return w;
  }

  it('RG-C005-1 (I+HRP, passive): the review\'s reproduction run as the relay decrypts nothing', async () => {
    const { by, hrp } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol]);
    await allSecure([alice, bob, carol]);
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    await bob.decodes(alice, { count: 5 });
    await sleep(2000);

    // Every wrapped_key, base64-decoded; every 16, 24 or 32-byte result is a candidate key.
    const candidates = hrp.messages({ dir: 's2c', type: 'voice_key_exchange' })
      .flatMap(m => decodeWrappedCandidates(String(m.json!.wrapped_key)))
      .filter(b => [16, 24, 32].includes(b.length));
    // Positive control: a raw key in a wrapped_key is found and opens a legacy frame.
    const control = crypto.getRandomValues(new Uint8Array(32));
    const controlCandidates = decodeWrappedCandidates(b64(control)).filter(b => b.length === 32);
    expect(await legacyDecrypt(controlCandidates[0], await legacyEncrypt(control, pcmMarker(1, 1), 1))).not.toBeNull();

    const frames = [...hrp.messages({ dir: 's2c', type: 'srtp_voice_packet' }), ...hrp.messages({ dir: 's2c', type: 'SCREEN_DOWN' })]
      .map(wireFrame)
      .filter((f): f is WireFrame => f !== null);
    expect(frames.length).toBeGreaterThan(100);
    const insts = [...new Set(w!.hcs.flatMap(hc => hc.receivedKeys.map(k => k.inst)))].map(instBytes);
    let successes = 0;
    for (const key of candidates) {
      for (const f of frames.filter((_, i) => i % 5 === 0)) {
        if (await legacyDecrypt(key, f.bytes)) successes++;
        if (key.length === 32 && (await openWithBaseKey(f, key, insts))) successes++;
      }
    }
    expect(successes).toBe(0);
    expect(hrp.messages({ dir: 'c2s', type: 'VoicePacket' })).toEqual([]);
  });

  it('RG-C005-2 (I+HRP, active): a raw key injected under A\'s id, then frames under it in both forms, play nothing', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    const k = crypto.getRandomValues(new Uint8Array(32));
    hrp.inject(bob.userId, 's2c', { type: 'voice_key_exchange', from: alice.userId, channel_id: voiceChannel, wrapped_key: b64(k), sender_ssrc: 0, key_generation: 0 });
    const inst = newestKey(bob, alice).inst;
    const epoch = newestKey(bob, alice).epoch;
    for (let i = 0; i < 40; i++) {
      const legacy = await legacyEncrypt(k, pcmMarker(FORGED, i), i);
      hrp.inject(bob.userId, 's2c', { type: 'voice_packet', from: alice.userId, channel_id: voiceChannel, encrypted_audio: Array.from(legacy), sequence: i });
      for (const e of [0, epoch, epoch + 1]) hrp.inject(bob.userId, 's2c', await forgedAudio(k, e, voiceChannel, alice, inst, i * 3 + e));
      await sleep(20);
    }
    const t = Date.now();
    await sleep(1500);
    expect(bob.played.filter(p => p.tag === FORGED)).toEqual([]);
    await bob.hears(alice, { since: t });
  });

  it('RG-C005-3 (I+HRP, established session): A\'s first CKM to B replaced by an x3dh envelope from a relay-held identity installs nothing', async () => {
    const { by, hrp, voiceChannel, nodeId } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    const dm = await dmChannel(alice, bob, nodeId);
    // A and B already share a session.
    await alice.client.send({ kind: 'dm', channelId: dm, peerId: bob.userId }, 'hi');
    await bob.client.waitForMessage(r => r.channelId === dm);
    await bob.client.send({ kind: 'dm', channelId: dm, peerId: alice.userId }, 'hello');
    await alice.client.waitForMessage(r => r.channelId === dm);
    expect(alice.client.e2ee.hasSession(bob.userId) && bob.client.e2ee.hasSession(alice.userId)).toBe(true);

    const relayIdentity = new E2EEManager();
    relayIdentity.initialize();
    const resp = await alice.client.api.fetchKeyBundle(bob.userId, alice.client.token);
    const fromB64 = (s: string) => Uint8Array.from(Buffer.from(s, 'base64'));
    const bobBundle = { identityKey: fromB64(resp.identity_key), signedPrekey: fromB64(resp.signed_prekey), oneTimePrekey: resp.one_time_prekey ? fromB64(resp.one_time_prekey) : undefined };
    const k = crypto.getRandomValues(new Uint8Array(32));
    let replaced = 0;
    hrp.addRule('c2s', m => {
      if (m.conn.userId !== alice.userId || typeOf(m) !== 'VoiceKeyExchange') return undefined;
      const body = clientBody(m)!;
      const c = classifyWire(body.wrapped_key);
      if (c?.type !== 'call_key' || c.to !== bob.userId) return undefined;
      if (replaced > 0) return 'drop'; // A's retransmissions are blocked
      replaced++;
      const forged = encodeControlPayloadFor('voice', { type: 'call_key', v: 1, suite: 5, from: alice.userId, ch: voiceChannel, inst: c.body.inst, to_inst: c.body.to_inst, epoch: c.body.epoch, key: b64(k) });
      const env = relayIdentity.encryptEnvelope(bob.userId, forged, bobBundle);
      return { send: [{ ...m.json!, message_type: { VoiceKeyExchange: { ...body, wrapped_key: 'acv1:' + Buffer.from(env).toString('base64') } } }] };
    });
    await joinAll(w!, [bob, alice]);
    await waitFor('the forged CKM was sent', () => replaced > 0, 15_000);
    await waitFor('B notes a session problem', () => bob.participant(alice)?.notes.sessionProblem, 10_000);
    const inst = alice.encrypted.find(r => r.type === 'call_key')!.body.inst;
    for (let i = 0; i < 30; i++) {
      hrp.inject(bob.userId, 's2c', await forgedAudio(k, 0, voiceChannel, alice, inst, i));
      await sleep(20);
    }
    await waitFor('B shows "Can\'t hear them"', () => bob.participant(alice)?.label === 'cant_hear_them', 20_000);
    expect(bob.receivedKeys.filter(r => r.from === alice.userId)).toEqual([]);
    expect(bob.playedFrom(alice)).toEqual([]);
  });

  it('RG-C005-4 (I+HRP, harvesting): A\'s CKMs to B diverted into a DM and a pending distribution are never rendered, stored, logged or installed', async () => {
    const { by, hrp, textChannel, nodeId } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await establishSession(alice, bob, await dmChannel(alice, bob, nodeId));
    const ckms: HrpMessage[] = [];
    const stop = hrp.addRule('s2c', m => {
      if (m.conn.userId !== bob.userId || !isCallFrom(m, alice, 'call_key')) return undefined;
      ckms.push(m);
      return 'drop';
    });
    await joinAll(w!, [bob, alice]);
    await waitFor('two withheld CKM transmissions', () => ckms.length >= 2, 15_000);
    const needles = ckms.flatMap((m, i) => binaryNeedles(`secret ${i}`, Uint8Array.from(Buffer.from(callOf(m)!.body.key, 'base64'))));
    needles.push(...textNeedles('tag', '\u001eaccord-call\u001e'));
    const logged: string[] = [];
    const orig = { log: console.log, info: console.info, warn: console.warn, error: console.error };
    for (const level of ['log', 'info', 'warn', 'error'] as const) console[level] = (...args: unknown[]) => logged.push(args.map(a => String(a)).join(' '));
    const storageBefore = storageWrites().length;
    const received = bob.client.received.length;
    const cacheBefore = bob.client.cacheMap.size;
    try {
      const payload = (m: HrpMessage) => String(m.json!.wrapped_key).slice(5);
      hrp.inject(bob.userId, 's2c', { type: 'channel_message', channel_id: textChannel, from: alice.userId, message_id: crypto.randomUUID(), encrypted_data: payload(ckms[0]), is_dm: true, timestamp: Math.floor(Date.now() / 1000) });
      hrp.inject(bob.userId, 's2c', { type: 'pending_sender_keys', distributions: [{ id: crypto.randomUUID(), from_user_id: alice.userId, channel_id: textChannel, encrypted_payload: payload(ckms[1]), created_at: 1 }] });
      await waitFor('the DM path ran', () => bob.client.received.length > received, 10_000);
      await sleep(500);
    } finally {
      Object.assign(console, orig);
    }
    expect(bob.client.received.slice(received).map(r => r.decoded.display)).toEqual(['hidden']);
    expect(bob.client.cacheMap.size).toBe(cacheBefore);
    expect(leaks(storageWrites().slice(storageBefore).map(s => Buffer.from(s.value)), needles)).toEqual([]);
    expect(leaks(logged.map(l => Buffer.from(l)), needles)).toEqual([]);
    expect(bob.receivedKeys).toEqual([]);
    stop();
    await allSecure([alice, bob]);
  });

  it('RG-C116-1 (I): an outsider\'s VoicePacket and SrtpVoicePacket with marked PCM play nothing and add no participant, whether or not the relay forwards them', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob', 'mallory'], { outsiders: ['mallory'] });
    const { alice, bob, mallory } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    const ts = () => Math.floor(Date.now() / 1000);
    const legacy = (i: number) => ({ type: 'voice_packet', from: mallory.userId, channel_id: voiceChannel, encrypted_audio: Array.from(pcmMarker(FORGED, i)), sequence: i, timestamp: ts() });
    const srtp = (i: number) => ({ type: 'srtp_voice_packet', from: mallory.userId, channel_id: voiceChannel, packet_data: b64(pcmMarker(FORGED, i)), timestamp: ts() });
    const mark = hrp.mark();
    for (let i = 0; i < 50; i++) {
      const pcm = pcmMarker(FORGED, i);
      hrp.inject(mallory.userId, 'c2s', { message_type: { VoicePacket: { channel_id: voiceChannel, encrypted_audio: Array.from(pcm), sequence: i } }, message_id: crypto.randomUUID(), timestamp: ts() });
      hrp.inject(mallory.userId, 'c2s', { message_type: { SrtpVoicePacket: { channel_id: voiceChannel, packet_data: b64(pcm) } }, message_id: crypto.randomUUID(), timestamp: ts() });
      await sleep(10);
    }
    await sleep(1500);
    // The relay of this release still forwards both from a non-participant (C052, whose relay fix is
    // roadmap P0 item 3). Where it does not, HRP delivers them itself, as such a relay would: the
    // client's refusal is what this test checks.
    for (const hc of [alice, bob]) {
      for (const [type, make] of [['voice_packet', legacy], ['srtp_voice_packet', srtp]] as const) {
        const forwarded = relayMessagesTo(hrp, hc, type, mark).some(m => !m.injected && m.json?.from === mallory.userId);
        if (!forwarded) for (let i = 0; i < 50; i++) hrp.inject(hc.userId, 's2c', make(i));
      }
    }
    await sleep(1500);
    for (const hc of [alice, bob]) {
      for (const type of ['voice_packet', 'srtp_voice_packet']) expect(relayMessagesTo(hrp, hc, type, mark).some(m => m.json?.from === mallory.userId), `${type} to ${hc.name}`).toBe(true);
      expect(hc.played.filter(p => p.tag === FORGED || p.from === mallory.userId)).toEqual([]);
      expect(hc.snapshot!.participants.some(p => p.userId === mallory.userId)).toBe(false);
    }
    await bob.hears(alice, { since: Date.now() }); // the call itself is unaffected
  });

  it('RG-C116-2 (I+HRP): a participant whose call messages are all dropped sends frames that nobody plays', async () => {
    const { by, hrp } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    hrp.addRule('c2s', m => (m.conn.userId === carol.userId && typeOf(m) === 'VoiceKeyExchange' ? 'drop' : undefined));
    await joinAll(w!, [alice, bob, carol]);
    await waitFor('A and B secure', () => alice.participant(bob)?.label === 'secure' && bob.participant(alice)?.label === 'secure', 15_000);
    await sleep(4000);
    expect(hrp.messages({ dir: 'c2s', user: carol.userId, type: 'SrtpVoicePacket' }).length).toBeGreaterThan(20);
    expect(alice.playedFrom(carol)).toEqual([]);
    expect(bob.playedFrom(carol)).toEqual([]);
  });

  it('RG-C116-3 (I+HRP): after a reconnect peers play nothing from A until its new keys are installed, then only A\'s markers; no noise at any point', async () => {
    const { by, hrp } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await bob.hears(alice);
    const oldInst = alice.inst;
    const mark = hrp.mark();
    hrp.closeConn(connOf(hrp, alice));
    await waitFor('A rejoins', () => alice.state.phase === 'joined' && alice.inst !== oldInst, 20_000);
    const left = await waitFor('B told', () => relayMessagesTo(hrp, bob, 'voice_peer_left', mark)[0]);
    const installed = await waitFor('B installs A\'s new key', () => bob.receivedKeys.find(k => k.from === alice.userId && k.inst === alice.inst), 15_000);
    expect(playedBetween(bob, alice, left.at + 100, installed.at)).toBe(0);
    await bob.hears(alice, { since: installed.at });
    // Every buffer B ever played from A is one of A's markers: no noise.
    expect(bob.playedFrom(alice).every(p => p.tag === alice.options.tag)).toBe(true);
    expect(duplicatesPlayed(bob, alice)).toEqual([]);
  });

  it('RG-C112-1 (I+HRP): after C leaves, frames A sends never decrypt with any key C ever received, though a non-evicting relay keeps sending them', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol]);
    await allSecure([alice, bob, carol]);
    const processed = eventTimes(alice, 'voice_peer_left', d => d.user_id === carol.userId);
    copyMediaTo(hrp, alice, bob, carol);
    // Positive control: C's keys open A's frames from before the departure. A may already seal under
    // an epoch whose key is still on its way to C (REQ-17 switches within 2 s), so wait until they do.
    let controlOpened = false;
    for (const deadline = Date.now() + 10_000; !controlOpened && Date.now() < deadline;) {
      const last = alice.sentFrames[alice.sentFrames.length - 1];
      controlOpened = last !== undefined && (await openWithAny(sentAudio(alice, voiceChannel, last.bytes), carol.receivedKeys)) !== null;
      if (!controlOpened) await sleep(100);
    }
    expect(controlOpened).toBe(true);
    carol.leaveVoice();
    await waitFor('A processed the departure', () => processed[0]);
    await sleep(4000);
    const after = alice.sentFrames.filter(f => f.at > processed[0]);
    expect(after.length).toBeGreaterThan(50);
    for (const f of after) expect(await openWithAny(sentAudio(alice, voiceChannel, f.bytes), carol.receivedKeys)).toBeNull();
  });

  it('RG-C112-2 (I+HRP): kicked C keeps nothing useful with a relay emulating no eviction; with REQ-29, C is evicted and receives nothing more', async () => {
    const { by, hrp, voiceChannel, nodeId } = await call(['alice', 'bob', 'carol', 'dave']);
    const { alice, bob, carol, dave } = by;
    await joinAll(w!, [alice, bob, carol, dave], 300);
    await allSecure([alice, bob, carol, dave]);
    // A relay without REQ-29: no voice_peer_left(C), no voice_channel_left to C, and A's frames keep reaching C.
    hrp.addRule('s2c', m => {
      const t = typeOf(m);
      if (t === 'voice_peer_left' && m.json?.user_id === carol.userId) return 'drop';
      if (t === 'voice_channel_left' && m.conn.userId === carol.userId) return 'drop';
      return undefined;
    });
    copyMediaTo(hrp, alice, bob, carol);
    const rotated = eventTimes(alice, 'sender_key_rotation_required', d => d.removed_user_id === carol.userId);
    await alice.client.api.kickMember(nodeId, carol.userId, alice.client.token);
    await waitFor('A processed the rotation event', () => rotated[0], 10_000);
    await sleep(4000);
    const after = alice.sentFrames.filter(f => f.at > rotated[0]);
    expect(after.length).toBeGreaterThan(50);
    for (const f of after) expect(await openWithAny(sentAudio(alice, voiceChannel, f.bytes), carol.receivedKeys)).toBeNull();

    // Without the emulation (REQ-29 active), D is evicted and receives no more frames.
    const mark = hrp.mark();
    await alice.client.api.kickMember(nodeId, dave.userId, alice.client.token);
    const evicted = await waitFor('D evicted', () => relayMessagesTo(hrp, dave, 'voice_channel_left', mark).find(m => m.json?.reason === 'removed'), 10_000);
    await waitFor('D shows the removal', () => dave.state.phase === 'removed', 5000);
    await sleep(2000);
    expect(relayMessagesTo(hrp, dave, 'srtp_voice_packet', evicted.seq).length).toBe(0);
  });

  it('RG-C112-3 (I+HRP): banned C, with no eviction and no rotation events, is excluded by A\'s 2 s member refresh; later frames do not decrypt for C', async () => {
    const { by, hrp, voiceChannel, nodeId } = await call(['alice', 'bob', 'carol'], {
      client: name => (name === 'alice' ? { callTimings: { memberRefreshMs: 2000 } } : {}),
    });
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    hrp.addRule('s2c', m => {
      const t = typeOf(m);
      if (t === 'sender_key_rotation_required') return 'drop';
      if (t === 'voice_peer_left' && m.json?.user_id === carol.userId) return 'drop';
      if (t === 'voice_channel_left' && m.conn.userId === carol.userId) return 'drop';
      return undefined;
    });
    copyMediaTo(hrp, alice, bob, carol);
    const bannedAt = Date.now();
    expect(await ban(hrp.baseUrl, alice, nodeId, carol)).toBe(200);
    const excluded = await waitFor('A excludes C', () => (alice.participant(carol)?.ineligibleReason ? Date.now() : undefined), 6000);
    expect(excluded - bannedAt).toBeLessThanOrEqual(2000 + 1500);
    await sleep(3000);
    const after = alice.sentFrames.filter(f => f.at > excluded);
    expect(after.length).toBeGreaterThan(50);
    for (const f of after) expect(await openWithAny(sentAudio(alice, voiceChannel, f.bytes), carol.receivedKeys)).toBeNull();
    expect(bob.participant(carol)).toBeDefined();
  });

  /**
   * RG-C112-4: A, B and C in a call; A shares and B watches. C is kicked and A
   * rotates to g+1. HRP and C's client then inject audio frames and
   * fragments under A's epoch g, sealed with C's copy of g's key, with new
   * markers, a fragment with share_seq 2^32 − 1 and a keyframe with frame_no
   * 2^32 − 2. Run 1 injects once A's g+1 frames have reached B; run 2
   * withholds every A → B call message after the removal, injects for
   * KEY_MAX_AGE (a test value) and then releases them. `counters` places the
   * forged CTR and VCTR just ahead of A's own, or far ahead (2^47, the form
   * amendment A2 adds to run 2).
   */
  async function forgeUnderPreviousEpoch(run: 1 | 2, counters: 'near' | 'far') {
    const keyMaxAgeMs = 8000;
    const { by, hrp, voiceChannel, nodeId } = await call(['alice', 'bob', 'carol'], {
      client: name => (name === 'alice' ? { callTimings: { rotationIntervalMs: 6000 } } : name === 'bob' ? { callTimings: { keyMaxAgeMs } } : {}),
    });
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId), 10_000);
    bob.watch(alice);
    await bob.decodes(alice, { count: 3 });
    const g = newestKey(carol, alice);
    const installedAtB = bob.receivedKeys.find(k => k.from === alice.userId && k.epoch === g.epoch)!.at;
    let release: (() => void) | null = null;
    if (run === 2) release = withhold(w!, bob, m => typeOf(m) === 'voice_key_exchange' && m.json?.from === alice.userId).stop;
    const rotated = eventTimes(alice, 'sender_key_rotation_required', d => d.removed_user_id === carol.userId);
    await alice.client.api.kickMember(nodeId, carol.userId, alice.client.token);
    await waitFor('A rotated', () => rotated[0] && (alice.snapshot?.newestEpoch ?? 0) > g.epoch, 10_000);
    if (run === 1) {
      await waitFor('B installs A\'s next epoch', () => bob.receivedKeys.some(k => k.from === alice.userId && k.epoch > g.epoch), 10_000);
      const t = Date.now();
      await bob.hears(alice, { since: t });
      await sleep(2500); // past the overlap of REQ-18
    }
    const inst = instBytes(g.inst);
    const lastCtr = (type: string) => {
      const m = hrp.messages({ dir: 'c2s', user: alice.userId, type }).slice(-1)[0];
      const f = m ? wireFrame(m) : null;
      return f ? frameHeader(f.bytes)!.ctr : 0;
    };
    const audioBase = counters === 'far' ? 2 ** 47 : run === 1 ? 5_000_000 : lastCtr('SrtpVoicePacket') + 100;
    const videoBase = counters === 'far' ? 2 ** 47 : run === 1 ? 9_000_000 : lastCtr('SCREEN_UP') + 50;
    const forgeVideo = async (i: number, shareSeq: number, frameNo: number) => {
      const pt = forgedFragmentPlaintext({ vcodec: 1, flags: 1, shareSeq, frameNo, width: 1280, height: 720 }, syntheticVp8(true, 1280, 720, { tag: FORGED, seq: 100_000 + i, picture: i }, 2000));
      const frag = await sealWith(g.secret, g.epoch, MEDIA_KIND_VIDEO, videoBase + i, { channelId: voiceChannel, senderId: alice.userId, inst }, pt);
      return encodeScreenDown(voiceChannel, alice.userId, frag);
    };
    const injectUntil = Date.now() + (run === 1 ? 3000 : keyMaxAgeMs + 4000);
    let i = 0;
    while (Date.now() < injectUntil) {
      hrp.inject(bob.userId, 's2c', await forgedAudio(g.secret, g.epoch, voiceChannel, alice, g.inst, i, audioBase));
      hrp.inject(bob.userId, 's2c', await forgeVideo(i, i % 2 === 0 ? U32_MAX : 1, i % 2 === 0 ? 0 : U32_MAX - 1));
      i++;
      await sleep(100);
    }
    return {
      alice,
      bob,
      g: g.epoch,
      forgedPlayed: bob.played.filter(p => p.tag === FORGED),
      forgedDecoded: bob.decodedFrom(alice).filter(m => m.tag === FORGED).concat(bob.screen.decodedMarkers.filter(m => m.tag === FORGED)),
      deadline: installedAtB + keyMaxAgeMs + 1000,
      release,
    };
  }

  it('RG-C112-4 (I+HRP, run 1): frames and fragments forged under A\'s previous epoch with removed C\'s key are never played or decoded once A\'s next epoch reached B', async () => {
    const r = await forgeUnderPreviousEpoch(1, 'far');
    expect(r.forgedPlayed).toEqual([]);
    expect(r.forgedDecoded).toEqual([]);
  });

  it('RG-C112-4 (I+HRP, run 2): with A\'s newer keys withheld, forged frames stop within KEY_MAX_AGE, B shows "Can\'t hear them", and A\'s video resumes with its first keyframe under the newest epoch once released', async () => {
    // Run 2 documents the bounded residual of §9.2 item 2. The forged counters stay just ahead of A's
    // own; the far-ahead form of A2 (§14.1) is the next test.
    const { alice, bob, forgedPlayed, deadline, release } = await forgeUnderPreviousEpoch(2, 'near');
    expect(forgedPlayed.filter(p => p.at > deadline)).toEqual([]);
    await waitFor('B shows "Can\'t hear them"', () => bob.participant(alice)?.label === 'cant_hear_them' || bob.participant(alice)?.inbound === 'waiting', 5000);
    const seen = bob.decodedFrom(alice).length;
    release!();
    // A's genuine video resumes with A's first keyframe under its newest epoch.
    const resumed = await bob.decodes(alice, { count: 2, since: seen, timeoutMs: 25_000 });
    expect(resumed[0].key).toBe(true);
  });

  /**
   * RG-C112-4 run 2 as amended by A2 (§14.1): the forged CTR and VCTR are at
   * 2^47 and above. They authenticate under g until KEY_MAX_AGE (the bounded
   * residual), but with one replay window per epoch they move only g's
   * windows, which go with g; the jitter buffer is reset by A's first frame
   * under the newer epoch. So once HRP releases A's messages, A's genuine
   * audio plays and its video resumes at B under the newest epoch.
   */
  it('RG-C112-4 (I+HRP, run 2 with counters far ahead, A2): forged frames at 2^47 stop within KEY_MAX_AGE; once A\'s withheld messages are released, A\'s audio plays and its video resumes at B under the newest epoch', async () => {
    const r = await forgeUnderPreviousEpoch(2, 'far');
    expect(r.forgedPlayed.length).toBeGreaterThan(0); // they did authenticate under g (the residual)
    expect(r.forgedPlayed.filter(p => p.at > r.deadline)).toEqual([]);
    await waitFor('B shows "Can\'t hear them"', () => r.bob.participant(r.alice)?.label === 'cant_hear_them' || r.bob.participant(r.alice)?.inbound === 'waiting', 5000);
    // g's key, and with it g's windows (the only ones the forgeries moved), are gone.
    const g = r.g;
    const before = recordOf(r.bob, r.alice)!;
    expect(heldEpochs(r.bob, r.alice)).toEqual([]);
    expect(before.replayWindows.filter(w => w.audio >= 2 ** 47 || w.video >= 2 ** 47)).toEqual([]);
    const seenVideo = r.bob.decodedFrom(r.alice).length;
    const releasedAt = Date.now();
    r.release!();
    const heard = await r.bob.hears(r.alice, { since: releasedAt, timeoutMs: 25_000 });
    const resumed = await r.bob.decodes(r.alice, { count: 2, since: seenVideo, timeoutMs: 25_000 });
    expect(resumed[0].key).toBe(true);
    // Under the newest epoch: B holds only epochs above g, and A's own counters, far below 2^47.
    const held = heldEpochs(r.bob, r.alice);
    expect(held.length).toBeGreaterThan(0);
    expect(held.every(e => e > g)).toBe(true);
    const after = recordOf(r.bob, r.alice)!;
    expect(after.highestAuthEpoch.audio).toBeGreaterThan(g);
    expect(after.highestAuthEpoch.video).toBeGreaterThan(g);
    expect(after.replayWindows.every(w => w.audio < 2 ** 47 && w.video < 2 ** 47)).toBe(true);
    expect(heard.every(p => p.tag === r.alice.options.tag)).toBe(true);
    expect(r.bob.played.filter(p => p.tag === FORGED && p.at >= releasedAt)).toEqual([]);
  });

  it('RG-C216-1 (I+HRP): duplicated, replayed, reordered and modified frames: each genuine marker plays at most once, modified frames never', async () => {
    const { by, hrp } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    const recorded: Record<string, any>[] = [];
    const flipped: Record<string, any>[] = [];
    let k = 0;
    hrp.addRule('s2c', m => {
      if (m.conn.userId !== bob.userId || typeOf(m) !== 'srtp_voice_packet' || m.json?.from !== alice.userId) return undefined;
      recorded.push({ ...m.json, at: Date.now() });
      k++;
      if (k % 10 === 0) {
        const bytes = Buffer.from(String(m.json.packet_data), 'base64');
        const cfg = bytes[2];
        if ((cfg & 0x08) !== 0) {
          // A CTR byte (the last header byte) is flipped; the original is not delivered.
          const ctrLen = (cfg & 0x07) + 1;
          const kidLen = (cfg & 0x80) !== 0 ? ((cfg >> 4) & 0x07) + 1 : 0;
          bytes[2 + 1 + kidLen + ctrLen - 1] ^= 0x01;
          const mod = { ...m.json, packet_data: bytes.toString('base64') };
          flipped.push(m.json);
          return { send: [mod] };
        }
      }
      // Duplicated, and both copies delayed by up to 100 ms (reordering).
      return { send: [m.json!, m.json!], delayMs: Math.floor(Math.random() * 100) };
    });
    await sleep(6000);
    // Replay a 5-second-old batch.
    const old = recorded.filter(r => r.at < Date.now() - 5000).slice(0, 50);
    for (const r of old) hrp.inject(bob.userId, 's2c', { ...r, at: undefined });
    await sleep(1500);
    expect(duplicatesPlayed(bob, alice)).toEqual([]);
    // The flipped frames never play: their markers (read with B's keys) are absent.
    const flippedMarkers: number[] = [];
    for (const f of flipped) {
      const pt = await openWithAny({ msg: undefined as never, kind: MEDIA_KIND_AUDIO, from: alice.userId, channelId: f.channel_id, bytes: Uint8Array.from(Buffer.from(f.packet_data, 'base64')) }, bob.receivedKeys);
      if (pt) flippedMarkers.push(new DataView(pt.buffer, pt.byteOffset).getInt16(3, true));
    }
    expect(flippedMarkers.length).toBeGreaterThan(5);
    const played = new Set(bob.playedFrom(alice).map(p => p.n));
    expect(flippedMarkers.filter(n => played.has(n))).toEqual([]);
    expect(bob.playedFrom(alice).length).toBeGreaterThan(100);
  });

  /**
   * RG-C216-2 with A2's third case of REQ-33 (e): after the fake leave and
   * rejoin, B (same instance) erased S's keys and says hello again; S, whose
   * current epoch B had acknowledged, sends its current CKM once more, so S's
   * live audio resumes without waiting for S's next epoch (10 minutes here).
   */
  it('RG-C216-2 (I+HRP, withheld copy and fake rejoin, A2): the withheld first copy is refused, nothing replayed plays, and S\'s live audio resumes once S answers B\'s hello with its current epoch, without a new epoch', async () => {
    const { by, hrp, voiceChannel } = await call(['sam', 'bob']);
    const { sam, bob } = by;
    let first: HrpMessage | null = null;
    hrp.addRule('s2c', m => {
      if (first || m.conn.userId !== bob.userId || !isCallFrom(m, sam, 'call_key')) return undefined;
      first = m;
      return 'drop';
    });
    const frames = recordAudio(w!, sam, bob);
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await bob.hears(sam, { count: 50 });
    const epoch = sam.snapshot!.newestEpoch!;
    expect(heldEpochs(bob, sam)).toContain(epoch);
    const fakeAt = Date.now();
    hrp.inject(bob.userId, 's2c', { type: 'voice_peer_left', channel_id: voiceChannel, user_id: sam.userId });
    hrp.inject(bob.userId, 's2c', { type: 'voice_peer_joined', channel_id: voiceChannel, user_id: sam.userId });
    await sleep(300);
    const copyBody = callOf(first!)!.body;
    hrp.inject(bob.userId, 's2c', first!.json!);
    for (const f of frames.slice(0, 100)) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1000);
    // The withheld copy decrypted only with a stored skipped key: refused (REQ-32). When the copy is of
    // S's current epoch, the same key also arrives in S's re-send below, which is not a skipped-key decryption.
    const copies = bob.decrypted.filter(d => d.from === sam.userId && d.type === 'call_key' && d.at >= fakeAt && d.body.key === copyBody.key);
    expect(copies.filter(d => d.usedSkippedKey)).toHaveLength(1);
    expect(copies.filter(d => !d.usedSkippedKey).every(d => d.body.epoch === epoch)).toBe(true);
    if (copyBody.epoch !== epoch) expect(heldEpochs(bob, sam)).not.toContain(copyBody.epoch);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
    // B's hello names S's current instance; S answers with its current CKM once more, and S's live audio resumes.
    await bob.hears(sam, { since: fakeAt + 1000, timeoutMs: 8000 });
    expect(sam.snapshot!.newestEpoch).toBe(epoch);
    const resent = relayMessagesTo(hrp, bob, 'voice_key_exchange').filter(m => m.at > fakeAt && !m.injected && isCallFrom(m, sam, 'call_key'));
    expect(resent.map(m => callOf(m)!.body.epoch)).toEqual([epoch]);
    expect(bob.decrypted.filter(d => d.from === sam.userId && d.type === 'call_key' && d.at >= fakeAt && !d.usedSkippedKey).map(d => d.body.epoch)).toEqual([epoch]);
    expect(heldEpochs(bob, sam)).toEqual([epoch]);
    // Old counters stay rejected by the retained window of that epoch.
    for (const f of frames.slice(0, 300)) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1500);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
  });

  it('RG-C216-3 (I+HRP, eligibility flap): a member list without S, then with S, then the withheld copy and replays install and play nothing', async () => {
    const { by, hrp, nodeId } = await call(['sam', 'bob'], { client: name => (name === 'bob' ? { callTimings: { memberRefreshMs: 1500 }, refetchMinMs: 500 } : {}) });
    const { sam, bob } = by;
    let first: HrpMessage | null = null;
    hrp.addRule('s2c', m => {
      if (first || m.conn.userId !== bob.userId || !isCallFrom(m, sam, 'call_key')) return undefined;
      first = m;
      return 'drop';
    });
    const frames = recordAudio(w!, sam, bob);
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await bob.hears(sam, { count: 30 });
    const real = await (await fetch(`${relay.baseUrl}/nodes/${nodeId}/members`, { headers: { Authorization: `Bearer ${bob.client.token}` } })).json();
    const list: Array<{ user_id: string }> = Array.isArray(real) ? real : real.members;
    const without = { ...(Array.isArray(real) ? {} : real), members: list.filter(m => m.user_id !== sam.userId) };
    const flapAt = Date.now();
    const stopSub = hrp.addHttpRule(req => (req.token === bob.client.token && req.method === 'GET' && req.path.startsWith(`/nodes/${nodeId}/members`) ? { status: 200, json: without } : undefined));
    await waitFor('S ineligible at B', () => bob.participant(sam)?.ineligibleReason, 10_000);
    stopSub();
    await waitFor('S eligible again', () => bob.participant(sam)?.ineligibleReason === null, 10_000);
    const t = Date.now();
    const copyBody = callOf(first!)!.body;
    hrp.inject(bob.userId, 's2c', first!.json!);
    for (const f of frames.slice(0, 100)) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1500);
    // Nothing is installed from the copy: it decrypts only with a stored skipped key (REQ-32).
    const copies = bob.decrypted.filter(d => d.from === sam.userId && d.type === 'call_key' && d.at >= t && d.body.key === copyBody.key);
    expect(copies.filter(d => d.usedSkippedKey)).toHaveLength(1);
    // B erased S's keys while S was ineligible and says hello again once S is eligible; S, whose current
    // epoch B had acknowledged, sends that CKM once more (REQ-33 (e), third case, A2). So B may hold the
    // copy's epoch again only when it is S's current epoch, from S's own re-send, never from the copy.
    if (heldEpochs(bob, sam).includes(copyBody.epoch)) {
      expect(copyBody.epoch).toBe(sam.snapshot!.newestEpoch);
      expect(bob.decrypted.some(d => d.from === sam.userId && d.type === 'call_key' && d.body.epoch === copyBody.epoch && !d.usedSkippedKey && d.at >= flapAt)).toBe(true);
    }
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
  });

  it('RG-C216-4 (I+HRP, stale key in the next call): a CKM withheld from B\'s previous call is refused for its old instance; B sends a hello; nothing replayed plays', async () => {
    const { by, hrp } = await call(['sam', 'bob', 'carol']);
    const { sam, bob, carol } = by;
    const frames = recordAudio(w!, sam, bob);
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await bob.hears(sam, { count: 30 });
    const oldInst = bob.inst;
    const { held, stop } = withhold(w!, bob, m => isCallFrom(m, sam));
    await carol.joinVoice(w!.voiceChannel, w!.nodeId); // S rotates; its CKM to B is withheld
    await waitFor('a withheld CKM', () => held.some(m => callOf(m)?.type === 'call_key'), 10_000);
    hrp.closeConn(connOf(hrp, bob));
    await waitFor('B rejoins', () => bob.state.phase === 'joined' && bob.inst !== oldInst, 20_000);
    const firstCallCkm = held.find(m => callOf(m)?.type === 'call_key' && callOf(m)!.body.to_inst === oldInst)!;
    expect(firstCallCkm).toBeDefined();
    const staleSecret = Buffer.from(callOf(firstCallCkm)!.body.key, 'base64');
    await sleep(2500); // past SEND_MIN_GAP after B's first hello of the new call (REQ-36)
    const t = Date.now();
    // Every withheld message before it is skipped; it decrypts in order.
    for (const m of held.slice(held.indexOf(firstCallCkm))) {
      if (m === firstCallCkm) hrp.inject(bob.userId, 's2c', m.json!);
    }
    await waitFor('B decrypted it', () => bob.decrypted.find(d => d.from === sam.userId && d.at >= t && d.type === 'call_key'), 5000);
    // REQ-33 (b): refused for its to_inst, and answered with a hello naming S's instance.
    await waitFor('B sends S a hello', () => bob.encrypted.some(r => r.type === 'call_hello' && r.to === sam.userId && r.at >= t && r.body.to_inst === sam.inst), 5000);
    stop();
    for (const m of held.slice(held.indexOf(firstCallCkm) + 1)) hrp.inject(bob.userId, 's2c', m.json!);
    for (const f of frames.slice(0, 100)) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1500);
    const d = bob.decrypted.find(x => x.from === sam.userId && x.at >= t && x.type === 'call_key')!;
    // It decrypted in Double Ratchet order (no skipped key) and was refused for naming B's old instance.
    expect(d.usedSkippedKey).toBe(false);
    expect(Buffer.from(d.body.key, 'base64').equals(staleSecret)).toBe(true);
    expect(d.body.to_inst).toBe(oldInst);
    expect(heldEpochs(bob, sam)).not.toContain(callOf(firstCallCkm)!.body.epoch);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
    await bob.hears(sam, { since: Date.now(), timeoutMs: 15_000 });
  });

  it('RG-C216-5 (I+HRP, previous sender instance): S\'s withheld CKMs and frames from its previous instance are refused after B accepted its new one', async () => {
    const { by, hrp } = await call(['sam', 'bob', 'carol']);
    const { sam, bob, carol } = by;
    const frames = recordAudio(w!, sam, bob);
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await bob.hears(sam, { count: 30 });
    const oldInst = sam.inst!;
    const { held, stop } = withhold(w!, bob, m => isCallFrom(m, sam) && callOf(m)?.body.inst === oldInst);
    await carol.joinVoice(w!.voiceChannel, w!.nodeId);
    await waitFor('a withheld CKM', () => held.some(m => callOf(m)?.type === 'call_key'), 10_000);
    hrp.closeConn(connOf(hrp, sam));
    await waitFor('S rejoins', () => sam.state.phase === 'joined' && sam.inst !== oldInst, 20_000);
    await waitFor('B accepted S\'s new instance', () => bob.receivedKeys.some(k => k.from === sam.userId && k.inst === sam.inst), 15_000);
    stop();
    const t = Date.now();
    for (const m of held) hrp.inject(bob.userId, 's2c', m.json!);
    for (const f of frames.slice(0, 150)) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1500);
    // Every withheld message decrypted with a skipped key, or named the replaced instance; B's record still follows S's new instance.
    const heldWires = new Set(held.map(m => String(m.json!.wrapped_key)));
    const heldBodies = new Set([...heldWires].map(wire => JSON.stringify(classifyWire(wire)?.body)));
    const delivered = bob.decrypted.filter(d => d.from === sam.userId && d.at >= t && heldBodies.has(JSON.stringify(d.body)));
    expect(delivered.every(d => d.usedSkippedKey || d.body.inst === oldInst)).toBe(true);
    const rec = recordOf(bob, sam)!;
    expect(rec.currentInst).toBe(sam.inst);
    expect(rec.replaced).toContain(oldInst);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
  });

  it('RG-C216-6 (I+HRP, newest key held back): CKM(e+1) withheld while CKM(e+2) passes is refused later, and frames under e+1 and e play nothing', async () => {
    const { by, hrp } = await call(['sam', 'bob', 'carol', 'dave']);
    const { sam, bob, carol, dave } = by;
    const frames = recordAudio(w!, sam, bob);
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await bob.hears(sam, { count: 30 });
    const e = sam.snapshot!.newestEpoch!;
    const { held, stop } = withhold(w!, bob, m => isCallFrom(m, sam, 'call_key') && callOf(m)!.body.epoch === e + 1);
    await carol.joinVoice(w!.voiceChannel, w!.nodeId);
    await waitFor('S at e+1', () => sam.snapshot!.newestEpoch === e + 1 && held.length > 0, 10_000);
    await sleep(3000);
    await dave.joinVoice(w!.voiceChannel, w!.nodeId);
    await waitFor('B installs e+2', () => bob.receivedKeys.some(k => k.from === sam.userId && k.epoch >= e + 2), 15_000);
    stop();
    const t = Date.now();
    for (const m of held) hrp.inject(bob.userId, 's2c', m.json!);
    for (const f of frames) hrp.inject(bob.userId, 's2c', f.json!);
    await sleep(1500);
    expect(heldEpochs(bob, sam)).not.toContain(e + 1);
    expect(recordOf(bob, sam)!.maxEpoch).toBeGreaterThanOrEqual(e + 2);
    const copies = bob.decrypted.filter(d => d.from === sam.userId && d.at >= t && d.body.epoch === e + 1);
    expect(copies.length).toBeGreaterThan(0);
    expect(copies.every(d => d.usedSkippedKey)).toBe(true);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
  });

  it('RG-C216-7 (I+HRP, forgery with a departed member): frames forged under (S, inst, e) with departed D\'s key, and the withheld CKM(e) after a fake rejoin, yield nothing', async () => {
    const { by, hrp, voiceChannel } = await call(['sam', 'bob', 'dave']);
    const { sam, bob, dave } = by;
    const firsts = new Map<number, HrpMessage>();
    hrp.addRule('s2c', m => {
      if (m.conn.userId !== bob.userId || !isCallFrom(m, sam, 'call_key')) return undefined;
      const ep = callOf(m)!.body.epoch as number;
      if (firsts.has(ep)) return undefined;
      firsts.set(ep, m);
      return 'drop';
    });
    await joinAll(w!, [sam, bob, dave], 300);
    await allSecure([sam, bob, dave]);
    await sleep(1000);
    const e = newestKey(dave, sam);
    expect(firsts.has(e.epoch)).toBe(true);
    dave.leaveVoice();
    await waitFor('S rotates past e', () => (sam.snapshot?.newestEpoch ?? 0) > e.epoch, 10_000);
    await waitFor('B installs S\'s next epoch', () => bob.receivedKeys.some(k => k.from === sam.userId && k.epoch > e.epoch), 10_000);
    await sleep(2500); // the overlap of REQ-18 has passed
    for (let i = 0; i < 30; i++) {
      hrp.inject(bob.userId, 's2c', await forgedAudio(e.secret, e.epoch, voiceChannel, sam, e.inst, i));
      await sleep(10);
    }
    // A fake leave and rejoin of S, then the withheld first copy of CKM(e).
    hrp.inject(bob.userId, 's2c', { type: 'voice_peer_left', channel_id: voiceChannel, user_id: sam.userId });
    hrp.inject(bob.userId, 's2c', { type: 'voice_peer_joined', channel_id: voiceChannel, user_id: sam.userId });
    const copyAt = Date.now();
    hrp.inject(bob.userId, 's2c', firsts.get(e.epoch)!.json!);
    for (let i = 30; i < 60; i++) {
      hrp.inject(bob.userId, 's2c', await forgedAudio(e.secret, e.epoch, voiceChannel, sam, e.inst, i));
      await sleep(10);
    }
    await sleep(1500);
    expect(bob.played.filter(p => p.tag === FORGED)).toEqual([]);
    // KID e is no longer held, and the re-delivered copy (a skipped key) was refused.
    expect(heldEpochs(bob, sam)).not.toContain(e.epoch);
    const copies = bob.receivedKeys.filter(k => k.from === sam.userId && k.at >= copyAt && Buffer.from(k.secret).equals(Buffer.from(e.secret)));
    expect(copies.length).toBe(1);
    expect(copies[0].skipped).toBe(true);
  });

  it('RG-C216-8 (I+HRP, A1, replay into the receiver\'s next call): S gives B\'s new instance a new epoch; nothing recorded in B\'s previous call plays or decodes', async () => {
    const { by, hrp } = await call(['sam', 'bob']);
    const { sam, bob } = by;
    const audio = recordAudio(w!, sam, bob);
    const video: HrpMessage[] = [];
    hrp.addRule('s2c', m => {
      if (m.conn.userId === bob.userId && typeOf(m) === 'SCREEN_DOWN') video.push(m);
      return undefined;
    });
    await joinAll(w!, [sam, bob]);
    await allSecure([sam, bob]);
    await waitFor('S can share', () => sam.state.screen.control.kind === 'idle', 10_000);
    sam.shareScreen();
    await waitFor('tile', () => bob.state.screen.remote.some(r => r.sharerId === sam.userId), 10_000);
    bob.watch(sam);
    await bob.decodes(sam, { count: 10 });
    await bob.hears(sam, { count: 50 });
    const oldInst = bob.inst!;
    const oldEpochs = sam.encrypted.filter(r => r.type === 'call_key' && r.to === bob.userId).map(r => r.body.epoch as number);
    // S never learns that B left: the relay's voice_peer_left(B) and voice_peer_joined(B) are suppressed.
    hrp.addRule('s2c', m => (m.conn.userId === sam.userId && ['voice_peer_left', 'voice_peer_joined'].includes(typeOf(m)) && m.json?.user_id === bob.userId ? 'drop' : undefined));
    hrp.closeConn(connOf(hrp, bob));
    await waitFor('B rejoins', () => bob.state.phase === 'joined' && bob.inst !== oldInst, 20_000);
    await waitFor('B keyed by S again', () => bob.receivedKeys.some(k => k.from === sam.userId && k.inst === sam.inst && k.at > Date.now() - 20_000 && bob.participant(sam)?.inbound === 'keyed'), 15_000);
    await waitFor('tile again', () => bob.state.screen.remote.some(r => r.sharerId === sam.userId), 10_000);
    bob.watch(sam);
    const seen = bob.decodedFrom(sam).length;
    await bob.decodes(sam, { count: 2, since: seen });
    // S sent B's new instance only epochs newer than every epoch of B's previous call.
    const newEpochs = sam.encrypted.filter(r => r.type === 'call_key' && r.to === bob.userId && r.body.to_inst === bob.inst).map(r => r.body.epoch as number);
    expect(newEpochs.length).toBeGreaterThan(0);
    expect(Math.min(...newEpochs)).toBeGreaterThan(Math.max(...oldEpochs));
    const playedBefore = bob.playedFrom(sam).length;
    for (const m of audio.filter(a => a.at < Date.now() - 2000).slice(-150)) hrp.inject(bob.userId, 's2c', m.json!);
    for (const m of video.slice(0, 200)) hrp.inject(bob.userId, 's2c', m.data);
    await sleep(2000);
    expect(duplicatesPlayed(bob, sam)).toEqual([]);
    const seqs = bob.decodedFrom(sam).map(m => m.seq);
    expect(seqs.length - new Set(seqs).size).toBe(0);
    expect(bob.playedFrom(sam).length).toBeGreaterThan(playedBefore);
  });
});
