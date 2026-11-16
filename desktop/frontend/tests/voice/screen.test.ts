/**
 * SPEC-03 amendment A1 over the real relay: the integration (I) and
 * hostile-relay (I+HRP) tests of screen sharing and the A1 regression
 * replays of §10.3, with headless clients that share from the synthetic VP8
 * source and watch into the recording decoder (§10.1).
 *
 * Covered here: RG-C117-1 (I), RG-C003-1 (I+HRP) with T-39 (I), RG-C027-1,
 * T-47 (I+HRP, throttled upstream; relay at --screen-max-rate 200000), T-51
 * (I+HRP), RG-SCR-1 to RG-SCR-6 and RG-SCR-8 to RG-SCR-10. RG-SCR-7 and the
 * relay sides of RG-SCR-5, -8 and -9 are relay tests
 * (`server/tests/spec03_screen_test.rs`), RG-C003-2 is
 * `server/tests/spec03_p2p_retirement_test.rs`.
 *
 * T-47, T-51 and RG-SCR-8 need the 64 KiB receive buffers of §10.1, which
 * the CI job provides by capping the kernel's TCP receive buffers
 * (`CAPPED`). It leaves send buffers large (a 4 MiB maximum), so the
 * relay's kernel send buffer to a slow reader would hold megabytes but for
 * its TCP_NOTSENT_LOWAT: the capped forms of T-51 and RG-SCR-8 bound the
 * relay's unsent data by RELAY_NOTSENT_LOWAT and fail without the option.
 * T-47 and T-51 follow amendment A2 (§14.2): over TCP, data already handed
 * to the operating system cannot be recalled, so they assert what Accord
 * controls (the client's pacing and bitrate steps; the relay's 2 s queue
 * age, its TCP_NOTSENT_LOWAT and the link's buffers at the link's rate),
 * and print the end-to-end delays they measure; the 500 ms audio and 3 s
 * video targets are measured over real links on the T-57 release checklist
 * (docs/release-checklist.md).
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { RelayProcess } from '../../src/__integration__/relay';
import { encodeSFrameHeader } from '../../src/voice/mediaFrame';
import { encodeScreenDown, encodeScreenUp, FRAG_HDR, SCREEN_DOWN_MAX } from '../../src/voice/screenFrame';
import { syntheticVp8, readMarker } from '../../src/voice/screenShare.testkit';
import { RELAY_AVAILABLE, RELAY_NOTSENT_LOWAT, SMALL_SOCKET_BUFFER, allSecure, buildWorld, disposeWorld, joinAll, kernelReceiveBuffersCapped, startRelay, type VoiceWorld } from './world';
import { HC, sleep, waitFor } from './hc';
import { PROXY_READ_SIZE, clientBody, screenUp, typeOf, type HrpMessage } from './hrp';
import { clientMessagesFrom, connOf, copyMediaTo, eventTimes, relayMessagesTo } from './common';
import { MEDIA_KIND_AUDIO, MEDIA_KIND_VIDEO, frameHeader, instBytes, openWithAny, openWithBaseKey, sealWith, wireFrame, type WireFrame } from './wire';
import { peerConnectionConstructions } from './spies';

const suite = RELAY_AVAILABLE ? describe : describe.skip;

/** The §10.1 64 KiB receive buffers are in place (the CI voice job caps the kernel's TCP receive buffers and leaves send buffers large). */
const CAPPED = kernelReceiveBuffersCapped();

const OUTSIDER_SDP = 'v=0\r\no=- 1 2 IN IP4 203.0.113.7\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 203.0.113.7\r\n';
const CANDIDATE = 'candidate:1 1 udp 2122260223 203.0.113.7 54400 typ host';

/** Count of items in any window of `ms` milliseconds (the max). */
function maxPerWindow(times: readonly number[], ms: number): number {
  const t = [...times].sort((a, b) => a - b);
  let best = 0;
  let j = 0;
  for (let i = 0; i < t.length; i++) {
    while (t[i] - t[j] >= ms) j++;
    best = Math.max(best, i - j + 1);
  }
  return best;
}

/**
 * Every chunk `hc` decoded is a synthetic VP8 frame of one of `tags` (the
 * genuine sharers' encoders) and equals, byte for byte, the frame its marker
 * names: nothing spliced or forged was decoded.
 */
function decodedAreGenuine(hc: HC, tags: readonly number[]): boolean {
  for (const d of hc.screen.decoders) {
    for (const chunk of d.chunks) {
      const m = readMarker(chunk.data);
      if (!m || !tags.includes(m.tag)) return false;
      const w = d.config?.codedWidth ?? 0;
      const h = d.config?.codedHeight ?? 0;
      const expected = syntheticVp8(chunk.type === 'key', w, h, { tag: m.tag, seq: m.seq, picture: m.picture }, chunk.data.length);
      if (!Buffer.from(expected).equals(Buffer.from(chunk.data))) return false;
    }
  }
  return true;
}

/**
 * When `sharer`'s current share skips a source frame for backpressure
 * (REQ-47): every increment of its sender's `stats.skips`, timed as it
 * happens. Install once the share has started (its sender exists).
 */
function recordSkips(sharer: HC): number[] {
  const sender = sharer.conn?.screenParts?.sender;
  if (!sender) throw new Error(`${sharer.name} has no screen sender`);
  const at: number[] = [];
  const stats = sender.stats;
  let skips = stats.skips;
  Object.defineProperty(stats, 'skips', {
    configurable: true,
    enumerable: true,
    get: () => skips,
    set: (v: number) => {
      if (v > skips) at.push(Date.now());
      skips = v;
    },
  });
  return at;
}

async function startShare(sharer: HC, viewers: HC[], opts: { fps?: number; width?: number; height?: number } = {}): Promise<void> {
  await waitFor(`${sharer.name} can share`, () => sharer.state.screen.control.kind === 'idle', 10_000);
  expect(sharer.shareScreen(opts)).toBe(true);
  for (const v of viewers) {
    await waitFor(`${v.name} sees the tile`, () => v.state.screen.remote.some(r => r.sharerId === sharer.userId && r.canWatch), 10_000);
    expect(v.watch(sharer)).toBe(true);
  }
  for (const v of viewers) await v.decodes(sharer, { count: 2 });
}

suite('SPEC-03 A1 screen sharing over the real relay (I, I+HRP, regressions)', () => {
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

  async function call(names: string[], opts: Parameters<typeof buildWorld>[2] = {}, r: RelayProcess = relay): Promise<VoiceWorld> {
    w = await buildWorld(r, names, opts);
    for (const hc of w.hcs) hc.startAudio();
    return w;
  }

  it('RG-C117-1 (I): on a screen-capable relay A shares, B watches and decodes A\'s markers; "Sharing" only after screen_share_started', async () => {
    const { by, hrp } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await startShare(alice, [bob]);
    const started = relayMessagesTo(hrp, alice, 'screen_share_started').find(m => m.json?.user_id === alice.userId)!;
    expect(started).toBeDefined();
    const firstSharing = alice.states.find(s => s.state.screen.local?.state === 'sharing')!;
    expect(firstSharing.at).toBeGreaterThanOrEqual(started.at);
    const markers = await bob.decodes(alice, { count: 10 });
    expect(markers.every(m => m.tag === alice.options.tag)).toBe(true);
    expect(bob.drawnFrom(alice).length).toBeGreaterThan(0);
    expect(decodedAreGenuine(bob, [alice.options.tag])).toBe(true);
  });

  it('RG-C117-1 (I): when HRP strips screen/1, Share Screen is disabled with the §8.4 reason; no capture, no start, no P2P', async () => {
    w = await buildWorld(relay, ['alice', 'bob']);
    w.hrp.stripScreenFeature = true;
    for (const hc of w.hcs) hc.startAudio();
    // Reconnect both so their sockets get the stripped hello.
    for (const hc of w.hcs) w.hrp.closeConn(connOf(w.hrp, hc));
    await waitFor('reconnected', () => w!.hcs.every(hc => hc.ws.isSocketConnected() && hc.ws.helloProcessed()), 15_000);
    const { alice, bob } = w.by;
    await joinAll(w, [alice, bob]);
    await allSecure([alice, bob]);
    await waitFor('control row 4', () => alice.state.screen.control.kind === 'relay_unsupported', 10_000);
    expect(alice.shareScreen()).toBe(false);
    await sleep(1000);
    expect(alice.screen.displayMediaCalls).toEqual([]);
    expect(clientMessagesFrom(w.hrp, alice, 'ScreenShareStart')).toEqual([]);
    expect(clientMessagesFrom(w.hrp, alice, 'P2PSignal')).toEqual([]);
    expect(alice.states.some(s => s.state.screen.control.kind === 'sharing')).toBe(false);
    expect(peerConnectionConstructions()).toBe(0);
    await bob.hears(alice); // voice is unaffected
  });

  it('RG-C003-1 (I+HRP) and T-39 (I): p2p mode, SDP offers, ICE candidates and the WebRTC signaling messages from an outsider and from HRP change nothing; no peer connection, no SDP, same instances, media continues, the muted client stays muted', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob', 'carol', 'mallory'], { outsiders: ['mallory'], client: name => (name === 'carol' ? { muted: true } : {}) });
    const { alice, bob, carol, mallory } = by;
    await joinAll(w!, [alice, bob, carol]);
    await waitFor('A and B secure', () => alice.participant(bob)?.label === 'secure' && bob.participant(alice)?.label === 'secure', 15_000);
    await startShare(alice, [bob]);
    const insts = [alice.inst, bob.inst, carol.inst];
    const ts = () => Math.floor(Date.now() / 1000);
    const asMallory = (variant: string, body: Record<string, unknown>) => hrp.inject(mallory.userId, 'c2s', { message_type: { [variant]: body }, message_id: crypto.randomUUID(), timestamp: ts() });
    const participant = [alice, bob, carol];
    // The outsider, through the real relay (which retires these at R-A1).
    asMallory('SetVoiceMode', { channel_id: voiceChannel, mode: 'p2p' });
    for (const target of participant) {
      for (const signal of [{ type: 'sdp', sdp: OUTSIDER_SDP }, { type: 'screen-sdp', sdp: OUTSIDER_SDP }, { type: 'ice', candidate: CANDIDATE }]) {
        asMallory('P2PSignal', { channel_id: voiceChannel, target_user_id: target.userId, signal_data: JSON.stringify(signal) });
      }
      asMallory('VoiceOffer', { channel_id: voiceChannel, target_user_id: target.userId, sdp: OUTSIDER_SDP });
      asMallory('VoiceIceCandidate', { channel_id: voiceChannel, target_user_id: target.userId, candidate: CANDIDATE, sdp_mid: '0', sdp_mline_index: 0 });
    }
    // HRP, as a malicious relay, injects them directly, under participants' ids and an outsider's.
    for (const to of participant) {
      for (const from of [...participant.filter(p => p !== to), mallory]) {
        hrp.inject(to.userId, 's2c', { type: 'voice_mode_changed', channel_id: voiceChannel, voice_mode: 'p2p', user_id: from.userId });
        hrp.inject(to.userId, 's2c', { type: 'p2p_signal', channel_id: voiceChannel, from: from.userId, signal_data: JSON.stringify({ type: 'screen-sdp', sdp: OUTSIDER_SDP }) });
        hrp.inject(to.userId, 's2c', { type: 'p2p_signal', channel_id: voiceChannel, from: from.userId, signal_data: JSON.stringify({ type: 'sdp', sdp: OUTSIDER_SDP }) });
        hrp.inject(to.userId, 's2c', { type: 'p2p_signal', channel_id: voiceChannel, from: from.userId, signal_data: JSON.stringify({ type: 'ice', candidate: CANDIDATE }) });
        hrp.inject(to.userId, 's2c', { type: 'voice_offer', channel_id: voiceChannel, from: from.userId, sdp: OUTSIDER_SDP });
        hrp.inject(to.userId, 's2c', { type: 'voice_answer', channel_id: voiceChannel, from: from.userId, sdp: OUTSIDER_SDP });
        hrp.inject(to.userId, 's2c', { type: 'voice_ice_candidate', channel_id: voiceChannel, from: from.userId, candidate: CANDIDATE });
      }
    }
    const t = Date.now();
    await sleep(2000);
    expect(peerConnectionConstructions()).toBe(0);
    for (const hc of participant) {
      for (const type of ['P2PSignal', 'VoiceOffer', 'VoiceAnswer', 'VoiceIceCandidate', 'SetVoiceMode']) expect(clientMessagesFrom(hrp, hc, type)).toEqual([]);
      // No client message carries SDP or an ICE candidate.
      expect(hrp.messages({ dir: 'c2s', user: hc.userId, opcode: 1 }).filter(m => /a=fingerprint|candidate:|v=0\r\n/.test(m.data.toString('utf8')))).toEqual([]);
      // No listener for the WebRTC signaling events (T-39 F/I).
      const listeners = (hc.ws as unknown as { listeners: Map<string, Set<unknown>> }).listeners;
      for (const ev of ['p2p_signal', 'voice_offer', 'voice_answer', 'voice_ice_candidate']) expect(listeners.get(ev)?.size ?? 0).toBe(0);
    }
    expect([alice.inst, bob.inst, carol.inst]).toEqual(insts);
    await bob.hears(alice, { since: t });
    await alice.hears(bob, { since: t });
    const seen = bob.decodedFrom(alice).length;
    await bob.decodes(alice, { count: 3, since: seen });
    // The muted client stayed muted: it sent no frame at all.
    expect(clientMessagesFrom(hrp, carol, 'SrtpVoicePacket')).toEqual([]);
    // The relay answered the outsider's mode change with p2p_retired (REQ-56).
    expect(relayMessagesTo(hrp, mallory, 'error').some(m => m.json?.reason === 'p2p_retired')).toBe(true);
  });

  it('RG-C027-1 (I+HRP): HRP rewrites fingerprints and injects its own offers; no client sends or accepts SDP, screen video flows only as AMF1, and no recorded key-sized value decrypts a fragment', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    let rewritten = 0;
    hrp.addRule('c2s', m => {
      const text = m.opcode === 1 ? m.data.toString('utf8') : '';
      if (!/a=fingerprint/.test(text)) return undefined;
      rewritten++;
      return { send: [text.replace(/a=fingerprint:[^\\]*/g, 'a=fingerprint:sha-256 00:11')] };
    });
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await startShare(alice, [bob]);
    for (const [to, from] of [[bob, alice], [alice, bob]] as const) {
      hrp.inject(to.userId, 's2c', { type: 'p2p_signal', channel_id: voiceChannel, from: from.userId, signal_data: JSON.stringify({ type: 'screen-sdp', sdp: OUTSIDER_SDP }) });
      hrp.inject(to.userId, 's2c', { type: 'voice_offer', channel_id: voiceChannel, from: from.userId, sdp: OUTSIDER_SDP });
    }
    await bob.decodes(alice, { count: 20 });
    expect(rewritten).toBe(0);
    expect(peerConnectionConstructions()).toBe(0);
    // Every binary message is a well-formed SCREEN_UP or SCREEN_DOWN carrying an AMF1 fragment of kind 0x02.
    const binary = hrp.messages({ opcode: 2 });
    expect(binary.length).toBeGreaterThan(20);
    for (const m of binary) {
      const f = wireFrame(m);
      expect(f?.kind).toBe(MEDIA_KIND_VIDEO);
      expect(frameHeader(f!.bytes)).toMatchObject({ format: 1, kind: 2 });
    }
    // The C005 reproduction with every decoded value of key size from every recorded text message.
    const candidates = new Map<string, Uint8Array>();
    for (const m of hrp.messages({ opcode: 1 })) {
      for (const run of m.data.toString('latin1').matchAll(/[A-Za-z0-9+/]{20,}={0,2}/g)) {
        const bytes = Buffer.from(run[0], 'base64');
        for (const len of [16, 32]) if (bytes.length === len) candidates.set(bytes.toString('hex'), Uint8Array.from(bytes));
        // and every key-sized window of what decodes to more
        if (bytes.length > 32) for (let i = 0; i + 32 <= bytes.length && candidates.size < 4000; i += 8) candidates.set(bytes.subarray(i, i + 32).toString('hex'), Uint8Array.from(bytes.subarray(i, i + 32)));
      }
    }
    const fragments = binary.map(wireFrame).filter((f): f is WireFrame => !!f).filter((_, i) => i % 25 === 0).slice(0, 4);
    const insts = [...new Set(bob.receivedKeys.map(k => k.inst))].map(instBytes);
    let successes = 0;
    for (const key of candidates.values()) {
      for (const f of fragments) if (await openWithBaseKey({ ...f, from: alice.userId }, key, insts)) successes++;
    }
    expect(candidates.size).toBeGreaterThan(50);
    expect(successes).toBe(0);
    // Positive control: B's real key opens them.
    expect(await openWithAny({ ...fragments[0], from: alice.userId }, bob.receivedKeys)).not.toBeNull();
  });

  /**
   * T-47 (I+HRP) as replaced by A2 (§14.2). HRP throttles A's upstream to
   * 2 Mbit/s while A shares a source of large changes (frames far larger than
   * the link carries). §10.1 asks for 64 KiB receive buffers on HRP's
   * sockets so that A's queue fills within the test; Node cannot set
   * SO_RCVBUF, so the CI voice job caps the kernel's TCP receive buffers
   * (`CAPPED`). A's own kernel send buffer is not capped (it is not HRP's,
   * and real senders have large ones), so it fills first, which takes a few
   * seconds, and A's skips come in bursts as it drains. Expected: every
   * fragment is handed off only while `bufferedAmount` ≤ 65,536; every audio
   * frame reaches the relay, in order; the bitrate steps down as REQ-47 says
   * (half, then half again after each further 10 s of skips, down to a
   * 200,000 bit/s target) and back up (doubled after each 10 s without a
   * skip) once the throttle ends. A2 dropped the 500 ms end-to-end audio
   * bound from CI (it depends on link speed and kernel buffers, §14.2); the
   * delay is measured and printed for the T-57 release checklist instead.
   */
  it('T-47 (I+HRP, A2): with the sharer\'s upstream throttled to 2 Mbit/s, fragments are handed off only while bufferedAmount ≤ 65,536, frames are skipped rather than queued, every audio frame reaches the relay in order, and the bitrate steps down as REQ-47 says and back up after the throttle ends', async () => {
    const { by, hrp } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    const aConn = connOf(hrp, alice);
    // 2 Mbit/s; under the cap the proxy keeps about one fragment of its own queue on that link.
    hrp.throttle(aConn, 'c2s', 250_000, CAPPED ? 16_500 : undefined);
    const b0 = Date.now();
    await sleep(5000);
    const b1 = Date.now();
    alice.screen.outputSize = o => (o.key ? 120_000 : 60_000); // about 900 KB/s at 15 frames per second
    await startShare(alice, [bob]);
    const s0 = Date.now();
    const skipsAt = recordSkips(alice);
    const enc = alice.screen.enc;
    const fullTarget = enc.configs[0].bitrate;
    expect(fullTarget).toBe(1_500_000);
    // Throttled: long enough for the first halving and two more 10 s windows of skips.
    await waitFor('A halves its bitrate', () => (enc.configs.some(c => c.bitrate < fullTarget) ? true : undefined), 20_000);
    await sleep(21_000);
    const s1 = Date.now();
    const sent = alice.sentFrames.filter(f => f.at >= s0 && f.at < s1);
    expect(sent.length).toBeGreaterThan(600);
    // REQ-47: each fragment is handed off only while bufferedAmount is at most SEND_BUFFER_HIGH, so at
    // most that plus one SCREEN_UP of video (16,401 bytes) is ever queued in the client ahead of an audio frame.
    const frags = alice.sentFragments.filter(f => f.at >= s0);
    expect(frags.length).toBeGreaterThan(50);
    expect(Math.max(...frags.map(f => f.bufferedAhead ?? 0))).toBeLessThanOrEqual(65_536);
    // The client's queue really filled, so the pacing was exercised.
    expect(Math.max(...sent.map(f => f.bufferedAhead ?? 0))).toBeGreaterThan(65_536 - 16_401);
    // Once the buffer is full, source frames are closed unencoded rather than queued.
    const pushed = [...alice.pushedAt.values()].filter(t => t >= s0 && t < s1).length;
    const encoded = enc.inputs.filter(i => i.at >= s0 && i.at < s1).length;
    expect(encoded).toBeLessThan(pushed * 0.6);
    // The throttle ends: the bitrate doubles back after each 10 s without a skip.
    hrp.throttle(aConn, 'c2s', null);
    const r0 = Date.now();
    await waitFor('A is back at its full bitrate', () => (enc.configs[enc.configs.length - 1].bitrate === fullTarget ? true : undefined), 50_000);
    const r1 = Date.now();
    alice.stopSharing();
    await sleep(2000);
    // REQ-47 (A2): the steps, with when the encoder was reconfigured: the steps down, then the steps up.
    const steps = enc.configs.map((c, i) => ({ bitrate: c.bitrate, at: enc.configuredAt[i] }));
    const firstUp = steps.findIndex((x, i) => i > 0 && x.bitrate > steps[i - 1].bitrate);
    const down = firstUp < 0 ? steps : steps.slice(0, firstUp);
    const up = firstUp < 0 ? [] : steps.slice(firstUp);
    const downRates = down.map(x => x.bitrate);
    // At least the first halving and one more after a further 10 s of skips; each step halves, down to
    // 200,000, while the throttle lasts (or as A's queue drains just after it).
    expect(downRates.length).toBeGreaterThanOrEqual(3);
    expect(down[down.length - 1].at).toBeLessThanOrEqual(r0 + 1000);
    for (let i = 1; i < down.length; i++) {
      expect(down[i].bitrate).toBe(Math.max(200_000, Math.floor(down[i - 1].bitrate / 2)));
      expect(down[i].at - down[i - 1].at).toBeGreaterThanOrEqual(i === 1 ? 0 : 10_000 - 100);
    }
    // Back up, only after the throttle ended: each step doubles (up to the target) after 10 s without a
    // skip, to §6.13.4's target. The first is timed from A's last backpressure skip, not from the end of
    // the throttle: A's kernel send buffer (capped in neither form) and the proxy's buffers absorb
    // bursts, so A can stop skipping a second or so before the throttle ends. That last skip came from
    // the throttle (it is no later than 1 s after the throttle ended).
    expect(up.length).toBeGreaterThanOrEqual(1);
    expect(up[0].at).toBeGreaterThanOrEqual(r0);
    const lastSkipAt = Math.max(...skipsAt.filter(t => t < up[0].at));
    expect(lastSkipAt).toBeGreaterThan(s0);
    expect(lastSkipAt).toBeLessThanOrEqual(r0 + 1000);
    expect(up[0].at - lastSkipAt).toBeGreaterThanOrEqual(10_000 - 50);
    expect(up[0].at - lastSkipAt).toBeLessThanOrEqual(10_000 + 2000);
    for (let i = 0; i < up.length; i++) {
      const prev = i === 0 ? down[down.length - 1] : up[i - 1];
      expect(up[i].bitrate).toBe(Math.min(fullTarget, prev.bitrate * 2));
      if (i > 0) expect(up[i].at - up[i - 1].at).toBeGreaterThanOrEqual(10_000 - 100);
    }
    expect(up[up.length - 1].bitrate).toBe(fullTarget);
    expect(steps.every(x => x.bitrate <= 2_500_000)).toBe(true);
    // Every audio frame A handed off reached the relay, in order.
    const seen = hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SrtpVoicePacket' });
    const byBytes = new Map(seen.map((m, i) => [String(clientBody(m)!.packet_data), { i, m }]));
    const delays = (t0: number, t1: number) => alice.sentFrames.filter(f => f.at >= t0 && f.at < t1).map(f => {
      const hit = byBytes.get(Buffer.from(f.bytes).toString('base64'));
      return { i: hit?.i, delay: hit?.m.forwardedAt === undefined ? Infinity : hit.m.forwardedAt - f.at };
    });
    const base = delays(b0, b1);
    const shared = delays(s0, r1);
    expect(base.length).toBeGreaterThan(150);
    expect(shared.every(d => d.i !== undefined && Number.isFinite(d.delay))).toBe(true);
    expect(shared.every((d, k) => k === 0 || d.i! > shared[k - 1].i!)).toBe(true);
    const throttled = delays(s0, s1).map(d => d.delay).sort((a, b) => a - b);
    console.info(`T-47: ${CAPPED ? 'kernel TCP receive buffers capped at 64 KiB' : 'kernel TCP buffers NOT capped'}; bitrate steps ${steps.map(x => x.bitrate).join(' → ')} (A's last skip ${lastSkipAt - r0} ms after the throttle ended, the first step up ${up[0].at - lastSkipAt} ms after it; back to the target ${r1 - r0} ms after the throttle ended); audio from hand-off to the relay (measured, not asserted since A2): at most ${Math.max(...base.map(d => d.delay))} ms without sharing, ${throttled[throttled.length - 1]} ms while sharing on the throttled link (median ${throttled[Math.floor(throttled.length / 2)]} ms)`);
  });

  it('T-47 (I+HRP): against a relay started with --screen-max-rate 200000 the sharer never configures more than 1,280,000 bit/s, every SCREEN_UP of 60 s of sharing reaches the viewer, and the viewer decodes throughout', async () => {
    const slow = await startRelay(['--screen-max-rate', '200000']);
    try {
      // A rotates every 20 s, so the 60 s include rotations as well as periodic keyframes.
      const { by, hrp } = await call(['alice', 'bob'], { client: name => (name === 'alice' ? { callTimings: { rotationIntervalMs: 20_000 } } : {}) }, slow);
      const { alice, bob } = by;
      await joinAll(w!, [alice, bob]);
      await allSecure([alice, bob]);
      alice.outputsFollowBitrate(4);
      await startShare(alice, [bob]);
      expect(alice.ws.screenLimits()?.maxBytesPerSecond).toBe(200_000);
      // §10.2: 60 s of sharing, in 12 windows of 5 s; the viewer decodes in every one.
      const t0 = Date.now();
      const windows: number[] = [];
      for (let i = 0; i < 12; i++) {
        const before = bob.decodedFrom(alice).length;
        await sleep(5000);
        windows.push(bob.decodedFrom(alice).length - before);
      }
      const t1 = Date.now();
      expect(t1 - t0).toBeGreaterThanOrEqual(60_000);
      expect(windows.every(n => n >= 20)).toBe(true);
      const configs = alice.screen.encoders.flatMap(e => e.configs);
      expect(Math.max(...configs.map(c => c.bitrate))).toBeLessThanOrEqual(1_280_000);
      expect(configs[0].bitrate).toBe(960_000);
      // Every SCREEN_UP of the 60 s reaches the viewer: the byte bucket dropped nothing.
      alice.stopSharing();
      await sleep(2000);
      const ups = hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SCREEN_UP' }).filter(m => m.at >= t0 && m.at < t1);
      const downs = relayMessagesTo(hrp, bob, 'SCREEN_DOWN');
      const downSet = new Set(downs.map(m => Buffer.from(m.data.subarray(33)).toString('base64')));
      const lost = ups.filter(m => !downSet.has(Buffer.from(screenUp(m)!.fragment).toString('base64')));
      expect(ups.length).toBeGreaterThan(800);
      expect(lost.length).toBe(0);
      // Periodic keyframes and rotations happened within the 60 s at the minimum bucket, and the viewer kept up.
      expect(alice.screen.encoders.flatMap(e => e.outputs).filter(o => o.key && o.at >= t0 && o.at < t1).length).toBeGreaterThanOrEqual(5);
      expect(new Set(bob.receivedKeys.filter(k => k.from === alice.userId && k.at >= t0 && k.at < t1).map(k => k.epoch)).size).toBeGreaterThanOrEqual(2);
    } finally {
      await disposeWorld(w);
      w = undefined;
      await slow.dispose();
    }
  });

  /**
   * T-51 (I+HRP) as replaced by A2 (§14.2). A shares to B and C; B's
   * downstream is slower than the share. Expected: every fragment B receives
   * left the relay's screen queue at most 2 s after the relay received it;
   * every frame B draws was sent by A at most 2 s plus (RELAY_NOTSENT_LOWAT +
   * B's receive buffer) ÷ B's throttled rate earlier, or B shows "No video";
   * C receives at most one keyframe per 5 s beyond A's periodic keyframes.
   *
   * Under the §10.1 cap (`CAPPED`) HRP throttles B's downstream to half the
   * share's rate, as §10.2 says. HRP is B's link, so "B's receive buffer" is
   * everything between the relay's socket and the throttled output: the
   * kernel receive buffer (64 KiB under the cap), one proxy read
   * (`PROXY_READ_SIZE`) and the proxy's queue on the link, which holds its
   * 16,500-byte mark plus the message that crosses it. The relay's unsent
   * data stays near RELAY_NOTSENT_LOWAT (§14.2): up to the mark, plus the
   * write that crosses it, plus the message the relay's outgoing task holds
   * while the socket does not take it, so at most the mark plus two
   * SCREEN_DOWN messages (`RELAY_UNSENT_MAX`), which stands for
   * RELAY_NOTSENT_LOWAT in the bound (measured with `ss`: at most 48,670
   * bytes unsent). The cap leaves send buffers large, so without
   * TCP_NOTSENT_LOWAT the relay's kernel would hold megabytes for B (fragments
   * reached HRP up to 11.5 s after A sent them, measured) and the bound
   * fails. Without the cap the kernel's receive buffer is not known (Linux
   * tunes it up to megabytes), so the fallback keeps B's link at loopback
   * speed and makes it lossy instead: HRP drops every fragment to B for
   * 700 ms of every 3 s; the rate term is then zero.
   *
   * What HRP can see bounds the relay's queue from outside: HRP reads from
   * the relay only as its queue on the link drains, so a fragment that left
   * the relay's queue at q is read by HRP at most (RELAY_UNSENT_MAX + B's
   * receive buffer) ÷ rate after q, and HRP saw A's SCREEN_UP within
   * milliseconds of the relay receiving it. `SLACK_MS` covers what the
   * formula leaves out: the relay's and the proxy's processing, the proxy's
   * 50 ms throttle timer, and B's decryption, reassembly, decoding and next
   * animation frame.
   */
  it('T-51 (I+HRP, A2): with B\'s downstream slower than the share, every fragment B receives left the relay\'s queue within 2 s, every frame B draws is at most 2 s plus the link\'s buffers at its rate old (or B shows "No video"), B requests keyframes, and C gets at most one extra keyframe per 5 s and keeps decoding', async () => {
    const SLACK_MS = 300;
    const { by, hrp } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    alice.outputsFollowBitrate(4);
    await startShare(alice, [bob, carol]);
    // When A handed off each frame's last fragment, by the frame's picture (its marker).
    const mgr = alice.conn!.callKeys!;
    const sealVideoFrame = mgr.sealVideoFrame.bind(mgr);
    const lastVctrOf = new Map<number, number>();
    mgr.sealVideoFrame = (ticket, frame) => {
      const m = readMarker(frame.data);
      if (m) lastVctrOf.set(m.picture, ticket.firstVctr + ticket.count - 1);
      return sealVideoFrame(ticket, frame);
    };
    const up = new Map<number, number>(); // VCTR → when HRP saw A's SCREEN_UP
    hrp.addRule('c2s', m => {
      if (typeOf(m) === 'SCREEN_UP' && m.conn.userId === alice.userId) up.set(frameHeader(screenUp(m)!.fragment)!.ctr, m.at);
      return undefined;
    });
    // The share's rate, from what A sent over 3 s.
    const r0 = Date.now();
    await sleep(3000);
    const shareRate = hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SCREEN_UP' }).filter(m => m.at >= r0).reduce((n, m) => n + m.data.length, 0) / ((Date.now() - r0) / 1000);
    expect(shareRate).toBeGreaterThan(50_000);
    const mark = hrp.mark();
    const t0 = Date.now();
    const rate = CAPPED ? Math.floor(shareRate / 2) : Infinity;
    const LINK_QUEUE = 16_500;
    if (CAPPED) {
      hrp.throttle(connOf(hrp, bob), 's2c', rate, LINK_QUEUE);
    } else {
      hrp.addRule('s2c', m => (m.conn.userId === bob.userId && typeOf(m) === 'SCREEN_DOWN' && (Date.now() - t0) % 3000 < 700 ? 'drop' : undefined));
    }
    const noVideo: number[] = [];
    const sampler = setInterval(() => {
      const tile = bob.state.screen.remote.find(r => r.sharerId === alice.userId)?.tile;
      if (tile?.kind === 'no_video') noVideo.push(Date.now());
    }, 200);
    await sleep(20_000);
    clearInterval(sampler);
    const T = (Date.now() - t0) / 1000;
    const msAt = (bytes: number) => (Number.isFinite(rate) ? (bytes / rate) * 1000 : 0);
    const RELAY_UNSENT_MAX = RELAY_NOTSENT_LOWAT + 2 * SCREEN_DOWN_MAX;
    const receiveBuffer = SMALL_SOCKET_BUFFER + PROXY_READ_SIZE + LINK_QUEUE + SCREEN_DOWN_MAX;
    // (1) Every fragment B receives left the relay's screen queue at most 2 s after the relay received it.
    const queueBoundMs = 2000 + msAt(RELAY_UNSENT_MAX + receiveBuffer) + SLACK_MS;
    const downs = relayMessagesTo(hrp, bob, 'SCREEN_DOWN', mark).map(m => ({ at: m.at, sentUp: up.get(frameHeader(m.data.subarray(33))!.ctr) }));
    expect(downs.length).toBeGreaterThan(50);
    expect(downs.every(d => d.sentUp !== undefined)).toBe(true);
    const transits = downs.map(d => d.at - d.sentUp!).sort((a, b) => a - b);
    const transitMax = transits[transits.length - 1];
    // (2) Every frame B draws was sent by A at most 2 s + (RELAY_NOTSENT_LOWAT + B's receive buffer) ÷ rate earlier, or B shows "No video".
    const drawBoundMs = 2000 + msAt(RELAY_UNSENT_MAX + receiveBuffer) + SLACK_MS;
    const sentAtByVctr = new Map<number, number>();
    for (const f of alice.sentFragments) {
      const h = frameHeader(f.bytes);
      if (h) sentAtByVctr.set(h.ctr, f.at);
    }
    const handedOffAt = (picture: number): number | undefined => {
      const vctr = lastVctrOf.get(picture);
      return vctr === undefined ? undefined : sentAtByVctr.get(vctr);
    };
    const ages = bob.draws.filter(d => d.at >= t0 && d.marker && d.sharer === alice.userId).map(d => {
      const sentAt = handedOffAt(d.marker!.picture);
      return { at: d.at, age: sentAt === undefined ? Infinity : d.at - sentAt };
    });
    const late = ages.filter(d => d.age > drawBoundMs && !noVideo.some(t => Math.abs(t - d.at) < 1000));
    const carolKeys = carol.screen.decodedAt.filter(x => x.key && x.at >= t0).length;
    console.info(`T-51: ${CAPPED ? `B's downstream throttled to ${rate} B/s (half of ${Math.floor(shareRate)} B/s), kernel TCP receive buffers capped` : 'kernel TCP buffers NOT capped: B\'s link at loopback speed, every fragment to B dropped 700 ms of every 3 s (fallback form)'}; relay to B (at the proxy) at most ${transitMax} ms after A's SCREEN_UP, median ${transits[Math.floor(transits.length / 2)]} ms (bound ${Math.round(queueBoundMs)} ms); B drew ${ages.length} frames, the oldest ${Math.max(0, ...ages.map(a => a.age))} ms after A sent it (bound ${Math.round(drawBoundMs)} ms), ${late.length} later outside "No video"; C decoded ${carolKeys} keyframes in ${T.toFixed(1)} s`);
    expect(transitMax).toBeLessThanOrEqual(queueBoundMs);
    expect(ages.length).toBeGreaterThan(5);
    expect(late).toEqual([]);
    // (3) B asked for keyframes; A acted on at most one per 5 s, so C saw at most that many extra.
    expect(clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest').filter(m => m.at >= t0).length).toBeGreaterThan(0);
    expect(carolKeys).toBeLessThanOrEqual(Math.ceil(T / 10) + Math.ceil(T / 5) + 1);
    expect(carol.decodedFrom(alice).length).toBeGreaterThan(100);
  });

  it('RG-SCR-1 (I+HRP): 200 random fragments per second under A\'s id, current KID and a VCTR far ahead decode nothing, do not move the window, and do not show "can\'t be verified"', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await startShare(alice, [bob]);
    const kid = frameHeader(wireFrame(hrp.messages({ dir: 'c2s', user: alice.userId, type: 'SCREEN_UP' }).slice(-1)[0]!)!.bytes)!.kid;
    const rows: number[] = [];
    const sampler = setInterval(() => {
      const tile = bob.state.screen.remote.find(r => r.sharerId === alice.userId)?.tile;
      if (tile) rows.push(tile.row);
    }, 50);
    const t0 = Date.now();
    const before = bob.decodedFrom(alice).length;
    for (let i = 0; i < 1000; i++) {
      const ct = crypto.getRandomValues(new Uint8Array(400 + (i % 600)));
      const frag = new Uint8Array([0x01, 0x02, ...encodeSFrameHeader(kid, 2 ** 40 + i), ...ct]);
      hrp.inject(bob.userId, 's2c', encodeScreenDown(voiceChannel, alice.userId, frag));
      if (i % 10 === 9) await sleep(50);
    }
    clearInterval(sampler);
    const during = bob.decodedFrom(alice).length - before;
    const after0 = bob.decodedFrom(alice).length;
    await bob.decodes(alice, { count: 5, since: after0 });
    expect(Date.now() - t0).toBeGreaterThan(4000);
    expect(during).toBeGreaterThan(0);
    expect(rows.includes(4)).toBe(false);
    expect(decodedAreGenuine(bob, [alice.options.tag])).toBe(true);
  });

  it('RG-SCR-2 (I+HRP): fragments spliced from another frame, A\'s previous share and C\'s share are never decoded; B requests a keyframe and resumes', async () => {
    const { by, hrp } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    for (const hc of [alice, carol]) hc.screen.outputSize = o => (o.key ? 40_000 : 20_000);
    await startShare(alice, [bob]);
    // A's previous share: record its last fragments, then start a new share.
    const lastOf = (m: HrpMessage) => m.data.length < 1 + 32 + 16_000; // a non-full SCREEN_DOWN: the last fragment of a frame
    const prevShare = relayMessagesTo(hrp, bob, 'SCREEN_DOWN').filter(lastOf).slice(-10);
    alice.stopSharing();
    await waitFor('A idle', () => alice.state.screen.local?.state === 'idle', 10_000);
    await startShare(alice, [bob]);
    await startShare(carol, [bob]);
    const carolLast = relayMessagesTo(hrp, bob, 'SCREEN_DOWN').filter(m => lastOf(m) && Buffer.from(m.data.subarray(17, 33)).toString('hex') === carol.userId.replace(/-/g, '')).slice(-10);
    expect(prevShare.length).toBeGreaterThan(0);
    expect(carolLast.length).toBeGreaterThan(0);
    const aliceHex = alice.userId.replace(/-/g, '');
    const fromAlice = (m: HrpMessage) => Buffer.from(m.data.subarray(17, 33)).toString('hex') === aliceHex;
    // Last fragments of this share's earlier frames (already decoded): a frame whose last fragment is
    // replaced by one of them can never be completed from fragments that authenticate.
    const earlier = relayMessagesTo(hrp, bob, 'SCREEN_DOWN').filter(m => lastOf(m) && fromAlice(m)).slice(-10);
    expect(earlier.length).toBeGreaterThan(0);
    let mode: 'other_frame' | 'prev_share' | 'carol' | null = 'other_frame';
    let k = 0;
    hrp.addRule('s2c', m => {
      if (!mode || m.conn.userId !== bob.userId || typeOf(m) !== 'SCREEN_DOWN' || !fromAlice(m) || !lastOf(m)) return undefined;
      let sub: Uint8Array;
      if (mode === 'other_frame') sub = earlier[k++ % earlier.length].data;
      else if (mode === 'prev_share') sub = prevShare[k++ % prevShare.length].data;
      else {
        const c = Buffer.from(carolLast[k++ % carolLast.length].data);
        Buffer.from(aliceHex, 'hex').copy(c, 17); // `from` rewritten to A
        sub = c;
      }
      return { send: [sub] };
    });
    const kfrBefore = clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest').length;
    for (const next of ['prev_share', 'carol', null] as const) {
      await sleep(3000);
      mode = next;
    }
    expect(decodedAreGenuine(bob, [alice.options.tag, carol.options.tag])).toBe(true);
    // The incomplete frames were discarded; the first frame completed after them leaves a gap: B asks for a keyframe.
    await waitFor('B requests a keyframe', () => clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest').length > kfrBefore, 5000);
    const seen = bob.decodedFrom(alice).length;
    const resumed = await bob.decodes(alice, { count: 2, since: seen, timeoutMs: 20_000 });
    expect(resumed[0].key).toBe(true);
  });

  it('RG-SCR-3 (I+HRP): 5 s of A\'s fragments replayed 20 s later, after a rotation, and after A starts a new share decode nothing twice', async () => {
    const { by, hrp } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await startShare(alice, [bob]);
    const t0 = Date.now();
    await sleep(5000);
    const recorded = relayMessagesTo(hrp, bob, 'SCREEN_DOWN').filter(m => m.at >= t0);
    expect(recorded.length).toBeGreaterThan(50);
    const replay = () => recorded.forEach(m => hrp.inject(bob.userId, 's2c', m.data));
    await sleep(15_000);
    replay();
    await sleep(1000);
    await carol.joinVoice(w!.voiceChannel, w!.nodeId); // A rotates
    await waitFor('B installs A\'s next epoch', () => bob.receivedKeys.filter(k => k.from === alice.userId).length >= 2, 10_000);
    await sleep(2500);
    replay();
    await sleep(1000);
    alice.stopSharing();
    await waitFor('A idle', () => alice.state.screen.local?.state === 'idle', 10_000);
    // The new share's encoder restarts its output numbers: give its markers another tag so frames stay distinct.
    const secondTag = alice.options.tag + 1000;
    alice.screen.tag = secondTag;
    await waitFor('A can share', () => alice.state.screen.control.kind === 'idle', 10_000);
    alice.shareScreen();
    await waitFor('B sees the new tile', () => bob.state.screen.remote.some(r => r.sharerId === alice.userId && r.canWatch), 10_000);
    bob.watch(alice);
    await waitFor('the new share decodes', () => bob.screen.decodedMarkers.some(m => m.tag === secondTag), 15_000);
    replay();
    await sleep(1500);
    const all = bob.screen.decoders.flatMap(d => d.chunks.map(c => Buffer.from(c.data).toString('base64')));
    expect(all.length - new Set(all).size).toBe(0);
    expect(decodedAreGenuine(bob, [alice.options.tag, secondTag])).toBe(true);
  });

  it('RG-SCR-4 (I+HRP): A\'s audio frames moved into SCREEN_DOWN and its fragments moved into srtp_voice_packet play and decode nothing; A\'s audio and video continue', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    alice.screen.outputSize = o => (o.key ? 3000 : 1500);
    await startShare(alice, [bob]);
    let moving = true;
    hrp.addRule('s2c', m => {
      if (!moving || m.conn.userId !== bob.userId) return undefined;
      const t = typeOf(m);
      if (t === 'srtp_voice_packet' && m.json?.from === alice.userId) {
        const bytes = Buffer.from(String(m.json.packet_data), 'base64');
        hrp.inject(bob.userId, 's2c', encodeScreenDown(voiceChannel, alice.userId, bytes));
      }
      if (t === 'SCREEN_DOWN') {
        const frag = m.data.subarray(33);
        hrp.inject(bob.userId, 's2c', { type: 'srtp_voice_packet', from: alice.userId, channel_id: voiceChannel, packet_data: Buffer.from(frag).toString('base64'), timestamp: 0 });
      }
      return undefined;
    });
    const t0 = Date.now();
    const v0 = bob.decodedFrom(alice).length;
    await sleep(5000);
    moving = false;
    expect(bob.played.filter(p => p.at >= t0).every(p => p.from === alice.userId && p.tag === alice.options.tag)).toBe(true);
    expect(bob.playedFrom(alice).filter(p => p.at >= t0).length).toBeGreaterThan(100);
    expect(bob.decodedFrom(alice).length - v0).toBeGreaterThan(10);
    expect(decodedAreGenuine(bob, [alice.options.tag])).toBe(true);
    const dupAudio = new Map<number, number>();
    for (const p of bob.playedFrom(alice)) dupAudio.set(p.n, (dupAudio.get(p.n) ?? 0) + 1);
    expect([...dupAudio.values()].every(n => n === 1)).toBe(true);
  });

  it('RG-SCR-5 (I+HRP): a keyframe-request storm and a toggling watcher count force at most one extra keyframe per second; keys, epoch and bitrate are unchanged', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob', 'carol', 'mallory'], { outsiders: ['mallory'] });
    const { alice, bob, carol, mallory } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    await startShare(alice, [bob]);
    const epoch = alice.snapshot!.newestEpoch;
    const bitrate = alice.state.screen.local!.bitrate;
    // Which requests A acted on (REQ-51): its per-requester record of the last one acted on moved.
    const sender = alice.conn!.screenParts!.sender!;
    const lastActed = (sender as unknown as { lastActed: Map<string, number> }).lastActed;
    expect(lastActed).toBeInstanceOf(Map);
    const acted: Array<{ from: string; at: number }> = [];
    const onRequest = sender.onKeyframeRequest.bind(sender);
    sender.onKeyframeRequest = (from: unknown) => {
      const u = typeof from === 'string' ? from.toLowerCase() : '';
      const before = lastActed.get(u);
      onRequest(from);
      const after = lastActed.get(u);
      if (after !== undefined && after !== before) acted.push({ from: u, at: after });
    };
    hrp.addRule('s2c', m => (m.conn.userId === alice.userId && typeOf(m) === 'screen_watchers' ? 'drop' : undefined));
    const t0 = Date.now();
    const keysBefore = alice.screen.enc.outputs.filter(o => o.key).length;
    let toggle = 0;
    while (Date.now() - t0 < 6000) {
      for (const from of [bob, carol, mallory]) {
        for (let i = 0; i < 2; i++) hrp.inject(alice.userId, 's2c', { type: 'screen_keyframe_request', channel_id: voiceChannel, from: from.userId });
      }
      if (Date.now() - t0 >= toggle * 50) {
        hrp.inject(alice.userId, 's2c', { type: 'screen_watchers', channel_id: voiceChannel, watchers: toggle % 2 });
        toggle++;
      }
      await sleep(20);
    }
    hrp.inject(alice.userId, 's2c', { type: 'screen_watchers', channel_id: voiceChannel, watchers: 1 });
    const T = (Date.now() - t0) / 1000;
    const keys = alice.screen.enc.outputs.filter(o => o.key).length - keysBefore;
    // At most one per second from the relay-driven triggers, plus the 10 s periodic keyframe.
    expect(keys).toBeLessThanOrEqual(Math.ceil(T) + Math.ceil(T / 10) + 1);
    // Requests from the outsider are ignored; B and C each get at most one acted on per 5 s (and they do get some).
    expect(acted.filter(a => a.from === mallory.userId)).toEqual([]);
    for (const hc of [bob, carol]) {
      const times = acted.filter(a => a.from === hc.userId).map(a => a.at);
      expect(times.length, hc.name).toBeGreaterThan(0);
      expect(times.length, hc.name).toBeLessThanOrEqual(Math.ceil(T / 5));
      expect(times.slice(1).every((t, i) => t - times[i] >= 5000), hc.name).toBe(true);
    }
    expect(acted.every(a => a.from === bob.userId || a.from === carol.userId)).toBe(true);
    expect(alice.snapshot!.newestEpoch).toBe(epoch);
    expect(alice.state.screen.local!.bitrate).toBe(bitrate);
    expect(Math.max(...alice.screen.encoders.flatMap(e => e.configs.map(c => c.bitrate)))).toBeLessThanOrEqual(2_500_000);
  });

  it('RG-SCR-6 (I): a malicious sharer with valid keys cannot exceed the viewer\'s caps, queue, reassembly, budgets or decoder-setup limit; the watch ends with "can\'t be displayed"; a non-watcher decrypts nothing', async () => {
    const { by, hrp, voiceChannel } = await call(['mallory', 'bob', 'carol']);
    const { mallory, bob, carol } = by;
    await joinAll(w!, [mallory, bob, carol], 300);
    await allSecure([mallory, bob, carol]);
    await startShare(mallory, [bob]);
    mallory.stopScreenSource(); // a static screen: the forged traffic below is all M's client sends
    const key = bob.receivedKeys.filter(k => k.from === mallory.userId).slice(-1)[0]!;
    const inst = instBytes(key.inst);
    let vctr = 2 ** 36;
    const decrypts: number[] = [];
    const viewers = bob.conn!.screenParts!.viewers;
    const take = viewers.takeDecryption.bind(viewers);
    viewers.takeDecryption = (from: string) => {
      const ok = take(from);
      if (ok) decrypts.push(Date.now());
      return ok;
    };
    // B's incomplete frames after every fragment it processes from M (REQ-49: at most 4).
    let maxIncomplete = 0;
    const onFragment = viewers.onFragment.bind(viewers);
    viewers.onFragment = (from: string, kid: number, plaintext: Uint8Array) => {
      onFragment(from, kid, plaintext);
      maxIncomplete = Math.max(maxIncomplete, viewers.viewerOf(mallory.userId)?.reassembler.incompleteFrames ?? 0);
    };
    // B's tile never shows more than the waiting or stalled states (and the picture of M's valid frames).
    const rows = new Set<number>();
    const sampler = setInterval(() => {
      const tile = bob.state.screen.remote.find(r => r.sharerId === mallory.userId);
      if (tile?.watching) rows.add(tile.tile.row);
    }, 50);
    /** One fragment plaintext with any header, valid or not (M's modified client). */
    const raw = (h: { flags: number; shareSeq: number; frameNo: number; idx: number; count: number; w: number; h: number }, payload: Uint8Array) => {
      const out = new Uint8Array(FRAG_HDR + payload.length);
      const v = new DataView(out.buffer);
      out[0] = 1;
      out[1] = h.flags;
      v.setUint32(2, h.shareSeq);
      v.setUint32(6, h.frameNo);
      v.setUint16(10, h.idx);
      v.setUint16(12, h.count);
      v.setUint16(14, h.w);
      v.setUint16(16, h.h);
      out.set(payload, FRAG_HDR);
      return out;
    };
    const seal = (pt: Uint8Array) => sealWith(key.secret, key.epoch, MEDIA_KIND_VIDEO, vctr++, { channelId: voiceChannel, senderId: mallory.userId, inst }, pt);
    const send = async (pt: Uint8Array) => {
      hrp.inject(mallory.userId, 'c2s', encodeScreenUp(voiceChannel, await seal(pt)));
    };
    const seq = mallory.state.screen.local!.shareSeq;
    let frameNo = 1_000;
    const kf = (w: number, h: number, n: number) => syntheticVp8(true, w, h, { tag: 99, seq: n, picture: n }, 400);
    const delta = (n: number) => syntheticVp8(false, 1280, 720, { tag: 99, seq: 100 + n, picture: n }, 40);
    // Keyframes claiming 16383 × 16383; fragment header and VP8 header disagreeing.
    for (let i = 0; i < 5; i++) await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, kf(16383, 16383, i)));
    for (let i = 0; i < 5; i++) await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, kf(640, 360, i)));
    // Frames of 65 fragments; non-last fragments of 15,999 bytes; reserved flag bits.
    for (let i = 0; i < 3; i++) await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 65, w: 1280, h: 720 }, new Uint8Array(16_000)));
    for (let i = 0; i < 3; i++) await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 2, w: 1280, h: 720 }, new Uint8Array(15_999)));
    for (let i = 0; i < 3; i++) await send(raw({ flags: 0x81, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, kf(1280, 720, i)));
    // One valid keyframe, then 1,000 delta frames per second for 2 s.
    await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, kf(1280, 720, 50)));
    const tFlood = Date.now();
    for (let i = 0; i < 2000; i++) {
      await send(raw({ flags: 0, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, delta(i)));
      if (i % 100 === 99) await sleep(100);
    }
    await sleep(1100); // a new second of the decode budget
    // A slow decoder: B's decoder keeps its outputs for 300 ms at a time while M sends a keyframe and
    // 10 deltas each time. Nothing is passed to it while 5 chunks are queued (REQ-49, DECODE_QUEUE_MAX 4).
    const q0 = bob.screen.decodeQueueOnEntry.length;
    bob.screen.decoderHold = true;
    for (const d of bob.screen.decoders) d.hold = true;
    for (let c = 0; c < 4; c++) {
      await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, kf(1280, 720, 300 + c)));
      for (let i = 0; i < 10; i++) await send(raw({ flags: 0, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, delta(3000 + c * 10 + i)));
      await sleep(300);
      for (const d of bob.screen.decoders) d.flush();
    }
    bob.screen.decoderHold = false;
    for (const d of bob.screen.decoders) {
      d.hold = false;
      d.flush();
    }
    const heldQueue = bob.screen.decodeQueueOnEntry.slice(q0);
    expect(heldQueue.length).toBeGreaterThan(0);
    expect(Math.max(...bob.screen.decodeQueueOnEntry)).toBeLessThanOrEqual(4);
    expect(Math.max(...heldQueue)).toBe(4); // the queue did fill: the next chunk was refused, not queued
    // Incomplete frames: the first fragment of 3 for each of 20 frames. B keeps at most 4.
    for (let i = 0; i < 20; i++) await send(raw({ flags: 0, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 3, w: 1280, h: 720 }, new Uint8Array(16_000)));
    await sleep(500);
    // A flood of minimum-size fragments at the relay's full byte rate (500,000 B/s) for 1 s.
    const tMin = Date.now();
    let minBytes = 0;
    while (Date.now() - tMin < 1000) {
      const due = Math.ceil((Date.now() - tMin + 20) * 500 - minBytes); // bytes due at 500,000 B/s
      const n = Math.max(1, Math.ceil(due / 60));
      const batch = await Promise.all(Array.from({ length: n }, () => seal(raw({ flags: 0, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: 1280, h: 720 }, new Uint8Array(1)))));
      for (const frag of batch) {
        const up = encodeScreenUp(voiceChannel, frag);
        minBytes += up.length;
        hrp.inject(mallory.userId, 'c2s', up);
      }
      await sleep(10);
    }
    expect(minBytes / ((Date.now() - tMin) / 1000)).toBeGreaterThan(450_000);
    await sleep(1100);
    // Keyframes whose dimensions alternate on every frame.
    for (let i = 0; i < 40 && !bob.state.screen.remote.find(r => r.sharerId === mallory.userId)?.cantDisplay; i++) {
      const [w2, h2] = i % 2 === 0 ? [640, 360] : [1280, 720];
      await send(raw({ flags: 1, shareSeq: seq, frameNo: frameNo++, idx: 0, count: 1, w: w2, h: h2 }, kf(w2, h2, 200 + i)));
      await sleep(400);
    }
    await sleep(500);
    clearInterval(sampler);
    const setups = bob.screen.decoderSetups.map(s => s.at);
    for (const s of bob.screen.decoderSetups) {
      expect(s.codedWidth).toBeLessThanOrEqual(1920);
      expect(s.codedHeight).toBeLessThanOrEqual(1920);
      expect(s.codedWidth * s.codedHeight).toBeLessThanOrEqual(2_073_600);
    }
    expect(setups.slice(1).every((t, i) => t - setups[i] >= 2000 - 5)).toBe(true);
    expect(maxIncomplete).toBe(4); // the partial frames accumulated up to REASSEMBLY_MAX, never beyond
    expect(maxPerWindow(decrypts, 1000)).toBeLessThanOrEqual(160);
    expect(decrypts.filter(t => t >= tMin && t < tMin + 2000).length).toBeGreaterThan(50); // the flood reached B's budget
    const decoded = bob.screen.decodedAt.filter(d => d.at >= tFlood);
    expect(maxPerWindow(decoded.map(d => d.at), 1000)).toBeLessThanOrEqual(30);
    expect(maxPerWindow(decoded.filter(d => d.key).map(d => d.at), 1000)).toBeLessThanOrEqual(4);
    const tile = bob.state.screen.remote.find(r => r.sharerId === mallory.userId)!;
    expect(tile.cantDisplay).toBe(true);
    expect(tile.watching).toBe(false);
    // While watching, B showed only waiting, no-video, stalled or live rows (§8.4 rows 6 to 9), never "can't be verified".
    expect([...rows].filter(r => r < 6)).toEqual([]);
    // C does not watch: the relay sent it no fragment, and it set up no decoder.
    expect(relayMessagesTo(hrp, carol, 'SCREEN_DOWN')).toEqual([]);
    expect(carol.screen.decoders).toEqual([]);
  });

  /**
   * RG-SCR-8 (§10.3): B's socket is not read (HRP stops reading the relay's
   * socket for B) while the node owner kicks D, so the relay's screen queue
   * for B fills and its control queue holds `sender_key_rotation_required`.
   *
   * The stall is 6.5 s rather than §10.3's 5 s, in both forms, and B has
   * been decoding for 5 s since its last keyframe request when it starts.
   * That makes "B recovers with a keyframe request" deterministic instead of
   * a race (the fallback failed about 1 run in 5 with a 14 s stall: B's
   * whole REQ-50 schedule, now and 2, 4 and 8 s later, ran out during the
   * stall). Either B is between two frames when the stall begins, and the
   * gap after the resume puts it into awaiting-keyframe with a request at
   * once; or its incomplete frame expires about 1 s into the stall and it
   * requests then and 2, 4 and 8 s later. A acts on the first of those (no
   * request of B's in the last 5 s, REQ-51) and ignores the next two. With
   * 6.5 s the +4 s request falls before the resume and the +8 s one after
   * it, and every keyframe A made during the stall (the one for B's request,
   * and the first frame under the epoch D's removal starts) is more than 2 s
   * old at the resume, so the relay drops it: B cannot leave awaiting before
   * it requests again after the resume. With 5 s, the +4 s request and the
   * resume raced, and a keyframe answering the +2 s request could still be
   * in the queue. The longer stall checks the same properties with more of
   * the queue dropped. B's recovery is then a keyframe decoded after that
   * request; it can take up to the +8 s request, because the burst of
   * undecodable deltas the relay delivers at the resume can use up B's
   * 30-per-second decode budget, which §6.2.9 takes before the delta checks,
   * and the keyframe answering the first request is then discarded.
   *
   * Since A2 the relay keeps at most about `RELAY_NOTSENT_LOWAT` unsent in
   * its kernel send buffer, so without the §10.1 cap only the proxy's
   * receive buffer (Linux tunes it, about 0.5 MB here) is in transit, not
   * megabytes; the same stall fills the queue in both forms. The capped form
   * bounds what is in transit by the proxy's 64 KiB receive buffer, the
   * relay's unsent data (`RELAY_NOTSENT_LOWAT` plus two SCREEN_DOWN
   * messages, as in T-51) and one proxy read. Send buffers are not capped,
   * so without TCP_NOTSENT_LOWAT the relay's kernel would take megabytes of
   * the stalled stream before its screen queue filled, and both forms fail.
   * The uncapped form checks the 2 s age per fragment rather than the
   * capped form's byte bound.
   */
  it('RG-SCR-8 (I+HRP, C115): while B\'s socket is not read, its control messages still arrive afterwards; it loses only fragments, none held by the relay for over 2 s, and recovers with a keyframe request', async () => {
    const strict = CAPPED;
    const stallMs = 6500;
    const { by, hrp, nodeId } = await call(['owner', 'alice', 'bob', 'carol', 'dave'], { client: () => ({ muted: true }) });
    const { owner, alice, bob, carol, dave } = by;
    await joinAll(w!, [alice, bob, carol, dave], 300);
    await allSecure([alice, bob, carol]);
    alice.screen.outputSize = o => (o.key ? 120_000 : 33_000); // about 500 KB/s, the relay's default rate
    await startShare(alice, [bob, carol]);
    const bConn = connOf(hrp, bob);
    const up = new Map<number, number>(); // VCTR → when HRP saw A's SCREEN_UP
    hrp.addRule('c2s', m => {
      if (typeOf(m) === 'SCREEN_UP' && m.conn.userId === alice.userId) up.set(frameHeader(screenUp(m)!.fragment)!.ctr, m.at);
      return undefined;
    });
    // B decodes steadily, and its last keyframe request was at least 5 s ago (KFR_PER_USER_GAP).
    const lastRequest = () => Math.max(0, ...clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest').map(m => m.at));
    await waitFor('B decodes steadily, 5 s after its last keyframe request', () => {
      const v = bob.state.screen.remote.find(r => r.sharerId === alice.userId)?.viewer;
      return v?.state === 'decoding' && Date.now() - lastRequest() >= 5500 ? true : undefined;
    }, 30_000);
    // Before the stall: how long a fragment takes from A's SCREEN_UP to B's SCREEN_DOWN at the proxy.
    const pre = hrp.mark();
    await sleep(2000);
    const transit = relayMessagesTo(hrp, bob, 'SCREEN_DOWN', pre).map(m => m.at - (up.get(frameHeader(m.data.subarray(33))!.ctr) ?? m.at)).sort((a, b) => a - b);
    const transitP95 = transit[Math.floor(transit.length * 0.95)] ?? 0;
    const mark = hrp.mark();
    const stallAt = Date.now();
    hrp.stall(bConn, 's2c', true);
    await sleep(2000);
    await owner.client.api.kickMember(nodeId, dave.userId, owner.client.token);
    const carolBefore = carol.decodedFrom(alice).length;
    await sleep(stallAt + stallMs - Date.now());
    expect(carol.decodedFrom(alice).length - carolBefore).toBeGreaterThan(15); // other watchers keep receiving
    const resumeAt = Date.now();
    hrp.stall(bConn, 's2c', false);
    await waitFor('B gets the rotation event', () => relayMessagesTo(hrp, bob, 'sender_key_rotation_required', mark).some(m => m.json?.removed_user_id === dave.userId), 15_000);
    expect(relayMessagesTo(hrp, bob, 'voice_peer_left', mark).some(m => m.json?.user_id === dave.userId)).toBe(true);
    await sleep(2000);
    // What B lost is fragments only: the stream B receives after the stall has a gap where the relay dropped.
    const after = relayMessagesTo(hrp, bob, 'SCREEN_DOWN', mark).filter(m => m.at >= resumeAt).map(m => ({ at: m.at, ctr: frameHeader(m.data.subarray(33))!.ctr, bytes: m.data.length }));
    const firstGap = after.findIndex((x, i) => i > 0 && x.ctr !== after[i - 1].ctr + 1);
    expect(firstGap).toBeGreaterThan(0);
    // Before the gap: what sat in kernel and proxy buffers during the stall (the relay had already handed it on).
    const inTransit = after.slice(0, firstGap);
    const drainedAt = inTransit[inTransit.length - 1].at;
    // From the gap on, everything came out of the relay's screen queue after the stall: none of it was held there for over 2 s.
    const fromQueue = after.slice(firstGap).filter(x => up.has(x.ctr));
    expect(fromQueue.length).toBeGreaterThan(10);
    const worst = Math.max(...fromQueue.map(x => x.at - up.get(x.ctr)!));
    console.info(`RG-SCR-8: ${strict ? 'kernel TCP receive buffers capped' : 'kernel TCP buffers NOT capped'}; ${stallMs} ms stall; ${inTransit.reduce((n, x) => n + x.bytes, 0)} bytes in transit during the stall (drained ${drainedAt - resumeAt} ms after resuming); oldest fragment from the relay's queue ${worst} ms after A sent it; steady-state transit p95 ${transitP95} ms`);
    if (strict) {
      // HRP's 64 KiB receive buffer, the relay's unsent data (TCP_NOTSENT_LOWAT, A2) and one proxy read.
      expect(inTransit.reduce((n, x) => n + x.bytes, 0)).toBeLessThanOrEqual(SMALL_SOCKET_BUFFER + RELAY_NOTSENT_LOWAT + 2 * SCREEN_DOWN_MAX + PROXY_READ_SIZE);
      expect(worst).toBeLessThanOrEqual(2000 + transitP95 + (drainedAt - resumeAt) + 300);
    } else {
      for (const x of fromQueue.filter(f => up.get(f.ctr)! < resumeAt)) expect(x.at - up.get(x.ctr)!).toBeLessThanOrEqual(2000 + 500 + (x.at - resumeAt));
    }
    // B recovers with a keyframe request: one after the resume (at the latest the +8 s request of the
    // schedule B started about 1 s into the stall), then a keyframe decoded after it, and frames again.
    const request = await waitFor('B requests a keyframe after the resume', () => clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest', mark).find(m => m.at >= resumeAt), 15_000);
    await waitFor('B decodes a keyframe after its request', () => (bob.screen.decodedAt.some(d => d.key && d.at >= request.at) ? true : undefined), 15_000);
    const seen = bob.decodedFrom(alice).length;
    await bob.decodes(alice, { count: 3, since: seen, timeoutMs: 20_000 });
    const requestsAfter = clientMessagesFrom(hrp, bob, 'ScreenKeyframeRequest', mark).map(m => m.at - stallAt);
    console.info(`RG-SCR-8: B's keyframe requests at ${requestsAfter.join(', ')} ms after the stall began (resumed at ${resumeAt - stallAt} ms)`);
    expect(stallAt).toBeLessThan(resumeAt);
  });

  it('RG-SCR-9 (I+HRP): a kicked watcher keeps receiving fragments from a non-evicting relay, but none sealed after A processed the removal decrypts with any key it had', async () => {
    const { by, hrp, voiceChannel, nodeId } = await call(['alice', 'bob', 'carol']);
    const { alice, bob, carol } = by;
    await joinAll(w!, [alice, bob, carol], 300);
    await allSecure([alice, bob, carol]);
    await startShare(alice, [bob, carol]);
    hrp.addRule('s2c', m => {
      const t = typeOf(m);
      if ((t === 'voice_peer_left' || t === 'screen_share_stopped') && m.json?.user_id === carol.userId) return 'drop';
      if (t === 'voice_channel_left' && m.conn.userId === carol.userId) return 'drop';
      return undefined;
    });
    copyMediaTo(hrp, alice, bob, carol, { screen: true });
    const processed = eventTimes(alice, 'sender_key_rotation_required', d => d.removed_user_id === carol.userId);
    // Positive control: C's keys open A's fragments from before.
    const control = alice.sentFragments.slice(-1)[0]!;
    expect(await openWithAny({ msg: undefined as never, kind: MEDIA_KIND_VIDEO, from: alice.userId, channelId: voiceChannel, bytes: control.bytes }, carol.receivedKeys)).not.toBeNull();
    await alice.client.api.kickMember(nodeId, carol.userId, alice.client.token);
    await waitFor('A processed the removal', () => processed[0], 10_000);
    await sleep(4000);
    const after = alice.sentFragments.filter(f => f.at > processed[0]);
    expect(after.length).toBeGreaterThan(20);
    for (const f of after) {
      expect(await openWithAny({ msg: undefined as never, kind: MEDIA_KIND_VIDEO, from: alice.userId, channelId: voiceChannel, bytes: f.bytes }, carol.receivedKeys)).toBeNull();
    }
  });

  it('RG-SCR-10 (I+HRP, downgrade): a new socket without screen/1, a p2p report and screen-sdp offers make sharing and watching unavailable with their reasons; no video in audio messages, no peer connection, voice continues', async () => {
    const { by, hrp, voiceChannel } = await call(['alice', 'bob']);
    const { alice, bob } = by;
    await joinAll(w!, [alice, bob]);
    await allSecure([alice, bob]);
    await startShare(alice, [bob]);
    hrp.stripScreenFeature = conn => conn.userId === bob.userId;
    const mark = hrp.mark();
    hrp.closeConn(connOf(hrp, bob));
    await waitFor('B rejoins', () => bob.state.phase === 'joined' && bob.ws.helloProcessed(), 20_000);
    await waitFor('B\'s control is row 4', () => bob.state.screen.control.kind === 'relay_unsupported', 10_000);
    hrp.inject(bob.userId, 's2c', { type: 'voice_mode_changed', channel_id: voiceChannel, voice_mode: 'p2p', user_id: alice.userId });
    for (let i = 0; i < 3; i++) hrp.inject(bob.userId, 's2c', { type: 'p2p_signal', channel_id: voiceChannel, from: alice.userId, signal_data: JSON.stringify({ type: 'screen-sdp', sdp: OUTSIDER_SDP }) });
    await waitFor('the p2p note', () => bob.state.relayReportsP2p, 5000);
    const tile = await waitFor('B\'s tile for A', () => bob.state.screen.remote.find(r => r.sharerId === alice.userId), 10_000);
    expect(tile.tile).toMatchObject({ row: 1, kind: 'viewing_unavailable', cause: 'relay' });
    expect(tile.canWatch).toBe(false);
    expect(bob.watch(alice)).toBe(false);
    expect(bob.shareScreen()).toBe(false);
    await bob.hears(alice, { since: Date.now() });
    expect(peerConnectionConstructions()).toBe(0);
    // No audio message ever carried video: every frame is AMF1 audio of at most 4096 bytes.
    for (const m of hrp.messages({ dir: 'c2s', type: 'SrtpVoicePacket' })) {
      const f = wireFrame(m)!;
      expect(f.bytes.length).toBeLessThanOrEqual(4096);
      expect(frameHeader(f.bytes)?.kind).toBe(MEDIA_KIND_AUDIO);
    }
    expect(hrp.messages({ dir: 'c2s', type: 'VoicePacket' })).toEqual([]);
    // Nothing screen-related went to the relay that no longer offers it.
    for (const type of ['ScreenWatch', 'ScreenShareStart', 'ScreenKeyframeRequest', 'SCREEN_UP']) expect(clientMessagesFrom(hrp, bob, type, mark)).toEqual([]);
  });
});
