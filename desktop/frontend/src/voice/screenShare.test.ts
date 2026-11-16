// @vitest-environment node
/**
 * SPEC-03 A1 U tests of screen sharing end to end: real
 * `RelayVoiceConnection`s, `CallKeyManager`s and AMF1 crypto over the
 * in-memory relay of `voice/relay.testkit.ts` (which implements the screen
 * path of §6.12 per user), with the screen fakes of §10.1: a synthetic VP8
 * source and encoder whose frames carry markers, and a recording decoder
 * that pads coded sizes to 16 by default.
 *
 * T-2 (A1 part), T-3 (A1 part), T-22 (screen part), T-38 (screen part),
 * T-45, T-47 (audio first), T-48, T-49 (the parts above `ShareReassembler`:
 * the third watch, two decoders, drawing the visible rectangle), T-50 (U),
 * T-52 (U: a remote sharer's new instance, and the stop conditions the
 * connection owns: E2EE lock, eviction, self-check rejoin, channel switch),
 * T-53, and the panel refreshes of §8.4. The reassembly rules of
 * §6.2.9 themselves are tested in `screenFrame.test.ts`, the sender's in
 * `screenShare.sender.test.ts`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeWireBase64 } from '../attachments/base64';
import { A, B, C, CH, CH2, D, readCall } from './callKeys.testkit';
import { CallKeyManager } from './callKeys';
import { encodeSFrameHeader, parseFrame, MEDIA_KIND_VIDEO } from './mediaFrame';
import { decodeScreenUp, encodeFragment, WATCH_MAX } from './screenFrame';
import { FakeVoiceRelay, pcmMarker, voiceClient, type VoiceClient, type VoiceClientOptions } from './relay.testkit';
import { FakeScreenPlatform, FakeSurface, syntheticVp8 } from './screenShare.testkit';
import { SEND_BUFFER_HIGH, VIDEO_AEAD_FAIL_NOTICE } from './screenShare';

let relay: FakeVoiceRelay;

beforeEach(() => {
  relay = new FakeVoiceRelay();
  relay.enableScreen();
});

afterEach(() => {
  for (const s of relay.sockets.values()) s.connected = false;
  vi.restoreAllMocks();
});

const TAG: Record<string, number> = { [A]: 1, [B]: 2, [C]: 3, [D]: 4 };

interface SC extends VoiceClient {
  readonly screen: FakeScreenPlatform;
  readonly surface: FakeSurface;
}

function client(id: string, opts: Partial<VoiceClientOptions> = {}): SC {
  const screen = new FakeScreenPlatform(TAG[id] ?? 9);
  screen.clock = relay.clock;
  const c = voiceClient(relay, id, { channelId: CH, screen, ...opts });
  return Object.assign(c, { screen, surface: new FakeSurface() });
}

async function inCall(ids: string[]): Promise<SC[]> {
  const out: SC[] = [];
  for (const id of ids) {
    const c = client(id);
    out.push(c);
    void c.conn.connect();
    await relay.settle();
  }
  await relay.advance(3000);
  return out;
}

async function share(c: SC): Promise<void> {
  expect(c.conn.startScreenShare()).toBe(true);
  await relay.settle();
  expect(c.conn.state.screen.local?.state).toBe('sharing');
}

async function watch(v: SC, sharer: SC): Promise<void> {
  v.conn.attachScreenSurface(sharer.id, v.surface);
  expect(v.conn.watchScreen(sharer.id)).toBe(true);
  await relay.settle();
}

async function frames(c: SC, n: number, opts: { every?: number; w?: number; h?: number } = {}): Promise<void> {
  for (let i = 0; i < n; i++) {
    c.screen.source.push(opts.w ?? 1280, opts.h ?? 720);
    await relay.settle();
    await relay.advance(opts.every ?? 67);
  }
}

/** Markers of `from`'s video that `v` decoded. */
function decoded(v: SC, from: SC): number[] {
  return v.screen.decodedMarkers.filter(m => m.tag === from.screen.tag).map(m => m.seq);
}

function tileOf(v: SC, sharer: string) {
  return v.conn.state.screen.remote.find(t => t.sharerId === sharer) ?? null;
}

/** The AMF1 fragments `from` sent, in order. */
function fragmentsOf(from: string): Uint8Array[] {
  return relay.binaryLog.filter(m => m.from === from).map(m => Uint8Array.from(decodeScreenUp(m.bytes)!.fragment));
}

function sentTypes(user: string, type: string) {
  return relay.sent(user, type);
}

describe('screen sharing between two connections', () => {
  it('A shares, B watches: B decodes A\'s frames and draws only their visible rectangle (T-49: 1920 × 1080 decoded with a coded size of 1920 × 1088)', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    expect(tileOf(b, A)?.tile.kind).toBe('not_watching');
    expect(sentTypes(B, 'ScreenWatch')).toHaveLength(0); // opt-in (REQ-50)
    await watch(b, a);
    await frames(a, 10, { w: 1920, h: 1080 });
    expect(decoded(b, a)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(b.surface.draws.length).toBe(10);
    for (const d of b.surface.draws) expect([d.width, d.height, d.codedWidth, d.codedHeight]).toEqual([1920, 1080, 1920, 1088]);
    expect(tileOf(b, A)?.tile.kind).toBe('live');
    // Every decoded frame was closed after drawing (REQ-27).
    expect(b.screen.decodedFrames.size).toBe(0);
  });

  it('T-2 (A1): every fragment leaves as a binary SCREEN_UP of kind 0x02; no video in SrtpVoicePacket, and nothing before the share or the watch', async () => {
    const [a, b] = await inCall([A, B]);
    a.input.produce(pcmMarker(1, 0));
    await share(a);
    await frames(a, 3);
    expect(relay.binaryLog.filter(m => m.from === A)).toHaveLength(0); // no watcher yet
    await watch(b, a);
    await frames(a, 5);
    for (let i = 0; i < 5; i++) a.input.produce(pcmMarker(1, i + 1));
    await relay.settle();
    const ups = relay.binaryLog.filter(m => m.from === A);
    expect(ups.length).toBeGreaterThan(0);
    for (const m of ups) {
      expect(m.bytes[0]).toBe(0x01);
      expect(m.bytes[17]).toBe(0x01); // AMF1
      expect(m.bytes[18]).toBe(MEDIA_KIND_VIDEO);
    }
    const audio = relay.sent(A, 'SrtpVoicePacket').map(m => decodeWireBase64(m.body.packet_data)!);
    expect(audio.length).toBeGreaterThan(0);
    for (const f of audio) expect(f[1]).toBe(0x01);
    expect(relay.sent(A).map(m => m.type).filter(t => /VoicePacket$/.test(t) && t !== 'SrtpVoicePacket')).toEqual([]);
  });
});

describe('T-45 (REQ-45) video keys are the call\'s epoch keys', () => {
  it('only hello, CKM and ACK are sent; video goes to R_g; a participant joining during a share decrypts nothing sealed before its first epoch', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    await frames(a, 5);
    const before = fragmentsOf(A);
    expect(decoded(b, a)).toHaveLength(5);
    // C joins during the share and watches; A rotates for it (REQ-16 (a)).
    const c = client(C);
    void c.conn.connect();
    await relay.settle();
    await relay.advance(3000);
    await watch(c, a);
    // The relay replays to C every fragment A sent before C's first epoch.
    for (const f of before) relay.injectFragment(C, CH, A, f);
    await relay.settle();
    expect(decoded(c, a)).toEqual([]);
    await frames(a, 5);
    expect(decoded(c, a).length).toBeGreaterThan(0);
    expect(Math.min(...decoded(c, a))).toBeGreaterThan(5);
    // R for video is R of the epoch: the audience the panel shows equals the epoch's recipients.
    const audience = a.conn.state.screen.local!.audience!;
    const recipients = a.conn.state.call!.participants.filter(p => p.recipient).map(p => p.userId).sort();
    expect([...audience.members].sort()).toEqual(recipients);
    expect(recipients).toEqual([B, C].sort());
    // Screen sharing added no call message type.
    for (const user of [A, B, C]) {
      for (const m of relay.sent(user, 'VoiceKeyExchange')) expect(['call_hello', 'call_key', 'call_key_ack']).toContain(readCall(m.body.wrapped_key).type);
    }
  });
});

describe('T-48 (REQ-48) and T-3 (A1) receiving fragments', () => {
  it('discards a fragment at each check of §6.2.8; nothing unauthenticated reaches reassembly, the decoder or the canvas', async () => {
    const [a, b, c] = await inCall([A, B, C]);
    await share(a);
    await watch(b, a);
    await frames(a, 3);
    const good = fragmentsOf(A);
    const last = good[good.length - 1];
    const draws = b.surface.draws.length;
    const markers = b.screen.decodedMarkers.length;
    const parsed = parseFrame(last, MEDIA_KIND_VIDEO);
    if (!parsed.ok) throw new Error('bad fixture');
    const withHeader = (kid: number, ctr: number) => Uint8Array.from([0x01, 0x02, ...encodeSFrameHeader(kid, ctr), ...parsed.ciphertext]);
    const forged: Array<[string, string, string, Uint8Array]> = [
      ['another channel', CH2, A, last],
      ['a sender outside V', CH, D, last],
      ['the local user', CH, B, last],
      ['too short', CH, A, last.subarray(0, 19)],
      ['format 0x02', CH, A, Uint8Array.from([0x02, ...last.subarray(1)])],
      ['an audio kind', CH, A, Uint8Array.from([0x01, 0x01, ...last.subarray(2)])],
      ['a non-minimal header', CH, A, Uint8Array.from([0x01, 0x02, 0x08, 0x00, ...last.subarray(3)])],
      ['an unknown KID', CH, A, withHeader(parsed.kid + 5, parsed.ctr + 1)],
      ['a replay', CH, A, last],
      ['a failed AEAD', CH, A, withHeader(parsed.kid, parsed.ctr + 50)],
    ];
    for (const [, ch, from, bytes] of forged) relay.injectFragment(B, ch, from, bytes);
    // An authenticated audio frame of A re-wrapped as SCREEN_DOWN (T-3, RG-SCR-4).
    a.input.produce(pcmMarker(1, 1));
    await relay.settle();
    const audioFrame = decodeWireBase64(relay.sent(A, 'SrtpVoicePacket').slice(-1)[0].body.packet_data)!;
    relay.injectFragment(B, CH, A, audioFrame);
    await relay.settle();
    await relay.advance(100);
    expect(b.screen.decodedMarkers.length).toBe(markers);
    expect(b.surface.draws.length).toBe(draws);
    // A's genuine video continues.
    await frames(a, 2);
    expect(decoded(b, a)).toHaveLength(5);
    // C does not watch A: A's fragments delivered to C are never decrypted.
    const spy = vi.spyOn(globalThis.crypto.subtle, 'decrypt');
    for (const f of good) relay.injectFragment(C, CH, A, f);
    await relay.settle();
    expect(spy).not.toHaveBeenCalled();
    expect(c.screen.decodedMarkers).toHaveLength(0);
  });

  it('50 consecutive AEAD failures from a keyed, watched sharer show "can\'t be verified" and clear the picture; one success resets the count; fragments over the decryption budget are not decrypted and do not count', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    await frames(a, 3);
    const parsed = parseFrame(fragmentsOf(A).slice(-1)[0], MEDIA_KIND_VIDEO);
    if (!parsed.ok) throw new Error('bad fixture');
    const forge = (i: number) => Uint8Array.from([0x01, 0x02, ...encodeSFrameHeader(parsed.kid, parsed.ctr + 100 + i), ...parsed.ciphertext]);
    const clears = b.surface.clears;
    for (let i = 0; i < VIDEO_AEAD_FAIL_NOTICE - 1; i++) relay.injectFragment(B, CH, A, forge(i));
    await relay.settle();
    expect(tileOf(b, A)?.tile.kind).toBe('live');
    relay.injectFragment(B, CH, A, forge(VIDEO_AEAD_FAIL_NOTICE));
    await relay.settle();
    expect(tileOf(b, A)?.tile.kind).toBe('cant_verify');
    expect(b.surface.clears).toBe(clears + 1);
    await relay.advance(1000);
    await frames(a, 1);
    expect(tileOf(b, A)?.viewer?.aeadFailures).toBe(0);
    expect(tileOf(b, A)?.tile.kind).not.toBe('cant_verify');
    // 300 forgeries at one instant: at most 160 decryptions (VIEW_DECRYPT_RATE), and only those count.
    await relay.advance(1500);
    const spy = vi.spyOn(globalThis.crypto.subtle, 'decrypt');
    for (let i = 0; i < 300; i++) relay.injectFragment(B, CH, A, forge(1000 + i));
    await relay.settle();
    expect(spy.mock.calls.length).toBeLessThanOrEqual(160);
    expect(spy.mock.calls.length).toBeGreaterThan(100);
    expect(tileOf(b, A)?.viewer?.aeadFailures).toBe(spy.mock.calls.length);
  });
});

describe('T-49 (REQ-49) watches and decoders', () => {
  it('a third watch is refused locally; at most 2 decoders exist at once', async () => {
    const [a, b, c, d] = await inCall([A, B, C, D]);
    relay.enableScreen(true, { maxSharers: 3 });
    await relay.settle();
    for (const s of [a, b, c]) await share(s);
    expect(d.conn.state.screen.remote.map(t => t.sharerId)).toEqual([A, B, C]);
    await watch(d, a);
    await watch(d, b);
    expect(tileOf(d, C)?.canWatch).toBe(false);
    expect(d.conn.state.screen.watching).toBe(WATCH_MAX);
    expect(d.conn.watchScreen(C)).toBe(false);
    await relay.settle();
    expect(relay.sent(D, 'ScreenWatch').map(m => m.body.sharer_id)).toEqual([A, B]);
    for (const s of [a, b, c]) await frames(s, 2);
    const alive = d.screen.decoders.filter(x => x.state !== 'closed');
    expect(alive.length).toBeLessThanOrEqual(2);
    // Stopping one watch frees a slot.
    d.conn.unwatchScreen(A);
    await relay.settle();
    expect(tileOf(d, C)?.canWatch).toBe(true);
  });
});

/** An authenticated key-frame plaintext of one fragment, as a malicious sharer's own keys would produce. */
function keyframePlaintext(frameNo: number, w: number, h: number): Uint8Array {
  const data = syntheticVp8(true, w, h, { tag: 99, seq: frameNo, picture: 0 }, 64);
  return encodeFragment({ vcodec: 1, flags: 1, shareSeq: 1, frameNo, fragIndex: 0, fragCount: 1, width: w, height: h }, data);
}

describe('T-49 (REQ-49) RG-SCR-6: decoder setups', () => {
  it('key frames alternating 640 × 360 and 1280 × 720: at most one setup per 2 s; after 3 refusals within 30 s the watch ends with "can\'t be displayed" and ScreenWatch false', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    const viewers = b.conn.screenParts!.viewers;
    let frameNo = 0;
    for (let i = 0; i < 100 && viewers.isWatching(A); i++) {
      const [w, h] = i % 2 === 0 ? [640, 360] : [1280, 720];
      viewers.onFragment(A, 0, keyframePlaintext(frameNo++, w, h));
      await relay.settle();
      await relay.advance(100);
    }
    expect(viewers.isWatching(A)).toBe(false);
    const setups = b.screen.decoderSetups.map(s => s.at);
    for (let i = 1; i < setups.length; i++) expect(setups[i] - setups[i - 1]).toBeGreaterThanOrEqual(2000);
    expect(tileOf(b, A)?.cantDisplay).toBe(true);
    expect(tileOf(b, A)?.tile.kind).toBe('not_watching');
    expect(relay.attempts(B, 'ScreenWatch').map(m => m.body.watch)).toEqual([true, false]);
    // Watch again clears the note.
    expect(b.conn.watchScreen(A)).toBe(true);
    expect(tileOf(b, A)?.cantDisplay).toBe(false);
  });
});

describe('T-50 (REQ-50) watching and keyframe requests, U', () => {
  it('requests on watch start and 2, 4 and 8 s later, then none until a frame decodes; repeated failures while awaiting do not restart it; at most one per second; never a call message', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    const calls = b.bridge.encryptCalls.length;
    const t0 = relay.clock.now();
    await watch(b, a);
    await relay.advance(20_000);
    const at = () => sentTypes(B, 'ScreenKeyframeRequest').map(m => m.at - t0);
    expect(at()).toEqual([0, 2000, 4000, 8000]);
    // A frame decodes, then a gap (a lost frame) starts a new awaiting period.
    await frames(a, 3);
    expect(decoded(b, a)).toHaveLength(3);
    relay.screenFilter = () => false;
    await frames(a, 1);
    relay.screenFilter = () => true;
    const t1 = relay.clock.now();
    await frames(a, 1); // a delta after the gap
    // More failures while awaiting: deltas keep arriving and are dropped.
    a.screen.outputSize = o => (o.key ? 4000 : 600);
    for (let i = 0; i < 5; i++) await frames(a, 1);
    const after = sentTypes(B, 'ScreenKeyframeRequest').map(m => m.at).filter(x => x >= t1);
    expect(after.length).toBeGreaterThanOrEqual(1);
    for (let i = 1; i < after.length; i++) expect(after[i] - after[i - 1]).toBeGreaterThanOrEqual(1000);
    // Only one new schedule: its offsets from the first request are 0, 2, 4, 8 s at most.
    expect(after.length).toBeLessThanOrEqual(4);
    // Screen signals never go through the E2EE bridge (REQ-50).
    expect(b.bridge.encryptCalls.length).toBe(calls);
  });

  it('no request while no video key for the sharer is installed, and one as soon as it is', async () => {
    const a = client(A);
    void a.conn.connect();
    await relay.settle();
    await relay.advance(3000);
    await share(a);
    // B joins; the relay withholds A's call messages to B for now.
    let hold = true;
    relay.filter = (to, data) => !(hold && to === B && data.type === 'voice_key_exchange' && data.from === A);
    const b = client(B);
    void b.conn.connect();
    await relay.settle();
    await relay.advance(500);
    expect(tileOf(b, A)).not.toBeNull();
    await watch(b, a);
    await relay.advance(5000);
    expect(sentTypes(B, 'ScreenKeyframeRequest')).toHaveLength(0);
    expect(tileOf(b, A)?.tile.kind).toBe('waiting_for_keys');
    await relay.advance(8000);
    expect(tileOf(b, A)?.tile).toEqual({ row: 5, kind: 'waiting_for_keys', long: true });
    hold = false;
    await relay.advance(31_000); // A recovers its CKM (REQ-20)
    const reqs = sentTypes(B, 'ScreenKeyframeRequest');
    expect(reqs.length).toBeGreaterThan(0);
  });

  it('each end condition sends ScreenWatch false, closes the decoder and clears the canvas', async () => {
    type End = (ctx: { a: SC; b: SC }) => void | Promise<void>;
    const ends: Array<[string, End]> = [
      ['the user stops watching', ({ b }) => b.conn.unwatchScreen(A)],
      ['the share leaves the remote share list', ({ a }) => a.conn.stopScreenShare()],
      ['the sharer leaves V', ({ a }) => a.conn.disconnect()],
      ['the sharer becomes ineligible', ({ b }) => b.bridge.setMembership(A, 'not_member')],
      ['the call ends', ({ b }) => b.conn.disconnect()],
    ];
    for (const [name, end] of ends) {
      relay = new FakeVoiceRelay();
      relay.enableScreen();
      const [a, b] = await inCall([A, B]);
      await share(a);
      await watch(b, a);
      await frames(a, 2);
      const dec = b.screen.decoders[b.screen.decoders.length - 1];
      expect(dec.state, name).toBe('configured');
      const clears = b.surface.clears;
      await end({ a, b });
      await relay.settle();
      const watches = relay.attempts(B, 'ScreenWatch');
      expect(watches.map(m => [m.body.sharer_id, m.body.watch]), name).toEqual([[A, true], [A, false]]);
      expect(dec.state, name).toBe('closed');
      expect(b.surface.clears, name).toBeGreaterThan(clears);
      expect(b.conn.screenParts?.viewers.isWatching(A) ?? false, name).toBe(false);
    }
  });

  it('screen_watch_rejected, for each reason: stops watching without ScreenWatch false and without retrying; the tile shows the reason; not_sharing removes the tile', async () => {
    for (const reason of ['disabled', 'not_participant', 'rate_limited', 'not_sharing', 'watch_limit']) {
      relay = new FakeVoiceRelay();
      relay.enableScreen();
      const [a, b] = await inCall([A, B]);
      await share(a);
      await watch(b, a);
      await frames(a, 2);
      const dec = b.screen.decoders[b.screen.decoders.length - 1];
      const clears = b.surface.clears;
      const requests = sentTypes(B, 'ScreenKeyframeRequest').length;
      relay.inject(B, { type: 'screen_watch_rejected', channel_id: CH, sharer_id: A, reason, error: 'x', request_id: 'r' });
      await relay.settle();
      if (reason === 'not_sharing') expect(tileOf(b, A), reason).toBeNull();
      else expect(tileOf(b, A)?.rejected, reason).toBe(reason);
      await relay.advance(20_000);
      expect(dec.state, reason).toBe('closed');
      expect(b.surface.clears, reason).toBeGreaterThan(clears);
      expect(sentTypes(B, 'ScreenKeyframeRequest').length, reason).toBe(requests);
      expect(relay.attempts(B, 'ScreenWatch').map(m => m.body.watch), reason).toEqual([true]);
      // The relay still lists A's share, so the self-check brings the tile
      // back (REQ-38); Watch is offered again and nothing was retried.
      expect(tileOf(b, A)?.tile.kind, reason).toBe('not_watching');
      if (reason !== 'not_sharing') expect(tileOf(b, A)?.rejected, reason).toBe(reason);
    }
  });

  it('T-52: a remote sharer\'s new instance resets that share\'s decoding state and starts a new request schedule', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    await frames(a, 3);
    const viewer = b.conn.screenParts!.viewers.viewerOf(A)!;
    expect(viewer.decodeState).toBe('decoding');
    const dec = b.screen.decoders[b.screen.decoders.length - 1];
    const requests = sentTypes(B, 'ScreenKeyframeRequest').length;
    b.conn.screenParts!.viewers.onRemoteReset(A, true);
    await relay.settle();
    expect(viewer.decodeState).toBe('awaiting_keyframe');
    expect(viewer.reassembler.shareSeq).toBe(0);
    expect(dec.state).toBe('closed');
    // The new schedule's first request, at most one per share per second.
    await relay.advance(1000);
    expect(sentTypes(B, 'ScreenKeyframeRequest').length).toBe(requests + 1);
  });
});

describe('T-53 (REQ-53) announcements are hints', () => {
  it('announcements for another channel, for the local user, or for users outside V change nothing, and call no key, eligibility or R_g function', async () => {
    const [, b] = await inCall([A, B]);
    const spies = [
      vi.spyOn(b.bridge, 'eligibility'),
      vi.spyOn(b.bridge, 'refreshMembership'),
      vi.spyOn(b.bridge, 'encryptFor'),
      ...(['beginVideoFrame', 'sealVideoFrame', 'receiverKey', 'isEligibleParticipant', 'hasVideoKey', 'currentRecipients', 'isCurrentRecipient', 'videoAudience', 'sendingEpoch'] as const).map(m =>
        vi.spyOn(CallKeyManager.prototype, m),
      ),
    ];
    const stops = relay.attempts(B, 'ScreenShareStop').length;
    relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH2, user_id: A });
    relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH, user_id: D });
    relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH, user_id: B, request_id: 'stray' });
    relay.deliverNow(B, { type: 'voice_participants', channel_id: CH, participants: [A, B], screen_sharers: [D] });
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    expect(b.conn.screenParts!.viewers.snapshot()).toEqual([]);
    expect(b.conn.screenParts!.sender).toBeNull();
    // A stray acknowledgment for the local user is answered with a harmless stop (REQ-52).
    expect(relay.attempts(B, 'ScreenShareStop').length).toBe(stops + 1);
    // An announcement for a user in V creates a tile, still without any key call.
    for (const s of spies) s.mockClear();
    relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH, user_id: A });
    expect(spies.every(s => s.mock.calls.length === 0)).toBe(true);
    expect(b.conn.screenParts!.viewers.snapshot().map(s => s.sharerId)).toEqual([A]);
  });

  it('a forged screen_share_started produces a tile that never shows a picture (never rows 8 or 9)', async () => {
    const [, b] = await inCall([A, B]);
    // The relay forges A's share consistently, also in screen_sharers; A
    // never sees the replies that list it, and B's watch is never refused.
    relay.filter = (to, data) => data.type !== 'screen_watch_rejected' && !(to === A && data.type === 'voice_participants');
    relay.shares.set(CH, [A]);
    relay.inject(B, { type: 'screen_share_started', channel_id: CH, user_id: A });
    await relay.settle();
    await watch(b, { id: A } as SC);
    const rows = new Set<number>();
    for (let i = 0; i < 40; i++) {
      await relay.advance(1000);
      rows.add(tileOf(b, A)!.tile.row);
    }
    expect([...rows].some(r => r === 8 || r === 9)).toBe(false);
    expect(rows.has(7)).toBe(true);
    expect(b.surface.draws).toHaveLength(0);
  });

  it('T-38 (screen part): self-check replies with screen_sharers add and remove tiles, end a share the relay no longer lists, and stop one it lists while idle', async () => {
    const [a, b] = await inCall([A, B]);
    await relay.advance(6000);
    // The relay lists a share of A; only B sees these replies for now.
    let hideFromA = true;
    relay.filter = (to, data) => !(hideFromA && to === A && data.type === 'voice_participants');
    relay.shares.set(CH, [A]);
    await relay.advance(30_000);
    expect(b.conn.state.screen.remote.map(t => t.sharerId)).toEqual([A]);
    relay.shares.set(CH, []);
    await relay.advance(30_000);
    expect(b.conn.state.screen.remote).toEqual([]);
    // A is idle and the relay lists a share of A: A sends ScreenShareStop.
    hideFromA = false;
    relay.shares.set(CH, [A]);
    const stops = relay.attempts(A, 'ScreenShareStop').length;
    await relay.advance(30_000);
    expect(relay.attempts(A, 'ScreenShareStop').length).toBe(stops + 1);
    // A shares, then the relay silently forgets the share: A ends it.
    await share(a);
    relay.shares.set(CH, []);
    await relay.advance(30_000);
    expect(a.conn.state.screen.local?.state).toBe('idle');
    expect(a.conn.state.screen.notice).toEqual({ code: 'stopped_by_relay' });
    expect(a.screen.stream.allStopped).toBe(true);
  });
});

describe('A2 (REQ-52 "Stop"): every ScreenShareStop the client sends is recorded', () => {
  /**
   * The confirmation of a stop the connection sent outside the sender (the
   * self-check of REQ-38, or the answer to a stray acknowledgment before any
   * share) can arrive after the user started a new share. Recorded, it only
   * confirms that stop; unrecorded, it would end the new share as "stopped
   * by the relay".
   */
  async function heldConfirmation(a: SC, trigger: () => Promise<void>) {
    const held: Array<Record<string, any>> = [];
    relay.filter = (to, data) => {
      if (to === A && data.type === 'screen_share_stopped' && data.user_id === A) {
        held.push(data);
        return false;
      }
      return true;
    };
    const before = relay.attempts(A, 'ScreenShareStop').length;
    await trigger();
    const sent = relay.attempts(A, 'ScreenShareStop');
    expect(sent.length).toBe(before + 1);
    expect(held).toHaveLength(1);
    expect(held[0].request_id).toBe(sent[sent.length - 1].body.message_id);
    relay.filter = () => true;
    // The user starts a share; then the confirmation arrives.
    await share(a);
    relay.deliverNow(A, held[0]);
    await relay.settle();
    await frames(a, 3);
    expect(a.conn.state.screen.local?.state).toBe('sharing');
    expect(a.conn.state.screen.notice).not.toEqual({ code: 'stopped_by_relay' });
    expect(a.screen.stream.allStopped).toBe(false);
    expect(relay.attempts(A, 'ScreenShareStop').length).toBe(before + 1);
  }

  it('the self-check\'s stop for a share the relay lists while the local share is idle', async () => {
    const [a] = await inCall([A, B]);
    await relay.advance(6000);
    await heldConfirmation(a, async () => {
      relay.shares.set(CH, [A]);
      await relay.advance(30_000);
    });
  });

  it('the stop answering a stray acknowledgment before any share was attempted', async () => {
    const [a] = await inCall([A, B]);
    expect(a.conn.screenParts!.sender).toBeNull();
    await heldConfirmation(a, async () => {
      relay.shares.set(CH, [A]); // the relay holds a share this client never started
      relay.deliverNow(A, { type: 'screen_share_started', channel_id: CH, user_id: A });
      await relay.settle();
    });
  });
});

describe('T-22 (REQ-22) and REQ-52: a disconnect ends the share and every watch', () => {
  it('stops capture and decoding, forgets the relay\'s features, and resumes nothing by itself', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    await frames(a, 3);
    const dec = b.screen.decoders[b.screen.decoders.length - 1];
    relay.closeSocket(B);
    await relay.settle();
    expect(dec.state).toBe('closed');
    expect(b.conn.state.screen.remote).toEqual([]);
    expect(b.conn.state.screen.control.kind).toBe('not_ready');
    // The new socket is open, but its hello has not been processed yet: still "Not ready".
    relay.reopenSocket(B, { hello: false });
    await relay.settle();
    expect(b.conn.state.screen.control.kind).toBe('not_ready');
    relay.sendHello(B);
    await relay.settle();
    await relay.advance(3000);
    expect(b.conn.state.screen.control.kind).toBe('idle');
    expect(tileOf(b, A)?.watching).toBe(false); // not resumed
    const watches = relay.attempts(B, 'ScreenWatch').filter(m => m.handedOff).length;
    expect(watches).toBe(1);
    // The sharer's disconnect ends its share; nothing sent before it goes out after.
    const before = relay.binaryLog.length;
    relay.closeSocket(A);
    await relay.settle();
    expect(a.conn.state.screen.local).toBeNull();
    expect(a.conn.state.screen.notice).toEqual({ code: 'reconnected' });
    expect(a.screen.stream.allStopped).toBe(true);
    expect(a.screen.frames.open.size).toBe(0);
    relay.reopenSocket(A);
    await relay.settle();
    await relay.advance(3000);
    expect(relay.binaryLog.length).toBe(before);
    expect(a.conn.state.screen.control.kind).toBe('idle');
  });
});

describe('RG-SCR-10 (U form): a relay that stops offering screen/1', () => {
  it('a hello without screen/1 ends the share and every watch; a new socket without it makes sharing and watching unavailable; voice continues', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    await frames(a, 3);
    // The same socket's hello no longer lists screen/1.
    relay.sendHello(A, { features: [] });
    relay.sendHello(B, { features: [] });
    await relay.settle();
    expect(a.conn.state.screen.local?.state).toBe('idle');
    expect(a.conn.state.screen.notice).toEqual({ code: 'stopped_by_relay' });
    expect(a.screen.stream.allStopped).toBe(true);
    expect(b.conn.screenParts!.viewers.isWatching(A)).toBe(false);
    expect(a.conn.state.screen.control.kind).toBe('relay_unsupported');
    const ups = relay.binaryLog.length;
    await frames(a, 3);
    expect(relay.binaryLog.length).toBe(ups);
    // A new socket for B, whose hello lacks screen/1, while the relay reports p2p and injects an offer.
    relay.closeSocket(B);
    await relay.settle();
    const sentBefore = relay.sent(B).length;
    relay.reopenSocket(B, { hello: false });
    relay.sendHello(B, { features: ['admission/1'] });
    relay.voiceMode = 'p2p';
    await relay.settle();
    await relay.advance(3000);
    relay.inject(B, { type: 'screen_share_started', channel_id: CH, user_id: A });
    relay.inject(B, { type: 'p2p_signal', channel_id: CH, from: A, signal_data: JSON.stringify({ type: 'screen-sdp', sdp: 'v=0' }) });
    await relay.settle();
    expect(b.conn.state.screen.control.kind).toBe('relay_unsupported');
    expect(tileOf(b, A)?.tile).toEqual({ row: 1, kind: 'viewing_unavailable', cause: 'relay' });
    expect(tileOf(b, A)?.canWatch).toBe(false);
    expect(b.conn.watchScreen(A)).toBe(false);
    expect(relay.sent(B).slice(sentBefore).map(m => m.type).filter(t => /^Screen|P2PSignal|SetVoiceMode/.test(t))).toEqual([]);
    // Voice continues, and no audio frame carries video.
    for (let i = 0; i < 4; i++) a.input.produce(pcmMarker(7, i));
    await relay.settle();
    await relay.advance(400);
    expect(b.output.markers(A).filter(m => m.tag === 7).length).toBeGreaterThan(0);
    for (const m of relay.sent(A, 'SrtpVoicePacket')) expect(decodeWireBase64(m.body.packet_data)![1]).toBe(0x01);
  });
});

describe('T-47 (REQ-47): audio first', () => {
  it('audio captured while video waits is sent at once; at most 65,536 + 16,401 bytes are queued ahead of any audio frame', async () => {
    const [a, b] = await inCall([A, B]);
    await share(a);
    await watch(b, a);
    a.sock.drainPerMs = 120; // under 1 Mbit/s: video backs up
    a.screen.outputSize = () => 60_000;
    let produced = 0;
    const sent0 = relay.sent(A, 'SrtpVoicePacket').length;
    for (let t = 0; t < 3000; t += 20) {
      if (t % 67 < 20) a.screen.source.push(1280, 720);
      a.input.produce(pcmMarker(1, produced++));
      await relay.settle();
      await relay.advance(20);
    }
    expect(relay.sent(A, 'SrtpVoicePacket').length - sent0).toBe(produced);
    expect(relay.binaryLog.filter(m => m.from === A).length).toBeGreaterThan(10);
    expect(Math.max(...a.sock.bufferedBeforeAudio)).toBeLessThanOrEqual(SEND_BUFFER_HIGH + 16_401);
  });
});

describe('T-52 (REQ-52): the connection ends the local share on each stop condition', () => {
  interface Condition {
    readonly name: string;
    /** Run while the socket is still open. */
    readonly prepare?: (a: SC) => Promise<void>;
    readonly trigger: (a: SC) => Promise<void>;
  }
  const conditions: Condition[] = [
    {
      name: 'an E2EE lock',
      trigger: async a => {
        a.bridge.ready = false;
        await relay.advance(1000);
      },
    },
    {
      name: 'eviction',
      trigger: async () => {
        relay.deliverNow(A, { type: 'voice_channel_left', channel_id: CH, user_id: A, reason: 'removed' });
        await relay.settle();
      },
    },
    {
      name: 'a self-check rejoin',
      // The self-check request goes out; its reply is held back.
      prepare: async () => {
        relay.filter = (to, data) => !(to === A && data.type === 'voice_participants');
        await relay.advance(31_000);
      },
      trigger: async () => {
        relay.deliverNow(A, { type: 'voice_participants', channel_id: CH, participants: [B], voice_mode: 'relay', screen_sharers: [A] });
        await relay.settle();
      },
    },
    {
      name: 'a channel switch or unmount',
      trigger: async a => {
        a.conn.disconnect();
        await relay.settle();
      },
    },
  ];

  it('stops every track, the encoder and the frame source, and sends ScreenShareStop exactly when the socket is open', async () => {
    for (const c of conditions) {
      for (const open of [true, false]) {
        const name = `${c.name}, socket ${open ? 'open' : 'closed'}`;
        relay = new FakeVoiceRelay();
        relay.enableScreen();
        const [a, b] = await inCall([A, B]);
        await share(a);
        await watch(b, a);
        await frames(a, 3);
        const { stream, enc, source } = a.screen;
        expect(enc.state, name).toBe('configured');
        expect(relay.binaryLog.filter(m => m.from === A).length, name).toBeGreaterThan(0);
        await c.prepare?.(a);
        expect(a.conn.state.screen.local?.state, name).toBe('sharing');
        const stops = relay.attempts(A, 'ScreenShareStop').length;
        // The socket closed, and its disconnect is not processed yet.
        if (!open) a.sock.connected = false;
        await c.trigger(a);
        expect(stream.allStopped, name).toBe(true);
        expect(enc.state, name).toBe('closed');
        expect(source.closed, name).toBe(true);
        expect(a.screen.frames.open.size, name).toBe(0);
        expect(relay.attempts(A, 'ScreenShareStop').length - stops, name).toBe(open ? 1 : 0);
        expect(a.conn.state.screen.local?.state ?? 'idle', name).toBe('idle');
      }
    }
  });
});

describe('§8.4 refreshes: the panel is notified when a tile changes, not for every frame', () => {
  it('drawing frames notifies only when the tile becomes live; no timer runs for a tile nobody watches', async () => {
    // An unwatched tile shows nothing that changes with time: B is notified
    // exactly as often as in the same call without a share.
    const quiet = async (sharing: boolean): Promise<number> => {
      relay = new FakeVoiceRelay();
      relay.enableScreen();
      const [a, b] = await inCall([A, B]);
      if (sharing) await share(a);
      await relay.advance(1000);
      if (sharing) expect(tileOf(b, A)?.tile.kind).toBe('not_watching');
      let n = 0;
      b.conn.onStateChange = () => {
        n++;
      };
      await relay.advance(20_000);
      return n;
    };
    const withoutShare = await quiet(false);
    expect(await quiet(true)).toBe(withoutShare);
    relay = new FakeVoiceRelay();
    relay.enableScreen();
    const [a, b] = await inCall([A, B]);
    await share(a);
    let notes = 0;
    b.conn.onStateChange = () => {
      notes++;
    };
    // B's self-check replies, which notify by themselves, are held back.
    relay.filter = (to, data) => !(to === B && data.type === 'voice_participants');
    await watch(b, a);
    const watchNotes = notes;
    await frames(a, 30);
    expect(b.surface.draws.length).toBeGreaterThanOrEqual(29);
    expect(tileOf(b, A)?.tile.kind).toBe('live');
    // The tile became live once; the other 29 frames notify nothing.
    expect(notes - watchNotes).toBe(1);
    // A stall of 15 s is shown by the panel's timer, and its end by the next draw.
    relay.screenFilter = () => false;
    const before = notes;
    await relay.advance(15_000);
    expect(tileOf(b, A)?.tile.kind).toBe('stalled');
    expect(notes).toBeGreaterThan(before);
    relay.screenFilter = () => true;
    const stalled = notes;
    a.conn.screenParts!.sender!.onKeyframeRequest(B);
    await frames(a, 3);
    expect(tileOf(b, A)?.tile.kind).toBe('live');
    expect(notes).toBeGreaterThan(stalled);
  });

  it('a ScreenShareStop for a share the client never started answers at most one stray acknowledgment per second', async () => {
    const [, b] = await inCall([A, B]);
    const stops = () => relay.attempts(B, 'ScreenShareStop').length;
    const before = stops();
    for (let i = 0; i < 20; i++) relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH, user_id: B, request_id: `stray-${i}` });
    expect(stops()).toBe(before + 1);
    await relay.advance(1000);
    relay.deliverNow(B, { type: 'screen_share_started', channel_id: CH, user_id: B });
    expect(stops()).toBe(before + 2);
    expect(b.conn.screenParts!.sender).toBeNull();
  });
});
