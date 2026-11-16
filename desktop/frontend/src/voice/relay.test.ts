// @vitest-environment node
/**
 * SPEC-03 U tests of the relay-mode connection (`voice/relay.ts`), over an
 * in-memory relay with the real `CallKeyManager`, AMF1 sealing and jitter
 * buffer, a fake bridge, and fake media carrying marked PCM frames:
 * T-2, T-3, T-4, T-15 (playout sequence and the bounded jitter buffer),
 * T-22 and RG-C116-3 (U form), T-23, T-26 (audio transport), T-27 (storage,
 * IndexedDB and console), T-35, T-37 (U form), T-38 (U form), T-40, T-41,
 * the §8.3 join timeout, and the A1 removals of REQ-39.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { decodeWireBase64, encodeBase64 } from '../attachments/base64';
import { A, B, C, CH, CH2, D, readCall } from './callKeys.testkit';
import { deriveEpochKeys, frameContext, importHkdfKey, sealFrame, MEDIA_KIND_AUDIO } from './mediaFrame';
import {
  FakeMediaOutput,
  FakeVoiceRelay,
  callSecretsIn,
  codecMarker,
  markerOf,
  pcmMarker,
  spyText,
  voiceClient,
  type Marker,
  type VoiceClient,
  type VoiceClientOptions,
} from './relay.testkit';

let relay: FakeVoiceRelay;

beforeEach(() => {
  relay = new FakeVoiceRelay();
});

afterEach(() => {
  for (const s of relay.sockets.values()) s.connected = false;
});

function client(id: string, opts: Partial<VoiceClientOptions> = {}): VoiceClient {
  return voiceClient(relay, id, { channelId: CH, ...opts });
}

/** Clients join one after the other, then keys converge. */
async function inCall(ids: string[], opts: Partial<VoiceClientOptions> = {}): Promise<VoiceClient[]> {
  const out: VoiceClient[] = [];
  for (const id of ids) {
    const c = client(id, opts);
    out.push(c);
    void c.conn.connect();
    await relay.settle();
  }
  await relay.advance(3000);
  return out;
}

/**
 * Filler frames end each burst, so the marked frames never depend on the
 * jitter buffer's release of a lone last frame.
 */
const FILLER = 32_000;
const FILLERS = 2;

/** `from` speaks `count` marked frames and two fillers, which then play out. */
async function talk(from: VoiceClient, tag: number, count: number, first = 0): Promise<void> {
  for (let i = 0; i < count; i++) from.input.produce(pcmMarker(tag, first + i));
  for (let i = 0; i < FILLERS; i++) from.input.produce(pcmMarker(FILLER, i));
  await relay.settle();
  await relay.advance(20 * (count + 10));
}

/** Markers `c` played for `from`, in playout order, fillers left out. Nothing plays twice. */
function heard(c: VoiceClient, from: string): Marker[] {
  return c.output.markers(from).filter(m => m.tag !== FILLER);
}

function range(tag: number, from: number, to: number): Marker[] {
  const out: Marker[] = [];
  for (let n = from; n < to; n++) out.push({ tag, n });
  return out;
}

function labelOf(c: VoiceClient, user: string): string | undefined {
  return c.conn.state.call?.participants.find(p => p.userId === user)?.label;
}

/** The AMF1 bytes of every audio frame `from` handed off. */
function framesOf(from: string): Uint8Array[] {
  return relay.sent(from, 'SrtpVoicePacket').map(m => decodeWireBase64(m.body.packet_data)!);
}

describe('relay-mode call between two connections (REQ-2, REQ-3, REQ-15)', () => {
  it('exchanges keys, plays each other\'s frames in order and attributes them to their sender', async () => {
    const [a, b] = await inCall([A, B]);
    expect(a.conn.state.phase).toBe('joined');
    expect(labelOf(a, B)).toBe('secure');
    expect(labelOf(b, A)).toBe('secure');
    expect(a.conn.state.call?.indicator).toBe('e2ee_not_verified');

    await talk(a, 1, 10);
    await talk(b, 2, 10);
    expect(heard(b, A)).toEqual(range(1, 0, 10));
    expect(heard(a, B)).toEqual(range(2, 0, 10));
    expect(a.output.markers(A)).toEqual([]);

    // Frames leave only as SrtpVoicePacket AMF1 audio, call messages only
    // with a target and the acv1: prefix (REQ-1, REQ-2).
    for (const m of relay.log) {
      expect(['JoinVoiceChannel', 'VoiceKeyExchange', 'SrtpVoicePacket', 'GetVoiceParticipants', 'VoiceSpeakingState']).toContain(m.type);
      if (m.type === 'VoiceKeyExchange') {
        expect(typeof m.body.target_user_id).toBe('string');
        expect(m.body.wrapped_key.startsWith('acv1:')).toBe(true);
        expect(m.body.sender_ssrc).toBe(0);
        expect(m.body.key_generation).toBe(0);
      }
    }
    const frames = framesOf(A);
    expect(frames.length).toBe(10 + FILLERS);
    for (const f of frames) {
      expect(f[0]).toBe(0x01); // AMF1
      expect(f[1]).toBe(0x01); // audio
    }
  });

  it('T-15: the authenticated CTR is the playout sequence: frames reordered in transit play in CTR order', async () => {
    const [a, b] = await inCall([A, B]);
    const held: Array<Record<string, unknown>> = [];
    relay.filter = (to, data) => {
      if (to === B && data.type === 'srtp_voice_packet') {
        held.push(data);
        return false;
      }
      return true;
    };
    for (let i = 0; i < 6; i++) a.input.produce(pcmMarker(3, i));
    for (let i = 0; i < FILLERS; i++) a.input.produce(pcmMarker(FILLER, i));
    await relay.settle();
    relay.filter = () => true;
    for (const i of [0, 2, 1, 4, 3, 5, 6, 7]) relay.inject(B, held[i]);
    await relay.settle();
    await relay.advance(400);
    expect(heard(b, A)).toEqual(range(3, 0, 6));
  });

  it('decodes Opus frames (codec 0x01) where a decoder exists, in CTR order', async () => {
    const outA = new FakeMediaOutput();
    outA.opus = 'echo';
    const a = client(A, { output: outA });
    void a.conn.connect();
    await relay.settle();
    const b = client(B);
    void b.conn.connect();
    await relay.settle();
    await relay.advance(3000);
    for (let i = 0; i < 5; i++) b.input.produce(codecMarker(0x01, 4, i));
    for (let i = 0; i < FILLERS; i++) b.input.produce(codecMarker(0x01, FILLER, i));
    await relay.settle();
    await relay.advance(400);
    expect(heard(a, B)).toEqual(range(4, 0, 5));
    expect(outA.decodersCreated).toBe(1);
  });
});

describe('T-15 (REQ-15) the jitter buffer fed with authenticated CTRs is bounded', () => {
  /** A's playout pipeline for `from` (its jitter buffer). */
  const jitterOf = (c: VoiceClient, from: string) => (c.conn as any).pipelines.get(from).jitter as { buffered: number };
  /** Set the CTR `c` seals its next audio frame under (a modified client may choose any). */
  const setCtr = (c: VoiceClient, ctr: number) => {
    (c.conn as any).call.mgr.ctrNext = ctr;
  };

  it('a sender jumping its CTR 1000 ahead per frame leaves at most 20 frames buffered, which drain at one per tick', async () => {
    const [a, b] = await inCall([A, B]);
    let most = 0;
    for (let i = 0; i < 2000; i++) {
      setCtr(b, 1_000_000 + i * 1000);
      b.input.produce(pcmMarker(7, i));
      if (i % 100 === 99) {
        await relay.settle();
        most = Math.max(most, jitterOf(a, B).buffered);
      }
    }
    await relay.settle();
    expect(most).toBeLessThanOrEqual(20);
    expect(jitterOf(a, B).buffered).toBe(20);
    // Every authenticated frame was accepted, so only the bound limited the buffer.
    expect(relay.deliveries.filter(d => d.to === A && d.data.type === 'srtp_voice_packet')).toHaveLength(2000);
    await relay.advance(20 * 25);
    expect(jitterOf(a, B).buffered).toBe(0);
    // The newest 20 play, in CTR order, each once.
    expect(heard(a, B)).toEqual(range(7, 1980, 2000));
  });

  it('frames lost in transit add no lasting playout latency: the gap is skipped, not played out one counter per tick', async () => {
    const [a, b] = await inCall([A, B]);
    const sentAt = new Map<number, number>();
    const playedAt = new Map<number, number>();
    const play = a.output.play.bind(a.output);
    a.output.play = (userId, pcm) => {
      play(userId, pcm);
      const m = markerOf(pcm);
      if (m.tag === 4) playedAt.set(m.n, relay.clock.now());
    };
    let dropping = false;
    relay.filter = (to, data) => !(dropping && to === A && data.type === 'srtp_voice_packet');
    for (let i = 0; i < 300; i++) {
      dropping = i >= 50 && i < 150; // the relay drops 2 s of B's audio to A
      sentAt.set(i, relay.clock.now());
      b.input.produce(pcmMarker(4, i));
      await relay.advance(20);
    }
    await relay.advance(1000);
    expect(heard(a, B)).toEqual([...range(4, 0, 50), ...range(4, 150, 300)]);
    const latency = (n: number) => playedAt.get(n)! - sentAt.get(n)!;
    const before = latency(40);
    // At most targetDelay (2) frames more than before the gap, and no growth afterwards.
    for (const n of [150, 151, 160, 200, 250, 299]) expect(latency(n)).toBeLessThanOrEqual(before + 2 * 20);
    expect(latency(299)).toBeLessThanOrEqual(latency(160));
  });

  it('a duplicate or older CTR never plays, before or after a gap', async () => {
    const [a, b] = await inCall([A, B]);
    for (let i = 0; i < 8; i++) {
      if (i === 4) setCtr(b, 1000); // a gap of 996 counters
      b.input.produce(pcmMarker(6, i));
      await relay.advance(20);
    }
    const delivered = relay.deliveries.filter(d => d.to === A && d.data.type === 'srtp_voice_packet').map(d => d.data);
    expect(delivered).toHaveLength(8);
    await relay.advance(1000);
    expect(heard(a, B)).toEqual(range(6, 0, 8));
    // Replays of every frame play nothing (the replay window), and neither
    // does a new frame under an unused CTR inside the replay window but older
    // than the last one played (the jitter buffer drops it as late).
    for (const d of delivered) relay.inject(A, d);
    setCtr(b, 990);
    b.input.produce(pcmMarker(6, 99));
    await relay.settle();
    await relay.advance(1000);
    expect(heard(a, B)).toEqual(range(6, 0, 8));
  });

  /**
   * A2 (§14.1): a holder of B's epoch g (a departed member with the relay)
   * pushes A's jitter buffer to CTR 2^47 under g; B's own counters under
   * g+1 are far lower. The first frame under g+1 resets the buffer before it
   * is pushed, so B is heard again. Emulated here by B itself sealing under
   * g at 2^47, as a modified client could, then returning to low counters
   * once it has rotated (the per-epoch replay window accepts them).
   */
  for (const codec of ['pcm', 'opus'] as const) {
    it(`A2: the first frame under a sender's newer epoch with a CTR below the highest received resets the jitter buffer, so it plays (${codec})`, async () => {
      const outA = new FakeMediaOutput();
      if (codec === 'opus') outA.opus = 'echo';
      const a = client(A, { output: outA });
      void a.conn.connect();
      await relay.settle();
      const b = client(B);
      void b.conn.connect();
      await relay.settle();
      await relay.advance(3000);
      const marker = (tag: number, n: number) => (codec === 'opus' ? codecMarker(0x01, tag, n) : pcmMarker(tag, n));
      const epochOf = (c: VoiceClient) => (c.conn as any).call.mgr.sendingEpoch() as number;
      const g = epochOf(b);
      setCtr(b, 2 ** 47);
      for (let i = 0; i < 5; i++) b.input.produce(marker(8, i));
      for (let i = 0; i < FILLERS; i++) b.input.produce(marker(FILLER, i));
      await relay.settle();
      await relay.advance(400);
      expect(heard(a, B)).toEqual(range(8, 0, 5));
      expect((jitterOf(a, B) as unknown as { highestReceived: number }).highestReceived).toBeGreaterThanOrEqual(2 ** 47);
      // C joins: B rotates to g+1 and seals under it with its low counters again.
      const c = client(C);
      void c.conn.connect();
      await relay.settle();
      await relay.advance(3000);
      expect(epochOf(b)).toBeGreaterThan(g);
      setCtr(b, 100);
      for (let i = 0; i < 5; i++) b.input.produce(marker(9, i));
      for (let i = 0; i < FILLERS; i++) b.input.produce(marker(FILLER, 10 + i));
      await relay.settle();
      await relay.advance(400);
      expect(heard(a, B)).toEqual([...range(8, 0, 5), ...range(9, 0, 5)]);
      // Within one epoch nothing changes: a lower CTR under g+1 still never plays.
      setCtr(b, 50);
      b.input.produce(marker(9, 99));
      await relay.settle();
      await relay.advance(400);
      expect(heard(a, B)).toEqual([...range(8, 0, 5), ...range(9, 0, 5)]);
    });
  }

  /**
   * A2 (§14.1) on the Opus path: the frame that opened g+1 can be dropped
   * before it reaches the jitter buffer, with the decoder that held it:
   * more than `PENDING_DECODES_MAX` (50) outputs pending (the relay bursts
   * B's frames), `decode` throwing, or the decoder's error callback. The
   * reset still happens, on the first frame under g+1 that is pushed.
   */
  for (const fault of ['overflow', 'throw', 'error'] as const) {
    it(`A2: the reset after forged CTRs under g happens even when the frame that opened g+1 is dropped with its Opus decoder (${fault})`, async () => {
      const outA = new FakeMediaOutput();
      outA.opus = 'echo';
      const a = client(A, { output: outA });
      void a.conn.connect();
      await relay.settle();
      const b = client(B);
      void b.conn.connect();
      await relay.settle();
      await relay.advance(3000);
      const epochOf = (c: VoiceClient) => (c.conn as any).call.mgr.sendingEpoch() as number;
      const g = epochOf(b);
      // The forged frames under g, far ahead (emulated by B sealing them itself).
      setCtr(b, 2 ** 47);
      for (let i = 0; i < 5; i++) b.input.produce(codecMarker(0x01, 8, i));
      for (let i = 0; i < FILLERS; i++) b.input.produce(codecMarker(0x01, FILLER, i));
      await relay.settle();
      await relay.advance(400);
      expect(heard(a, B)).toEqual(range(8, 0, 5));
      const c = client(C);
      void c.conn.connect();
      await relay.settle();
      await relay.advance(3000);
      expect(epochOf(b)).toBeGreaterThan(g);
      // B's first frames under g+1, with its own low counters, are lost with the decoder.
      setCtr(b, 100);
      const decodersBefore = outA.decodersClosed;
      const lost = fault === 'overflow' ? 51 : 1;
      outA.opusFault = () => (fault === 'overflow' ? 'hold' : fault);
      for (let i = 0; i < lost; i++) b.input.produce(codecMarker(0x01, 10, i));
      await relay.settle();
      outA.opusFault = null;
      expect(outA.decodersClosed).toBe(decodersBefore + 1);
      // Every later frame under g+1 plays.
      for (let i = 0; i < 5; i++) b.input.produce(codecMarker(0x01, 9, i));
      for (let i = 0; i < FILLERS; i++) b.input.produce(codecMarker(0x01, FILLER, 10 + i));
      await relay.settle();
      await relay.advance(400);
      expect(heard(a, B)).toEqual([...range(8, 0, 5), ...range(9, 0, 5)]);
    });
  }

  it('the last frame of a talk spurt plays without waiting for the next spurt', async () => {
    const [a, b] = await inCall([A, B]);
    for (let i = 0; i < 5; i++) b.input.produce(pcmMarker(5, i));
    await relay.settle();
    await relay.advance(200);
    expect(heard(a, B)).toEqual(range(5, 0, 5));
    expect(jitterOf(a, B).buffered).toBe(0);
  });
});

describe('T-2 (REQ-2) no media is sent', () => {
  it('before voice_channel_joined, while the first epoch key is being derived, and while muted from construction', async () => {
    let joinedHeld = true;
    relay.filter = (to, data) => !(joinedHeld && to === A && data.type === 'voice_channel_joined');
    const a = client(A, { muted: true });
    void a.conn.connect();
    await relay.settle();
    expect(a.input.mutedAtStart).toEqual([true]); // REQ-5: applied before capture
    // Before voice_channel_joined (even unmuted).
    a.conn.setMuted(false);
    a.input.produce(pcmMarker(1, 0));
    a.conn.setMuted(true);
    await relay.settle();
    expect(a.sock.attempts.filter(m => m.type === 'SrtpVoicePacket')).toHaveLength(0);

    // Right at voice_channel_joined, before epoch 0's keys are derived.
    joinedHeld = false;
    a.sock.on('voice_channel_joined', () => {
      a.conn.setMuted(false);
      a.input.produce(pcmMarker(1, 1));
    });
    relay.inject(A, { type: 'voice_channel_joined', channel_id: CH, participants: [A], voice_mode: 'relay' });
    await relay.settle();
    expect(a.sock.attempts.filter(m => m.type === 'SrtpVoicePacket')).toHaveLength(0);

    // Keys ready, muted again: nothing; unmuted: sent.
    a.conn.setMuted(true);
    a.input.produce(pcmMarker(1, 2));
    await relay.settle();
    expect(a.sock.attempts.filter(m => m.type === 'SrtpVoicePacket')).toHaveLength(0);
    a.conn.setMuted(false);
    a.input.produce(pcmMarker(1, 3));
    await relay.settle();
    expect(a.sock.attempts.filter(m => m.type === 'SrtpVoicePacket')).toHaveLength(1);
  });

  it('while sending is suspended after a departure, and nothing under the departed member\'s epoch afterwards', async () => {
    const [a, , c] = await inCall([A, B, C]);
    const epochBefore = a.conn.state.call!.sendingEpoch!;
    // B leaves: A suspends in this turn (REQ-17) and creates a new epoch.
    a.sock.on('voice_peer_left', () => a.input.produce(pcmMarker(5, 0)));
    relay.dropFromVoice(B);
    await relay.settle();
    await relay.advance(3000);
    await talk(a, 5, 1, 1);
    const frames = framesOf(A).map(f => f[2] >> 4); // KID < 8: the config byte's K bits
    expect(frames.length).toBe(1 + FILLERS);
    expect(frames.every(kid => kid > epochBefore)).toBe(true);
    expect(heard(c, A).map(m => m.n)).toEqual([1]);
  });
});

describe('T-3 (REQ-3) and T-26 (REQ-26) only authenticated frames from eligible participants are played', () => {
  it('discards every failure of §6.2.6, other formats and kinds, legacy voice_packet, unknown codecs and Opus without a decoder', async () => {
    const [a, b] = await inCall([A, B]);
    relay.filter = (to, data) => !(to === A && data.type === 'srtp_voice_packet');
    b.input.produce(pcmMarker(9, 0));
    b.input.produce(codecMarker(0x01, 9, 1)); // Opus: A has no decoder
    b.input.produce(codecMarker(0x05, 9, 2)); // reserved codec: never PCM
    b.input.produce(pcmMarker(9, 3));
    for (let i = 0; i < FILLERS; i++) b.input.produce(pcmMarker(FILLER, i));
    await relay.settle();
    relay.filter = () => true;
    const [genuine, opus, reserved, ...rest] = relay.sent(B, 'SrtpVoicePacket').map(m => m.body.packet_data as string);
    const g = decodeWireBase64(genuine)!;
    const mutate = (fn: (x: Uint8Array) => Uint8Array) => encodeBase64(fn(Uint8Array.from(g)));
    const variants: Array<Record<string, unknown>> = [
      { from: B, channel_id: CH2, packet_data: genuine }, // another channel
      { from: A, channel_id: CH, packet_data: genuine }, // the local user
      { from: D, channel_id: CH, packet_data: genuine }, // not in V
      { from: B, channel_id: CH, packet_data: '@@@@' }, // not base64
      { from: B, channel_id: CH, packet_data: 'A'.repeat(5468) }, // longer than any 4096-byte frame
      { from: B, channel_id: CH, packet_data: 7 }, // not a string
      { from: B, channel_id: CH, packet_data: mutate(x => x.subarray(0, 19)) }, // short
      // T-26: formats 0x00, 0x02 and 0xFF; kinds 0x00, 0x02 (video on the audio path) and 0x03.
      ...[0x00, 0x02, 0xff].map(fmt => ({ from: B, channel_id: CH, packet_data: mutate(x => { x[0] = fmt; return x; }) })),
      ...[0x00, 0x02, 0x03].map(kind => ({ from: B, channel_id: CH, packet_data: mutate(x => { x[1] = kind; return x; }) })),
      {
        from: B, channel_id: CH, packet_data: mutate(x => {
          // non-minimal CTR: Y = 1 with one byte for a CTR below 8
          const cfg = x[2];
          return Uint8Array.from([x[0], x[1], (cfg & 0xf0) | 0x08, cfg & 0x07, ...x.subarray(3)]);
        }),
      },
      { from: B, channel_id: CH, packet_data: mutate(x => { x[2] = (x[2] & 0x8f) | 0x70; return x; }) }, // unknown KID 7
      { from: B, channel_id: CH, packet_data: mutate(x => { x[x.length - 1] ^= 1; return x; }) }, // tag flip
      { from: B, channel_id: CH, packet_data: mutate(x => { x[5] ^= 0x40; return x; }) }, // ciphertext flip
      { from: B, channel_id: CH, packet_data: opus },
      { from: B, channel_id: CH, packet_data: reserved },
    ];
    for (const v of variants) relay.inject(A, { type: 'srtp_voice_packet', timestamp: 0, ...v });
    // A legacy relay-readable frame containing PCM (REQ-3, REQ-4).
    relay.inject(A, { type: 'voice_packet', from: B, channel_id: CH, encrypted_audio: Array.from(pcmMarker(9, 3)), sequence: 1 });
    await relay.settle();
    await relay.advance(1000);
    expect(a.output.played).toHaveLength(0);
    const bView = a.conn.state.call!.participants.find(p => p.userId === B)!;
    expect(bView.notes.outdatedApp).toBe(true);
    expect(bView.label).toBe('secure'); // legacy evidence never changes eligibility (REQ-4)

    // The genuine PCM frames still play, each once (positive control): the
    // duplicate fails the replay window, the authenticated Opus and reserved
    // frames leave silent gaps.
    for (const pd of [genuine, genuine, ...rest]) relay.inject(A, { type: 'srtp_voice_packet', from: B, channel_id: CH, packet_data: pd, timestamp: 0 });
    await relay.settle();
    await relay.advance(400);
    expect(heard(a, B)).toEqual([{ tag: 9, n: 0 }, { tag: 9, n: 3 }]);
  });
});

describe('T-4 (REQ-4) raw keys are never used', () => {
  it('a raw key under B\'s id installs nothing; B keeps its place, gets keys after its hello, and its hello clears the note', async () => {
    const a = client(A);
    void a.conn.connect();
    await relay.settle();
    // Hold B's call messages to A until the raw key has arrived.
    let holdB = true;
    relay.filter = (to, data) => !(holdB && to === A && data.type === 'voice_key_exchange' && data.from === B);
    const b = client(B);
    void b.conn.connect();
    await relay.settle();

    const raw = crypto.getRandomValues(new Uint8Array(32));
    relay.inject(A, { type: 'voice_key_exchange', from: B, channel_id: CH, wrapped_key: encodeBase64(raw), sender_ssrc: 0, key_generation: 0, timestamp: 0 });
    // Frames under that key: legacy layout, and AMF1 with it as the base key.
    relay.inject(A, { type: 'voice_packet', from: B, channel_id: CH, encrypted_audio: Array.from(pcmMarker(7, 0)), sequence: 0 });
    const keys = await deriveEpochKeys(await importHkdfKey(Uint8Array.from(raw)), 0, 'encrypt');
    for (let ctr = 0; ctr < 4; ctr++) {
      const frame = await sealFrame(MEDIA_KIND_AUDIO, keys, ctr, frameContext(CH, B, new Uint8Array(16).fill(3)), pcmMarker(7, ctr + 1));
      relay.inject(A, { type: 'srtp_voice_packet', from: B, channel_id: CH, packet_data: encodeBase64(frame), timestamp: 0 });
    }
    await relay.settle();
    await relay.advance(500);
    expect(a.output.played).toHaveLength(0);
    let bView = a.conn.state.call!.participants.find(p => p.userId === B)!;
    expect(bView.notes.outdatedApp).toBe(true);
    expect(bView.ineligibleReason).toBeNull();

    // B's hello (retransmitted) now reaches A: accepted, the note clears, and A sends B its key.
    holdB = false;
    await relay.advance(9000);
    bView = a.conn.state.call!.participants.find(p => p.userId === B)!;
    expect(bView.notes.outdatedApp).toBe(false);
    const keysToB = relay.sent(A, 'VoiceKeyExchange').filter(m => m.body.target_user_id === B).map(m => readCall(m.body.wrapped_key));
    expect(keysToB.some(m => m.type === 'call_key')).toBe(true);
    await talk(b, 8, 4);
    expect(heard(a, B)).toEqual(range(8, 0, 4));
  });
});

describe('T-22 and RG-C116-3 (REQ-22, REQ-37) reconnect', () => {
  it('a disconnect ends the call and erases it; the rejoin uses a new instance, and nothing from before is sent after it', async () => {
    const [a, b] = await inCall([A, B]);
    await talk(a, 1, 3);
    const firstInst = a.conn.state.instanceId!;
    a.conn.setMuted(true);

    relay.closeSocket(A);
    await relay.settle();
    expect(a.conn.state.phase).toBe('reconnecting');
    expect(a.conn.state.reconnecting).toBe(true);
    expect(a.conn.state.call).toBeNull();
    expect(a.input.active).toBe(false); // capture stopped
    const attemptsWhileDown = a.sock.attempts.length;
    a.input.produce(pcmMarker(1, 99));
    await relay.advance(20_000); // no retransmission timer survives the call
    expect(a.sock.attempts.length).toBe(attemptsWhileDown);

    const logAtReopen = relay.log.length;
    relay.reopenSocket(A);
    await relay.settle();
    await relay.advance(3000);
    expect(a.conn.state.phase).toBe('joined');
    expect(a.conn.state.reconnecting).toBe(false);
    const secondInst = a.conn.state.instanceId!;
    expect(secondInst).not.toBe(firstInst);
    // Every call message after the reconnect names the new instance.
    const after = relay.log.slice(logAtReopen).filter(m => m.from === A && m.type === 'VoiceKeyExchange');
    expect(after.length).toBeGreaterThan(0);
    for (const m of after) expect(readCall(m.body.wrapped_key).inst).toBe(secondInst);
    expect(relay.log.slice(logAtReopen).filter(m => m.from === A)[0].type).toBe('JoinVoiceChannel');
    // Still muted after the rejoin (REQ-5): nothing until unmuted.
    expect(a.input.mutedAtStart).toEqual([false, true]);
    const before = framesOf(A).length;
    a.input.produce(pcmMarker(1, 50));
    await relay.settle();
    expect(framesOf(A).length).toBe(before);
    a.conn.setMuted(false);
    await talk(a, 1, 3, 10);
    expect(heard(b, A)).toEqual([...range(1, 0, 3), ...range(1, 10, 13)]);
  });

  it('T-35: a sender that restarts at CTR 0 without voice_peer_left is heard after its new key, because its pipeline was reset', async () => {
    const [a, b] = await inCall([A, B]);
    await talk(b, 2, 12);
    expect(heard(a, B)).toEqual(range(2, 0, 12));
    // B's socket closes, but A never hears that B left or rejoined.
    relay.filter = (to, data) => !(to === A && (data.type === 'voice_peer_left' || data.type === 'voice_peer_joined'));
    relay.closeSocket(B);
    await relay.settle();
    relay.reopenSocket(B);
    await relay.settle();
    await relay.advance(3000);
    expect(labelOf(a, B)).toBe('secure');
    await talk(b, 3, 5);
    expect(heard(a, B)).toEqual([...range(2, 0, 12), ...range(3, 0, 5)]);
    // B's second call starts at CTR 0 again.
    const ctrs = framesOf(B).slice(12 + FILLERS, 12 + FILLERS + 5).map(f => f[2] & 0x0f);
    expect(ctrs).toEqual([0, 1, 2, 3, 4]);
  });
});

describe('T-23 (REQ-23) secure voice needs the E2EE manager', () => {
  it('does not join, capture or send while the bridge is not ready, and shows "unavailable"', async () => {
    const a = client(A);
    a.bridge.ready = false;
    void a.conn.connect();
    await relay.settle();
    await relay.advance(15_000);
    expect(a.conn.state.phase).toBe('unavailable');
    expect(relay.sent(A)).toHaveLength(0);
    expect(a.input.starts).toBe(0);
  });

  it('without a bridge or a node for the call, nothing is joined either', async () => {
    const a = voiceClient(relay, A, { channelId: CH, nodeId: null });
    void a.conn.connect();
    await relay.settle();
    expect(a.conn.state.phase).toBe('unavailable');
    expect(relay.sent(A)).toHaveLength(0);
  });
});

describe('§8.3 join timeout', () => {
  it('no voice_channel_joined within 10 s tears the call down and leaves at the relay', async () => {
    const b = client(B);
    void b.conn.connect();
    await relay.settle();
    // The relay processes A's join; only its reply to A is lost.
    relay.filter = (to, data) => !(to === A && data.type === 'voice_channel_joined');
    const a = client(A);
    void a.conn.connect();
    await relay.settle();
    expect(relay.participants(CH)).toContain(A);
    await relay.advance(9900);
    expect(a.conn.state.phase).toBe('connecting');
    expect(relay.sent(A, 'LeaveVoiceChannel')).toHaveLength(0);
    await relay.advance(200);
    expect(a.conn.state.phase).toBe('failed');
    expect(a.conn.state.call).toBeNull();
    expect(a.input.active).toBe(false);
    // Exactly one LeaveVoiceChannel: the relay and B no longer list A.
    expect(relay.sent(A, 'LeaveVoiceChannel')).toHaveLength(1);
    expect(relay.participants(CH)).not.toContain(A);
    expect(b.conn.state.call!.participants.map(p => p.userId)).not.toContain(A);
    // The relay's reply has no reason and is ignored (REQ-40); closing the
    // panel afterwards sends no second leave.
    expect(a.conn.state.phase).toBe('failed');
    a.conn.disconnect();
    expect(relay.sent(A, 'LeaveVoiceChannel')).toHaveLength(1);
  });
});

describe('T-38 (REQ-38) self-check, U form', () => {
  it('rejoins with a new instance when the relay silently dropped the local user, at most once per 30 s', async () => {
    // A joined at about 0 s; inCall ends at about 3 s.
    const [a, b] = await inCall([A, B]);
    const inst0 = a.conn.state.instanceId;
    relay.dropFromVoice(A); // another socket of A closed (C154): only B is told
    await relay.settle();
    await relay.advance(2500); // the self-check 5 s after the join finds A missing
    const inst1 = a.conn.state.instanceId;
    expect(inst1).not.toBe(inst0);
    expect(a.conn.state.phase).toBe('joined');
    expect(relay.participants(CH)).toContain(A);
    await relay.advance(1000);
    await talk(a, 6, 3);
    expect(heard(b, A)).toEqual(range(6, 0, 3));

    // Dropped again at once: the new call's check 5 s after its join finds
    // A missing, but the last rejoin was less than 30 s ago.
    relay.dropFromVoice(A);
    await relay.settle();
    await relay.advance(5000);
    expect(a.conn.state.instanceId).toBe(inst1);
    // The check after that comes more than 30 s after the rejoin.
    await relay.advance(30_000);
    expect(a.conn.state.instanceId).not.toBe(inst1);
  });

  it('shows "Reconnecting secure voice…" while the rejoin waits for its join', async () => {
    const [a] = await inCall([A, B]);
    relay.dropFromVoice(A);
    let joinedHeld = true;
    relay.filter = (to, data) => !(joinedHeld && to === A && data.type === 'voice_channel_joined');
    await relay.advance(2500); // the self-check at 5 s rejoins
    expect(a.conn.state.phase).toBe('connecting');
    expect(a.conn.state.reconnecting).toBe(true);
    joinedHeld = false;
    relay.inject(A, { type: 'voice_channel_joined', channel_id: CH, participants: relay.participants(CH), voice_mode: 'relay' });
    await relay.settle();
    expect(a.conn.state.phase).toBe('joined');
    expect(a.conn.state.reconnecting).toBe(false);
  });

  it('reconciles V: a dropped voice_peer_joined is repaired by the next self-check', async () => {
    const [a] = await inCall([A, B]);
    relay.filter = (to, data) => !(to === A && data.type === 'voice_peer_joined');
    const d = client(D);
    void d.conn.connect();
    await relay.settle();
    expect(a.conn.state.call!.participants.map(p => p.userId)).toEqual([B]);
    await relay.advance(35_000);
    expect(a.conn.state.call!.participants.map(p => p.userId).sort()).toEqual([B, D].sort());
  });

  it('a voice_peer_joined or voice_peer_left that reaches the socket before its own join reply is applied right after the reply', async () => {
    // The real relay takes the reply's list when it adds the user and
    // handles connections concurrently, so a peer's join or departure can
    // overtake the reply (seen with three simultaneous joins).
    const [b] = await inCall([B]);
    let held: Record<string, any> | null = null;
    relay.filter = (to, data) => {
      if (to === A && data.type === 'voice_channel_joined' && !held) {
        held = data;
        return false;
      }
      return true;
    };
    const a = client(A);
    void a.conn.connect();
    await relay.settle();
    expect(held).not.toBeNull();
    const d = client(D);
    void d.conn.connect();
    await relay.settle();
    b.conn.disconnect();
    await relay.settle();
    expect(relay.deliveries.filter(x => x.to === A).map(x => x.data.type)).toEqual(expect.arrayContaining(['voice_peer_joined', 'voice_peer_left']));
    relay.deliverNow(A, held!);
    await relay.settle();
    // The reply listed B only; D joined and B left after it was taken.
    expect(a.conn.state.call!.participants.map(p => p.userId)).toEqual([D]);
  });

  it('ignores a voice_participants reply it did not ask for', async () => {
    const [a] = await inCall([A, B]);
    const inst = a.conn.state.instanceId;
    relay.inject(A, { type: 'voice_participants', channel_id: CH, participants: [B] });
    await relay.settle();
    expect(a.conn.state.instanceId).toBe(inst);
    expect(a.conn.state.call!.participants.map(p => p.userId)).toEqual([B]);
  });
});

describe('T-40 (REQ-40) eviction', () => {
  it('ignores voice_channel_left without a reason, for another channel, or before the join, and ends the call on the exact form', async () => {
    let joinedHeld = true;
    relay.filter = (to, data) => !(joinedHeld && to === A && data.type === 'voice_channel_joined');
    const a = client(A);
    void a.conn.connect();
    await relay.settle();
    // Before the instance's voice_channel_joined.
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: A, reason: 'removed' });
    await relay.settle();
    expect(a.conn.state.phase).toBe('connecting');
    joinedHeld = false;
    relay.inject(A, { type: 'voice_channel_joined', channel_id: CH, participants: [A], voice_mode: 'relay' });
    await relay.settle();
    const b = client(B);
    void b.conn.connect();
    await relay.settle();
    await relay.advance(3000);
    const inst = a.conn.state.instanceId;
    // A rebuild's reply (no reason), another channel, another user.
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: A });
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH2, user_id: A, reason: 'removed' });
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: B, reason: 'removed' });
    await relay.settle();
    expect(a.conn.state.phase).toBe('joined');
    expect(a.conn.state.instanceId).toBe(inst);
    // The valid form.
    relay.inject(A, { type: 'voice_channel_left', channel_id: CH, user_id: A.toUpperCase(), reason: 'removed' });
    await relay.settle();
    expect(a.conn.state.phase).toBe('removed');
    expect(a.conn.state.call).toBeNull();
    expect(a.input.active).toBe(false);
    const sent = relay.sent(A).length;
    a.input.produce(pcmMarker(1, 1));
    await relay.advance(60_000);
    expect(relay.sent(A).length).toBe(sent); // no frame, hello or self-check after eviction
    // Leaving after an eviction sends no LeaveVoiceChannel.
    a.conn.disconnect();
    expect(relay.sent(A, 'LeaveVoiceChannel')).toHaveLength(0);
  });
});

describe('T-41 (REQ-41) relay mode reports only drive a note', () => {
  it('voice_mode_changed, voice_mode, the join reply and the self-check reply saying p2p change nothing but the note', async () => {
    relay.voiceMode = 'p2p'; // the join reply says p2p
    const [a, b] = await inCall([A, B]);
    expect(a.conn.state.relayReportsP2p).toBe(true);
    const inst = a.conn.state.instanceId;
    relay.voiceMode = 'relay';
    relay.inject(A, { type: 'voice_mode_changed', channel_id: CH, voice_mode: 'relay', changed_by: B });
    await relay.settle();
    expect(a.conn.state.relayReportsP2p).toBe(false);

    relay.inject(A, { type: 'voice_mode_changed', channel_id: CH, voice_mode: 'p2p', changed_by: C });
    await relay.settle();
    expect(a.conn.state.relayReportsP2p).toBe(true);
    // The per-participant note: B has sent no call message since the report.
    expect(a.conn.state.call!.participants.find(p => p.userId === B)!.notes.olderAppP2p).toBe(true);
    relay.inject(A, { type: 'voice_mode', channel_id: CH, voice_mode: 'p2p' });
    relay.voiceMode = 'p2p';
    await relay.advance(36_000); // a self-check reply says p2p too
    await talk(b, 5, 4);
    expect(heard(a, B)).toEqual(range(5, 0, 4));
    expect(a.conn.state.instanceId).toBe(inst);
    expect(a.conn.state.phase).toBe('joined');
    // A report for another channel is not about C.
    relay.inject(A, { type: 'voice_mode_changed', channel_id: CH2, voice_mode: 'relay' });
    await relay.settle();
    expect(a.conn.state.relayReportsP2p).toBe(true);

    relay.voiceMode = 'relay';
    relay.inject(A, { type: 'voice_mode', channel_id: CH, voice_mode: 'relay' });
    await relay.settle();
    expect(a.conn.state.relayReportsP2p).toBe(false);
    expect(a.conn.state.instanceId).toBe(inst);
    // Nothing but voice traffic was ever sent: no mode change, no signaling.
    expect(new Set(relay.log.map(m => m.type))).toEqual(new Set(['JoinVoiceChannel', 'VoiceKeyExchange', 'SrtpVoicePacket', 'GetVoiceParticipants']));
  });

  it('registers no listener for P2P signaling (REQ-39)', async () => {
    const [a] = await inCall([A, B]);
    const events = a.sock.listenedEvents();
    for (const e of ['p2p_signal', 'voice_offer', 'voice_answer', 'voice_ice_candidate']) expect(events).not.toContain(e);
    a.conn.disconnect();
    expect(a.sock.listenedEvents()).toEqual([]);
  });
});

describe('deafen and local leave', () => {
  it('a deafened user gets no playback; frames keep their place and play again after undeafening', async () => {
    const [a, b] = await inCall([A, B], { deafened: false });
    b.conn.setDeafened(true);
    expect(b.output.deafened).toBe(true);
    await talk(a, 1, 5);
    expect(b.output.played).toHaveLength(0);
    b.conn.setDeafened(false);
    await talk(a, 1, 5, 5);
    expect(heard(b, A)).toEqual(range(1, 5, 10));
  });

  it('a deafened user is muted from construction', async () => {
    const a = client(A, { deafened: true });
    void a.conn.connect();
    await relay.settle();
    expect(a.input.mutedAtStart).toEqual([true]);
    expect(a.output.deafened).toBe(true);
  });

  it('local leave sends LeaveVoiceChannel, stops capture and erases the call', async () => {
    const [a, b] = await inCall([A, B]);
    a.conn.disconnect();
    expect(relay.sent(A, 'LeaveVoiceChannel')).toHaveLength(1);
    expect(a.conn.state.phase).toBe('left');
    expect(a.conn.state.call).toBeNull();
    expect(a.input.active).toBe(false);
    expect(a.output.closed).toBe(1);
    await relay.settle();
    expect(b.conn.state.call!.participants).toEqual([]);
  });
});

describe('T-27 (REQ-27) nothing reaches storage, IndexedDB or the console', () => {
  it('a call script with rotations, a reconnect and a leave writes nothing, opens no database and logs nothing', async () => {
    const store = new Map<string, string>();
    const writes: string[] = [];
    const shim = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        writes.push(`${k}=${v}`);
        store.set(k, v);
      },
      removeItem: (k: string) => store.delete(k),
      clear: () => store.clear(),
      key: () => null,
      length: 0,
    };
    vi.stubGlobal('localStorage', shim);
    vi.stubGlobal('sessionStorage', shim);
    const idb = { open: vi.fn(), deleteDatabase: vi.fn() };
    vi.stubGlobal('indexedDB', idb);
    const logged: string[] = [];
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(m =>
      vi.spyOn(console, m).mockImplementation((...args: unknown[]) => {
        logged.push(spyText(args));
      }),
    );
    try {
      const [a, b] = await inCall([A, B, C]);
      await talk(a, 1, 3);
      relay.dropFromVoice(C);
      await relay.advance(3000);
      relay.closeSocket(B);
      relay.reopenSocket(B);
      await relay.advance(3000);
      await talk(b, 2, 3);
      a.conn.disconnect();
      await relay.settle();
      expect(writes).toEqual([]);
      expect(idb.open).not.toHaveBeenCalled();
      expect(idb.deleteDatabase).not.toHaveBeenCalled();
      for (const s of spies) expect(s).not.toHaveBeenCalled();
      // No spy saw a secret, an instance id or a call-message plaintext.
      const { forms, plaintexts } = callSecretsIn(relay.log);
      expect(forms.length).toBeGreaterThan(0);
      for (const line of [...writes, ...logged]) {
        for (const f of forms) expect(line.includes(f)).toBe(false);
        for (const pt of plaintexts) expect(line.includes(pt)).toBe(false);
        expect(line.includes('accord-call')).toBe(false);
      }
    } finally {
      for (const s of spies) s.mockRestore();
      vi.unstubAllGlobals();
    }
  });
});
