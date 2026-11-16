// @vitest-environment node
/**
 * SPEC-03 A1: T-46 (REQ-46, fragmentation and numbering), T-49 (REQ-49,
 * reassembly, validation and decoding limits of §6.2.9), the fragment rules
 * of §6.2.7 and the binary relay messages of §6.12.2 (with the fragment and
 * binary parts of T-26 and T-48).
 *
 * The decoder is the recording decoder of §10.1: it records every chunk with
 * the frame number it carries, and outputs frames whose visible rectangle is
 * the configured size and whose coded size is padded up to a multiple of 16
 * (switchable). No real codec is needed.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import {
  DECODE_QUEUE_MAX,
  FRAG_HDR,
  FRAG_PAYLOAD,
  FRAME_TIMESTAMP_US,
  REASSEMBLY_MAX,
  ShareNumbering,
  RateBudget,
  ShareReassembler,
  VIDEO_FRAME_MAX,
  VIEW_DECODE_RATE,
  VIEW_DECRYPT_RATE,
  VIEW_KEYFRAME_RATE,
  decodeScreenDown,
  decodeScreenUp,
  encodeFragment,
  encodeScreenDown,
  encodeScreenUp,
  fragmentCount,
  parseFragment,
  sealScreenFrame,
  splitFrame,
  withinCaps,
  type DecodedVideoFrame,
  type FragmentHeader,
  type VideoDecoderPort,
  type Vp8Chunk,
  type Vp8DecoderConfig,
} from './screenFrame';
import { MEDIA_KIND_VIDEO, deriveEpochKeys, frameContext, importHkdfKey, openFrame, parseFrame } from './mediaFrame';

const CH = '00000000-0000-4000-8000-0000000000c1';
const S = '00000000-0000-4000-8000-0000000000a1';

// ---------------------------------------------------------------------------
// Synthetic VP8 source (§10.1)
// ---------------------------------------------------------------------------

/** A key frame: valid frame tag (first_part_size 0) and key-frame header, then a marker and padding. */
function vp8Key(w: number, h: number, size = 64, marker = 0): Uint8Array {
  const b = new Uint8Array(size);
  b.set([1 << 4, 0, 0, 0x9d, 0x01, 0x2a, w & 0xff, (w >> 8) & 0xff, h & 0xff, (h >> 8) & 0xff]);
  new DataView(b.buffer).setUint32(10, marker);
  return b;
}

/** An inter frame: frame tag with the inter bit and first_part_size 0, then a marker. */
function vp8Delta(size = 32, marker = 0): Uint8Array {
  const b = new Uint8Array(size);
  b.set([1 | (1 << 4), 0, 0]);
  new DataView(b.buffer).setUint32(3, marker);
  return b;
}

interface Frag { header: FragmentHeader; payload: Uint8Array }

const last = <T>(a: T[]): T | undefined => a[a.length - 1];

function fragmentsOf(data: Uint8Array, o: { key: boolean; shareSeq?: number; frameNo: number; w?: number; h?: number }): Frag[] {
  const parts = splitFrame(data);
  return parts.map((payload, fragIndex) => ({
    header: { vcodec: 1, flags: o.key ? 1 : 0, shareSeq: o.shareSeq ?? 1, frameNo: o.frameNo, fragIndex, fragCount: parts.length, width: o.w ?? 640, height: o.h ?? 360 },
    payload,
  }));
}

// ---------------------------------------------------------------------------
// Recording decoder, frames, renderer and clock
// ---------------------------------------------------------------------------

class FakeFrame implements DecodedVideoFrame {
  closed = false;
  constructor(readonly codedWidth: number, readonly codedHeight: number, readonly visibleRect: { width: number; height: number } | null, readonly frameNo: number, env: Env) {
    env.frames.push(this);
  }
  close(): void {
    this.closed = true;
  }
}

class RecordingDecoder implements VideoDecoderPort {
  decodeQueueSize = 0;
  state = 'unconfigured';
  config: Vp8DecoderConfig | null = null;
  readonly chunks: Vp8Chunk[] = [];
  private pending: Vp8Chunk[] = [];
  constructor(private readonly out: (f: FakeFrame) => void, private readonly err: (e: unknown) => void, private readonly env: Env) {}
  configure(c: Vp8DecoderConfig): void {
    this.config = c;
    this.state = 'configured';
    this.env.setups += 1;
  }
  decode(chunk: Vp8Chunk): void {
    if (this.state !== 'configured') throw new Error('decode on a decoder that is not configured');
    this.chunks.push(chunk);
    this.env.decoded.push({ type: chunk.type, frameNo: chunk.timestamp / FRAME_TIMESTAMP_US });
    this.env.decodedAt.push(this.env.now);
    this.pending.push(chunk);
  }
  /** Output every chunk passed so far. */
  flush(): void {
    const p = this.pending;
    this.pending = [];
    for (const chunk of p) {
      const w = this.config!.codedWidth;
      const h = this.config!.codedHeight;
      const coded = this.env.coded ?? (this.env.pad ? [Math.ceil(w / 16) * 16, Math.ceil(h / 16) * 16] : [w, h]);
      const visible = this.env.visible ?? { width: w, height: h };
      this.out(new FakeFrame(coded[0], coded[1], visible, chunk.timestamp / FRAME_TIMESTAMP_US, this.env));
    }
  }
  fail(): void {
    this.err(new Error('decoder error'));
  }
  close(): void {
    this.state = 'closed';
  }
}

interface Env {
  now: number;
  decoders: RecordingDecoder[];
  decoded: { type: string; frameNo: number }[];
  /** `env.now` when each entry of `decoded` was passed to the decoder. */
  decodedAt: number[];
  frames: FakeFrame[];
  draws: { frameNo: number; width: number; height: number }[];
  raf: (() => void)[];
  awaiting: number;
  cantDisplay: number;
  setups: number;
  pad: boolean;
  coded: [number, number] | null;
  visible: { width: number; height: number } | null;
}

function setup(): { env: Env; r: ShareReassembler<FakeFrame> } {
  const env: Env = { now: 0, decoders: [], decoded: [], decodedAt: [], frames: [], draws: [], raf: [], awaiting: 0, cantDisplay: 0, setups: 0, pad: true, coded: null, visible: null };
  const r = new ShareReassembler<FakeFrame>({
    now: () => env.now,
    createDecoder: (out, err) => {
      const d = new RecordingDecoder(out, err, env);
      env.decoders.push(d);
      return d;
    },
    requestAnimationFrame: cb => void env.raf.push(cb),
    draw: (frame, width, height) => void env.draws.push({ frameNo: frame.frameNo, width, height }),
    onAwaitingKeyframe: () => void env.awaiting++,
    onCantDisplay: () => void env.cantDisplay++,
  });
  return { env, r };
}

/** The largest number of `times` (ascending) inside any window [t, t + 1000 ms). */
function maxPerSecond(times: number[]): number {
  let max = 0;
  for (let i = 0, j = 0; i < times.length; i++) {
    while (times[i] - times[j] >= 1000) j++;
    max = Math.max(max, i - j + 1);
  }
  return max;
}

function deliver(r: ShareReassembler<FakeFrame>, kid: number, frags: Frag[]): void {
  for (const f of frags) r.onFragment(kid, f.header, f.payload);
}

function flush(env: Env): void {
  for (const d of env.decoders) d.flush();
}

function animationFrame(env: Env): void {
  const q = env.raf;
  env.raf = [];
  for (const cb of q) cb();
}

/** Deliver a frame, output it from the decoder and draw it. */
function show(env: Env, r: ShareReassembler<FakeFrame>, kid: number, frags: Frag[]): void {
  deliver(r, kid, frags);
  flush(env);
  animationFrame(env);
}

// ---------------------------------------------------------------------------
// §6.2.7 fragment header
// ---------------------------------------------------------------------------

describe('fragment header (§6.2.7)', () => {
  const h: FragmentHeader = { vcodec: 1, flags: 1, shareSeq: 7, frameNo: 2 ** 32 - 1, fragIndex: 1, fragCount: 2, width: 1920, height: 1080 };

  it('round-trips through the 18-byte big-endian header', () => {
    const pt = encodeFragment(h, new Uint8Array(10).fill(3));
    expect(pt.length).toBe(FRAG_HDR + 10);
    expect(Array.from(pt.subarray(0, 18))).toEqual([1, 1, 0, 0, 0, 7, 0xff, 0xff, 0xff, 0xff, 0, 1, 0, 2, 0x07, 0x80, 0x04, 0x38]);
    expect(parseFragment(pt)).toEqual({ header: h, payload: new Uint8Array(10).fill(3) });
  });

  it('T-26: rejects vcodec 0x00 and 0x02 and every reserved flag bit', () => {
    for (const vcodec of [0, 2, 0xff]) expect(parseFragment(patch(h, { vcodec }))).toBeNull();
    for (let bit = 1; bit < 8; bit++) expect(parseFragment(patch(h, { flags: 1 | (1 << bit) })), `bit ${bit}`).toBeNull();
    expect(parseFragment(patch(h, { flags: 0 }))).not.toBeNull();
  });

  it('rejects every other rule of §6.2.7', () => {
    const bad: Partial<FragmentHeader>[] = [
      { shareSeq: 0 },
      { fragCount: 0 }, { fragCount: 65 }, { fragIndex: 2 }, { fragIndex: 9, fragCount: 3 },
      { width: 15 }, { width: 1921 }, { height: 15 }, { height: 1921 }, { width: 1920, height: 1200 },
    ];
    for (const b of bad) expect(parseFragment(patch(h, b)), JSON.stringify(b)).toBeNull();
    // Payload length: a non-last fragment carries exactly 16,000 bytes; none carries more.
    const notLast = { ...h, fragIndex: 0 };
    expect(parseFragment(raw(notLast, FRAG_PAYLOAD))).not.toBeNull();
    expect(parseFragment(raw(notLast, FRAG_PAYLOAD - 1))).toBeNull();
    expect(parseFragment(raw(h, FRAG_PAYLOAD + 1))).toBeNull();
    expect(parseFragment(raw(h, 0))).toBeNull(); // fewer than 19 bytes
    expect(() => encodeFragment({ ...h, width: 1921 }, new Uint8Array(1))).toThrow(RangeError);
  });

  it('caps: 16 to 1920 per side and at most 2,073,600 pixels', () => {
    expect(withinCaps(1920, 1080)).toBe(true);
    expect(withinCaps(1080, 1920)).toBe(true);
    expect(withinCaps(1920, 1081)).toBe(false);
    expect(withinCaps(16, 16)).toBe(true);
    expect(withinCaps(15, 16)).toBe(false);
  });

  /** A header written without the encoder's checks. */
  function raw(x: FragmentHeader, payloadLength: number): Uint8Array {
    const b = new Uint8Array(FRAG_HDR + payloadLength);
    const v = new DataView(b.buffer);
    b[0] = x.vcodec;
    b[1] = x.flags;
    v.setUint32(2, x.shareSeq);
    v.setUint32(6, x.frameNo);
    v.setUint16(10, x.fragIndex);
    v.setUint16(12, x.fragCount);
    v.setUint16(14, x.width);
    v.setUint16(16, x.height);
    b.fill(5, FRAG_HDR);
    return b;
  }
  function patch(x: FragmentHeader, p: Partial<FragmentHeader>): Uint8Array {
    const y = { ...x, ...p };
    return raw(y, y.fragIndex === y.fragCount - 1 ? 10 : FRAG_PAYLOAD);
  }
});

// ---------------------------------------------------------------------------
// T-46 (REQ-46)
// ---------------------------------------------------------------------------

describe('T-46: fragmentation and numbering (REQ-46)', () => {
  it('splits 1; 16,000; 16,001; 32,000; 32,001 and 1,024,000 bytes into 1, 1, 2, 2, 3 and 64 fragments', () => {
    const cases: [number, number][] = [[1, 1], [16_000, 1], [16_001, 2], [32_000, 2], [32_001, 3], [1_024_000, 64]];
    for (const [len, n] of cases) {
      const data = new Uint8Array(len).map((_, i) => i % 251);
      const parts = splitFrame(data);
      expect(fragmentCount(len)).toBe(n);
      expect(parts.length, `${len}`).toBe(n);
      parts.slice(0, -1).forEach(p => expect(p.length).toBe(FRAG_PAYLOAD));
      const joined = new Uint8Array(len);
      let o = 0;
      for (const p of parts) {
        joined.set(p, o);
        o += p.length;
      }
      expect(Buffer.from(joined).equals(Buffer.from(data))).toBe(true);
    }
    expect(() => fragmentCount(0)).toThrow(RangeError);
    expect(() => fragmentCount(VIDEO_FRAME_MAX + 1)).toThrow(RangeError);
  });

  it('seals all fragments of a frame under one epoch with consecutive VCTRs, in index order, with equal headers', async () => {
    const secret = await importHkdfKey(new Uint8Array(32).fill(0x33));
    const tx = await deriveEpochKeys(secret, 6, 'encrypt');
    const rx = await deriveEpochKeys(secret, 6, 'decrypt');
    const ctx = frameContext(CH, S, new Uint8Array(16).fill(4));
    for (const key of [true, false]) {
      const data = key ? vp8Key(1280, 720, 32_001, 9) : vp8Delta(32_001, 9);
      const sealed = await sealScreenFrame({ data, key, shareSeq: 2, frameNo: 41, width: 1280, height: 720 }, tx, 1000, ctx);
      expect(sealed.length).toBe(3);
      const headers: FragmentHeader[] = [];
      for (const [i, s] of sealed.entries()) {
        const p = parseFrame(s, MEDIA_KIND_VIDEO);
        if (!p.ok) throw new Error('fragment must parse');
        expect(p.kid).toBe(6);
        expect(p.ctr).toBe(1000 + i);
        const f = parseFragment((await openFrame(p, rx, ctx))!)!;
        expect(f.header.fragIndex).toBe(i);
        headers.push(f.header);
      }
      for (const h of headers) {
        expect({ ...h, fragIndex: 0 }).toEqual({ vcodec: 1, flags: key ? 1 : 0, shareSeq: 2, frameNo: 41, fragIndex: 0, fragCount: 3, width: 1280, height: 720 });
      }
    }
  });

  it('share_seq is 1 then 2; frame_no counts only frames with a handed-off fragment', () => {
    const n = new ShareNumbering();
    expect(n.canNumberFrame).toBe(false);
    expect(n.startShare()).toBe(1);
    expect(n.frameNo).toBe(0);
    n.frameDone(true);
    n.frameDone(false); // nothing of frame 1 was handed off: the next frame is frame 1 again
    expect(n.frameNo).toBe(1);
    n.frameDone(true);
    expect(n.frameNo).toBe(2);
    expect(n.startShare()).toBe(2);
    expect(n.shareSeq).toBe(2);
    expect(n.frameNo).toBe(0);
    expect(n.canNumberFrame).toBe(true);
  });

  it('stops numbering before frame_no would exceed 2^32 − 1', () => {
    const n = new ShareNumbering();
    n.startShare();
    (n as unknown as { frame: number }).frame = 2 ** 32 - 1;
    expect(n.canNumberFrame).toBe(true);
    n.frameDone(true);
    expect(n.canNumberFrame).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// §6.12.2 binary messages
// ---------------------------------------------------------------------------

describe('SCREEN_UP and SCREEN_DOWN (§6.12.2)', () => {
  it('round-trip with the channel and sender as 16 bytes in RFC 9562 order', () => {
    const fragment = new Uint8Array(20).fill(2);
    const up = encodeScreenUp(CH.toUpperCase(), fragment);
    expect(up.length).toBe(37);
    expect(up[0]).toBe(1);
    expect(Array.from(up.subarray(1, 17))).toEqual([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xc1]);
    expect(decodeScreenUp(up)).toEqual({ channelId: CH, fragment });
    const down = encodeScreenDown(CH, S, fragment);
    expect(down.length).toBe(53);
    expect(decodeScreenDown(down)).toEqual({ channelId: CH, from: S, fragment });
  });

  it('T-26: drops binary messages whose type byte is not 0x02, and wrong sizes', () => {
    const down = encodeScreenDown(CH, S, new Uint8Array(100));
    for (const t of [0x00, 0x01, 0x03]) {
      const b = Uint8Array.from(down);
      b[0] = t;
      expect(decodeScreenDown(b), `type ${t}`).toBeNull();
    }
    expect(decodeScreenDown(down.subarray(0, 52))).toBeNull();
    expect(decodeScreenDown(new Uint8Array(16_418).fill(2))).toBeNull();
    expect(() => encodeScreenUp(CH, new Uint8Array(19))).toThrow(RangeError);
    expect(() => encodeScreenUp(CH, new Uint8Array(16_385))).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

describe('RateBudget', () => {
  it('allows a burst up to its limit, then each token comes back 1 s after it was taken', () => {
    const b = new RateBudget(4);
    let n = 0;
    while (b.take(0)) n++;
    expect(n).toBe(4);
    expect(b.take(999)).toBe(false);
    expect(b.take(1000)).toBe(true);
    expect(b.take(1000)).toBe(true);
    expect(b.take(1000)).toBe(true);
    expect(b.take(1000)).toBe(true);
    expect(b.take(1999)).toBe(false);
    let m = 0;
    while (b.take(10_000)) m++;
    expect(m).toBe(4);
  });

  it('never lets more than its limit through in any 1 s window, also after an idle second (REQ-49)', () => {
    for (const limit of [4, 30, 160]) {
      const b = new RateBudget(limit);
      const taken: number[] = [];
      for (let t = 0; t < 5000; t += 0.5) if (b.take(t)) taken.push(t);
      // An idle second, then a dense second again.
      for (let t = 6000; t < 8000; t += 0.25) if (b.take(t)) taken.push(t);
      for (let i = 0; i < taken.length; i++) {
        let inWindow = 0;
        for (let j = i; j < taken.length && taken[j] < taken[i] + 1000; j++) inWindow++;
        expect(inWindow).toBeLessThanOrEqual(limit);
      }
      // The steady rate is the limit, not less.
      expect(taken.filter(t => t >= 1000 && t < 2000).length).toBe(limit);
    }
  });

  it('refuses a time that is not a number or went backwards inside the window', () => {
    const b = new RateBudget(2);
    expect(b.take(Number.NaN)).toBe(false);
    expect(b.take(5000)).toBe(true);
    expect(b.take(4500)).toBe(true); // the second token was still there
    expect(b.take(4000)).toBe(false);
    expect(() => new RateBudget(0)).toThrow(RangeError);
    expect(() => new RateBudget(1.5)).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// T-49 (REQ-49)
// ---------------------------------------------------------------------------

describe('T-49: reassembly, validation and decoding (REQ-49, §6.2.9)', () => {
  let env: Env;
  let r: ShareReassembler<FakeFrame>;
  beforeEach(() => ({ env, r } = setup()));

  /** Bring the share into `decoding` with a key frame at `frameNo`. */
  function start(frameNo = 0, kid = 0, w = 640, h = 360): void {
    show(env, r, kid, fragmentsOf(vp8Key(w, h, 64, frameNo), { key: true, frameNo, w, h }));
    expect(r.state).toBe('decoding');
  }

  it('decodes a key frame and the deltas that follow it, drawing the visible rectangle', () => {
    start(0);
    for (let n = 1; n <= 3; n++) show(env, r, 0, fragmentsOf(vp8Delta(40, n), { key: false, frameNo: n }));
    expect(env.decoded).toEqual([{ type: 'key', frameNo: 0 }, { type: 'delta', frameNo: 1 }, { type: 'delta', frameNo: 2 }, { type: 'delta', frameNo: 3 }]);
    expect(env.decoders[0].config).toEqual({ codec: 'vp8', codedWidth: 640, codedHeight: 360, optimizeForLatency: true });
    expect(env.draws.map(d => d.frameNo)).toEqual([0, 1, 2, 3]);
    expect(env.frames.every(f => f.closed)).toBe(true);
  });

  it('five frames interleaved fragment by fragment: the lowest incomplete frame is dropped when a fifth starts', () => {
    start(0);
    env.now += 1000; // the start key frame's budget token is back: four more key frames fit
    const frames = [1, 2, 3, 4, 5].map(n => fragmentsOf(vp8Key(640, 360, 20_000, n), { key: true, frameNo: n }));
    for (const f of frames) r.onFragment(0, f[0].header, f[0].payload);
    expect(r.incompleteFrames).toBe(REASSEMBLY_MAX);
    // Frame 1 lost its first fragment: its second one starts a new, incomplete entry.
    for (const f of frames.slice(1)) {
      env.now += 200; // stay inside the key-frame budget and the 1 s idle limit
      r.onFragment(0, f[1].header, f[1].payload);
    }
    r.onFragment(0, frames[0][1].header, frames[0][1].payload);
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 2, 3, 4, 5]);
    expect(env.decoded.map(d => d.frameNo)).not.toContain(1);
    expect(env.decoded.map(d => d.frameNo)).toContain(5);
  });

  it('drops an incomplete frame idle for 1 s, and one still progressing 10 s after its first fragment', () => {
    start(0);
    const awaitingBefore = env.awaiting;
    const f1 = fragmentsOf(vp8Key(640, 360, 20_000, 1), { key: true, frameNo: 1 });
    r.onFragment(0, f1[0].header, f1[0].payload);
    env.now += 1000;
    r.sweep();
    expect(r.incompleteFrames).toBe(0);
    expect(env.awaiting).toBe(awaitingBefore + 1); // a loss awaits a key frame
    r.onFragment(0, f1[1].header, f1[1].payload);
    expect(env.decoded.map(d => d.frameNo)).not.toContain(1);

    // 64 fragments, one every 900 ms: the frame times out 10 s after the first.
    const slow = fragmentsOf(vp8Key(640, 360, VIDEO_FRAME_MAX, 2), { key: true, frameNo: 2 });
    for (const f of slow.slice(0, 12)) {
      r.onFragment(0, f.header, f.payload);
      env.now += 900;
    }
    r.sweep();
    expect(r.incompleteFrames).toBe(0);
    for (const f of slow.slice(12)) r.onFragment(0, f.header, f.payload);
    expect(env.decoded.map(d => d.frameNo)).not.toContain(2);
  });

  it('decodes a 600,000-byte key frame delivered at 2 Mbit/s (2.4 s)', () => {
    const frags = fragmentsOf(vp8Key(1920, 1080, 600_000, 0), { key: true, frameNo: 0, w: 1920, h: 1080 });
    expect(frags.length).toBe(38);
    for (const f of frags) {
      r.onFragment(0, f.header, f.payload);
      env.now += 2400 / frags.length;
      r.sweep();
    }
    expect(env.decoded).toEqual([{ type: 'key', frameNo: 0 }]);
  });

  it('a fragment disagreeing in frag_count, flags, width, height or KID, or repeating a frag_index, discards the whole frame', () => {
    start(0);
    let frameNo = 1;
    const variants: ((f: Frag, first: Frag) => [number, Frag])[] = [
      f => [0, { ...f, header: { ...f.header, fragCount: 3, fragIndex: 2 } }], // valid on its own (§6.2.7), not with frame 0's count
      f => [0, { ...f, header: { ...f.header, flags: 0 } }],
      f => [0, { ...f, header: { ...f.header, width: 1280 } }],
      f => [0, { ...f, header: { ...f.header, height: 720 } }],
      f => [1, f], // the same fragment under another epoch
      (_f, first) => [0, first], // a repeated index (a malicious sharer seals it again under a new VCTR)
    ];
    for (const v of variants) {
      const frags = fragmentsOf(vp8Key(640, 360, 20_000, frameNo), { key: true, frameNo });
      r.onFragment(0, frags[0].header, frags[0].payload);
      const [kid, odd] = v(frags[1], frags[0]);
      r.onFragment(kid, odd.header, odd.payload);
      r.onFragment(0, frags[1].header, frags[1].payload); // the genuine fragment arrives too late
      expect(env.decoded.map(d => d.frameNo), `variant ${variants.indexOf(v)}`).not.toContain(frameNo);
      frameNo++;
    }
  });

  it('a key frame whose VP8 header disagrees with the fragment header, exceeds the caps or fails the tag rules is not decoded', () => {
    start(0);
    const cases: [Uint8Array, number, number][] = [
      [vp8Key(1280, 720, 64), 640, 360], // another size than the header
      [vp8Key(1920, 1200, 64), 1920, 1200], // over the pixel cap (the header itself is checked in §6.2.8)
      [vp8Delta(64), 640, 360], // the tag says inter frame
      [(() => { const b = vp8Key(640, 360, 64); b[5] = 0; return b; })(), 640, 360], // start code
      [(() => { const b = vp8Key(640, 360, 64); b[0] |= 4 << 1; return b; })(), 640, 360], // version 4
    ];
    let frameNo = 1;
    for (const [data, w, h] of cases) {
      const awaiting = env.awaiting;
      env.now += 1000; // stay inside the key-frame budget
      // A header over the caps never passes §6.2.8; feed the frame under a valid header.
      const header = withinCaps(w, h) ? { w, h } : { w: 640, h: 360 };
      deliver(r, 0, fragmentsOf(data, { key: true, frameNo, ...header }));
      expect(env.decoded.map(d => d.frameNo)).not.toContain(frameNo);
      expect(r.state).toBe('awaiting_keyframe');
      expect(env.awaiting).toBe(awaiting + 1); // a new awaiting period: keyframe requests start
      start(++frameNo);
      frameNo++;
    }
  });

  it('a delta after a gap is not decoded and starts a request; a delta with a lower frame_no is dropped', () => {
    start(0);
    show(env, r, 0, fragmentsOf(vp8Delta(40, 1), { key: false, frameNo: 1 }));
    const awaiting = env.awaiting;
    show(env, r, 0, fragmentsOf(vp8Delta(40, 3), { key: false, frameNo: 3 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 1]);
    expect(env.awaiting).toBe(awaiting + 1);
    // Still awaiting with nothing decoded since: no new request schedule.
    show(env, r, 0, fragmentsOf(vp8Delta(40, 4), { key: false, frameNo: 4 }));
    expect(env.awaiting).toBe(awaiting + 1);
    // Lower than the last decoded frame_no: dropped before reassembly.
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 1), { key: true, frameNo: 1 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 1]);
    expect(r.incompleteFrames).toBe(0);
  });

  it('passes nothing to the decoder while decodeQueueSize exceeds 4', () => {
    start(0);
    env.decoders[0].decodeQueueSize = DECODE_QUEUE_MAX + 1;
    show(env, r, 0, fragmentsOf(vp8Delta(40, 1), { key: false, frameNo: 1 }));
    env.now += 1000;
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 2), { key: true, frameNo: 2 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0]);
    expect(r.state).toBe('awaiting_keyframe');
    env.decoders[0].decodeQueueSize = DECODE_QUEUE_MAX;
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 3), { key: true, frameNo: 3 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 3]);
  });

  it('draws padded frames by their visible rectangle and closes frames of the wrong size undrawn', () => {
    start(0, 0, 1920, 1080);
    expect(env.frames[0]).toMatchObject({ codedWidth: 1920, codedHeight: 1088 });
    expect(env.draws).toEqual([{ frameNo: 0, width: 1920, height: 1080 }]);

    env.now += 3000;
    start(1, 0, 1820, 1138);
    expect(last(env.frames)).toMatchObject({ codedWidth: 1824, codedHeight: 1152 });
    expect(last(env.draws)).toEqual({ frameNo: 1, width: 1820, height: 1138 });

    const bad: Partial<Env>[] = [
      { visible: { width: 1820, height: 1136 } }, // visible size differs from the key frame
      { coded: [2064, 1152] }, // coded size over 2048
      { coded: [1816, 1152] }, // coded smaller than visible
      { visible: null as unknown as Env['visible'], coded: null },
    ];
    let n = 2;
    for (const b of bad) {
      env.visible = b.visible ?? null;
      env.coded = b.coded ?? null;
      if ('visible' in b && b.visible === null) env.visible = { width: 0, height: 0 };
      const drawn = env.draws.length;
      const awaiting = env.awaiting;
      show(env, r, 0, fragmentsOf(vp8Delta(40, n), { key: false, frameNo: n, w: 1820, h: 1138 }));
      expect(env.draws.length, JSON.stringify(b)).toBe(drawn);
      expect(last(env.frames)!.closed).toBe(true);
      expect(env.awaiting).toBe(awaiting + 1);
      env.visible = null;
      env.coded = null;
      env.now += 3000;
      start(++n, 0, 1820, 1138);
      n++;
    }
  });

  it('a decoder error closes the decoder; the next key frame replaces it', () => {
    start(0);
    env.decoders[0].fail();
    expect(env.decoders[0].state).toBe('closed');
    expect(r.state).toBe('awaiting_keyframe');
    show(env, r, 0, fragmentsOf(vp8Delta(40, 1), { key: false, frameNo: 1 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0]);
    env.now += 2000;
    start(2);
    expect(env.decoders.length).toBe(2);
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 2]);
  });

  it('three frames decoded within one animation frame cause one draw, of the newest; the others are closed', () => {
    start(0);
    for (let n = 1; n <= 3; n++) deliver(r, 0, fragmentsOf(vp8Delta(40, n), { key: false, frameNo: n }));
    flush(env);
    expect(env.raf.length).toBe(1);
    animationFrame(env);
    expect(env.draws.map(d => d.frameNo)).toEqual([0, 3]);
    expect(env.frames.filter(f => f.frameNo === 1 || f.frameNo === 2).every(f => f.closed)).toBe(true);
    expect(env.frames.every(f => f.closed)).toBe(true);
  });

  it('floors: a forged share_seq of 2^32 − 1 under epoch g is undone by the first key frame under g+1', () => {
    start(0, 3);
    // A former key holder of epoch 3 forges a delta with share_seq 2^32 − 1.
    deliver(r, 3, fragmentsOf(vp8Delta(40, 99), { key: false, frameNo: 0, shareSeq: 2 ** 32 - 1 }));
    expect(r.shareSeq).toBe(2 ** 32 - 1);
    show(env, r, 3, fragmentsOf(vp8Key(640, 360, 64, 1), { key: true, frameNo: 1 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0]); // the genuine share is now "older"
    env.now += 1000;
    show(env, r, 4, fragmentsOf(vp8Key(640, 360, 64, 2), { key: true, frameNo: 2 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 2]);
    expect(r.shareSeq).toBe(1);
    expect(r.floorEpoch).toBe(4);
  });

  it('floors: a decoded forged key frame with frame_no near 2^32 − 1 is undone by the first key frame under g+1', () => {
    start(0, 3);
    show(env, r, 3, fragmentsOf(vp8Key(640, 360, 64, 0), { key: true, frameNo: 2 ** 32 - 2 }));
    expect(r.lastFrameNo).toBe(2 ** 32 - 2);
    show(env, r, 3, fragmentsOf(vp8Delta(40, 1), { key: false, frameNo: 1 }));
    expect(env.decoded.length).toBe(2);
    env.now += 1000;
    show(env, r, 4, fragmentsOf(vp8Key(640, 360, 64, 5), { key: true, frameNo: 5 }));
    expect(last(env.decoded)).toEqual({ type: 'key', frameNo: 5 });
    show(env, r, 4, fragmentsOf(vp8Delta(40, 6), { key: false, frameNo: 6 }));
    expect(last(env.decoded)).toEqual({ type: 'delta', frameNo: 6 });
  });

  it('a new share_seq starts over in awaiting_keyframe; an older one is dropped', () => {
    start(0);
    const awaiting = env.awaiting;
    show(env, r, 0, fragmentsOf(vp8Delta(40, 0), { key: false, frameNo: 0, shareSeq: 2 }));
    expect(r.shareSeq).toBe(2);
    expect(r.state).toBe('awaiting_keyframe');
    expect(env.awaiting).toBe(awaiting + 1);
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 7), { key: true, frameNo: 7, shareSeq: 1 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0]);
    env.now += 1000;
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 1), { key: true, frameNo: 1, shareSeq: 2 }));
    expect(env.decoded.map(d => d.frameNo)).toEqual([0, 1]);
  });

  it('budgets: a burst of 1,000 one-fragment frames at one instant gets at most 160 decryptions and 30 decodes, of which 4 key frames', () => {
    let decrypted = 0;
    for (let i = 0; i < 1000; i++) {
      if (!r.takeDecryption()) continue;
      decrypted++;
      const key = i % 10 === 0;
      deliver(r, 0, fragmentsOf(key ? vp8Key(640, 360, 64, i) : vp8Delta(40, i), { key, frameNo: i }));
    }
    expect(decrypted).toBe(VIEW_DECRYPT_RATE);
    expect(env.decoded.length).toBeLessThanOrEqual(VIEW_DECODE_RATE);
    expect(env.decoded.filter(d => d.type === 'key').length).toBeLessThanOrEqual(VIEW_KEYFRAME_RATE);
  });

  it('budgets: 1,000 one-fragment frames spread over one second get at most 160 decryptions and 30 decodes, of which 4 key frames', () => {
    // A fresh share: its budgets are full, as after an idle second.
    let decrypted = 0;
    let frameNo = 0;
    for (let ms = 0; ms < 1000; ms++) {
      env.now = ms;
      if (!r.takeDecryption()) continue;
      decrypted++;
      const key = frameNo % 10 === 0;
      deliver(r, 0, fragmentsOf(key ? vp8Key(640, 360, 64, frameNo) : vp8Delta(40, frameNo), { key, frameNo }));
      frameNo++;
    }
    expect(decrypted).toBe(VIEW_DECRYPT_RATE);
    expect(env.decoded.length).toBeLessThanOrEqual(VIEW_DECODE_RATE);
    expect(env.decoded.filter(d => d.type === 'key').length).toBeLessThanOrEqual(VIEW_KEYFRAME_RATE);
  });

  it('budgets: deltas paced to arrive after each decoded chunk never pass 30 decodes in one second', () => {
    // A key frame, 29 deltas at once, then one delta every 34 ms: a bucket
    // refilled continuously would decode about 59 chunks in this second.
    let frameNo = 0;
    deliver(r, 0, fragmentsOf(vp8Key(640, 360, 64, frameNo), { key: true, frameNo }));
    for (frameNo = 1; frameNo < 30; frameNo++) deliver(r, 0, fragmentsOf(vp8Delta(40, frameNo), { key: false, frameNo }));
    for (env.now = 34; env.now < 1000; env.now += 34, frameNo++) deliver(r, 0, fragmentsOf(vp8Delta(40, frameNo), { key: false, frameNo }));
    expect(env.decoded.length).toBe(VIEW_DECODE_RATE);
    expect(r.state).toBe('awaiting_keyframe');
  });

  it('budgets: key frames every 125 ms never pass 4 decoded key frames in one second', () => {
    for (let i = 0; i < 8; i++) {
      env.now = i * 125;
      deliver(r, 0, fragmentsOf(vp8Key(640, 360, 64, i), { key: true, frameNo: i }));
    }
    expect(env.decoded.filter(d => d.type === 'key').length).toBe(VIEW_KEYFRAME_RATE);
    // The first token comes back 1 s after it was taken.
    env.now = 1000;
    deliver(r, 0, fragmentsOf(vp8Key(640, 360, 64, 8), { key: true, frameNo: 8 }));
    expect(last(env.decoded)).toEqual({ type: 'key', frameNo: 8 });
  });

  it('budgets: over 5 s at 1,000 frames per second, no 1 s window passes 160 decryptions or 30 decodes, of which 4 key frames', () => {
    const decryptedAt: number[] = [];
    let frameNo = 0;
    for (let ms = 0; ms < 5000; ms++) {
      env.now = ms;
      if (!r.takeDecryption()) continue;
      decryptedAt.push(ms);
      const key = frameNo % 50 === 0;
      deliver(r, 0, fragmentsOf(key ? vp8Key(640, 360, 64, frameNo) : vp8Delta(40, frameNo), { key, frameNo }));
      frameNo++;
    }
    expect(maxPerSecond(decryptedAt)).toBeLessThanOrEqual(VIEW_DECRYPT_RATE);
    // Every second, including the first, gets the full decryption rate and no more.
    for (let sec = 0; sec < 5; sec++) expect(decryptedAt.filter(t => t >= sec * 1000 && t < (sec + 1) * 1000).length).toBe(VIEW_DECRYPT_RATE);
    expect(maxPerSecond(env.decodedAt)).toBeLessThanOrEqual(VIEW_DECODE_RATE);
    expect(maxPerSecond(env.decodedAt.filter((_, i) => env.decoded[i].type === 'key'))).toBeLessThanOrEqual(VIEW_KEYFRAME_RATE);
  });

  it('key frames alternating 640 × 360 and 1280 × 720: at most one decoder setup per 2 s, and 3 refusals within 30 s end the watch', () => {
    const setupsAt: number[] = [];
    let last = 0;
    for (let i = 0; i < 40 && !r.closed; i++) {
      const [w, h] = i % 2 === 0 ? [640, 360] : [1280, 720];
      deliver(r, 0, fragmentsOf(vp8Key(w, h, 64, i), { key: true, frameNo: i, w, h }));
      if (env.setups > last) {
        setupsAt.push(env.now);
        last = env.setups;
      }
      env.now += 300;
    }
    for (let i = 1; i < setupsAt.length; i++) expect(setupsAt[i] - setupsAt[i - 1]).toBeGreaterThanOrEqual(2000);
    expect(env.cantDisplay).toBe(1);
    expect(r.closed).toBe(true);
    expect(env.decoders.every(d => d.state === 'closed')).toBe(true);
    // Nothing reaches a closed reassembler.
    const n = env.decoded.length;
    deliver(r, 0, fragmentsOf(vp8Key(640, 360, 64, 99), { key: true, frameNo: 99 }));
    expect(env.decoded.length).toBe(n);
    expect(r.takeDecryption()).toBe(false);
  });

  it('REQ-35: reset discards buffers, closes the decoder and awaits a key frame; a new instance also resets the floors', () => {
    start(5, 2);
    const frags = fragmentsOf(vp8Key(640, 360, 20_000, 6), { key: true, frameNo: 6 });
    r.onFragment(2, frags[0].header, frags[0].payload);
    const awaiting = env.awaiting;
    r.reset(false);
    expect(r.incompleteFrames).toBe(0);
    expect(env.decoders[0].state).toBe('closed');
    expect(r.state).toBe('awaiting_keyframe');
    expect(env.awaiting).toBe(awaiting + 1);
    expect(r.lastFrameNo).toBe(5);
    r.reset(true);
    expect([r.shareSeq, r.lastFrameNo, r.floorEpoch]).toEqual([0, null, -1]);
    env.now += 2000;
    show(env, r, 0, fragmentsOf(vp8Key(640, 360, 64, 0), { key: true, frameNo: 0 })); // the new instance restarts at epoch 0
    expect(last(env.decoded)).toEqual({ type: 'key', frameNo: 0 });
  });

  it('close releases the decoder, a frame waiting to be drawn and every buffer', () => {
    start(0);
    deliver(r, 0, fragmentsOf(vp8Delta(40, 1), { key: false, frameNo: 1 }));
    flush(env);
    r.onFragment(0, fragmentsOf(vp8Key(640, 360, 20_000, 2), { key: true, frameNo: 2 })[0].header, new Uint8Array(FRAG_PAYLOAD));
    r.close();
    animationFrame(env);
    expect(env.draws.map(d => d.frameNo)).toEqual([0]);
    expect(env.frames.every(f => f.closed)).toBe(true);
    expect(env.decoders[0].state).toBe('closed');
    expect(r.incompleteFrames).toBe(0);
  });
});
