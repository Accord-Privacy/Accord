/**
 * @module voice/screenFrame
 * Screen video fragments (SPEC-03 A1): the authenticated fragment header of
 * §6.2.7, fragmentation and sealing of encoded frames (REQ-46), the binary
 * relay messages `SCREEN_UP` and `SCREEN_DOWN` (§6.12.2), and a viewer's
 * reassembly, validation and decoding rules of §6.2.9 (REQ-49).
 *
 * Everything here is pure: the clock, the video decoder and the renderer are
 * injected (`ShareReassemblerHooks`), so the module runs without WebCodecs.
 * `voice/screenShare.ts` wires it to `VideoDecoder`, a canvas and the relay.
 *
 * Nothing here logs or stores anything (REQ-27).
 */

import { vp8KeySize, vp8TagOk } from './vp8';
import {
  FRAG_MAX,
  FRAG_MIN,
  MEDIA_KIND_VIDEO,
  bytesToUuid,
  sealFrame,
  uuidToBytes,
  type EpochKeys,
  type FrameContext,
} from './mediaFrame';

// ---------------------------------------------------------------------------
// Constants (§6.2.7, §6.5)
// ---------------------------------------------------------------------------

/** `vcodec` 0x01: the payloads of a frame concatenate to one VP8 frame (RFC 6386). */
export const VCODEC_VP8 = 0x01;
/** `flags` bit 0: the frame is a key frame. Bits 1 to 7 are reserved (0). */
export const FRAG_FLAG_KEY = 0x01;
/** `FRAG_HDR`: the fragment header length. */
export const FRAG_HDR = 18;
/** `FRAG_PAYLOAD`: every fragment but a frame's last carries exactly this many bytes. */
export const FRAG_PAYLOAD = 16_000;
/** `FRAGS_MAX`. */
export const FRAGS_MAX = 64;
/** `VIDEO_FRAME_MAX`: the largest encoded frame, 64 × 16,000 bytes. */
export const VIDEO_FRAME_MAX = FRAGS_MAX * FRAG_PAYLOAD;
/** `VIDEO_CAPS`. */
export const VIDEO_SIDE_MIN = 16;
export const VIDEO_SIDE_MAX = 1920;
export const VIDEO_PIXELS_MAX = 2_073_600;
/** `VIDEO_CODED_MAX`: per side of a decoded frame's coded size, padding included. */
export const VIDEO_CODED_MAX = 2048;
/** Largest `share_seq` and `frame_no`. */
export const U32_MAX = 2 ** 32 - 1;
/** `REASSEMBLY_MAX` incomplete frames per watched sharer. */
export const REASSEMBLY_MAX = 4;
/** `REASSEMBLY_TIMEOUT`: 1 s without a new fragment, or 10 s after the first. */
export const REASSEMBLY_IDLE_MS = 1000;
export const REASSEMBLY_MAX_AGE_MS = 10_000;
/** `VIEW_DECRYPT_RATE`, per watched sharer and second. */
export const VIEW_DECRYPT_RATE = 160;
/** `VIEW_DECODE_RATE`: chunks per second per watched sharer, of which key frames. */
export const VIEW_DECODE_RATE = 30;
export const VIEW_KEYFRAME_RATE = 4;
/** `DECODER_SETUP_MIN_GAP`, and the refusals that stop a watch. */
export const DECODER_SETUP_MIN_GAP_MS = 2000;
export const DECODER_SETUP_REFUSAL_WINDOW_MS = 30_000;
export const DECODER_SETUP_REFUSALS_MAX = 3;
/** `DECODE_QUEUE_MAX`. */
export const DECODE_QUEUE_MAX = 4;
/** `WATCH_MAX`: shares watched (and decoders alive) at once. */
export const WATCH_MAX = 2;
/** Decoder timestamp per `frame_no`, in µs (a monotonic label only). */
export const FRAME_TIMESTAMP_US = 66_667;

/** `withinCaps(w, h)`: each side 16 to 1920, at most 2,073,600 pixels. */
export function withinCaps(w: number, h: number): boolean {
  return Number.isInteger(w) && Number.isInteger(h)
    && w >= VIDEO_SIDE_MIN && w <= VIDEO_SIDE_MAX
    && h >= VIDEO_SIDE_MIN && h <= VIDEO_SIDE_MAX
    && w * h <= VIDEO_PIXELS_MAX;
}

// ---------------------------------------------------------------------------
// Fragment header (§6.2.7)
// ---------------------------------------------------------------------------

export interface FragmentHeader {
  readonly vcodec: number;
  readonly flags: number;
  readonly shareSeq: number;
  readonly frameNo: number;
  readonly fragIndex: number;
  readonly fragCount: number;
  readonly width: number;
  readonly height: number;
}

export interface Fragment {
  readonly header: FragmentHeader;
  readonly payload: Uint8Array;
}

function isU32(n: number): boolean {
  return Number.isInteger(n) && n >= 0 && n <= U32_MAX;
}

/** Every rule of §6.2.7 for a header and its payload length. */
export function fragmentRulesHold(h: FragmentHeader, payloadLength: number): boolean {
  if (h.vcodec !== VCODEC_VP8) return false;
  if (!Number.isInteger(h.flags) || (h.flags & ~FRAG_FLAG_KEY) !== 0 || h.flags < 0) return false;
  if (!isU32(h.shareSeq) || h.shareSeq < 1) return false;
  if (!isU32(h.frameNo)) return false;
  if (!Number.isInteger(h.fragCount) || h.fragCount < 1 || h.fragCount > FRAGS_MAX) return false;
  if (!Number.isInteger(h.fragIndex) || h.fragIndex < 0 || h.fragIndex >= h.fragCount) return false;
  if (!withinCaps(h.width, h.height)) return false;
  if (payloadLength < 1 || payloadLength > FRAG_PAYLOAD) return false;
  if (h.fragIndex !== h.fragCount - 1 && payloadLength !== FRAG_PAYLOAD) return false;
  return true;
}

/** The fragment plaintext: the 18-byte header and the payload. Throws if a rule fails. */
export function encodeFragment(h: FragmentHeader, payload: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!fragmentRulesHold(h, payload.length)) throw new RangeError('fragment header or payload breaks §6.2.7');
  const out = new Uint8Array(FRAG_HDR + payload.length);
  const v = new DataView(out.buffer);
  out[0] = h.vcodec;
  out[1] = h.flags;
  v.setUint32(2, h.shareSeq);
  v.setUint32(6, h.frameNo);
  v.setUint16(10, h.fragIndex);
  v.setUint16(12, h.fragCount);
  v.setUint16(14, h.width);
  v.setUint16(16, h.height);
  out.set(payload, FRAG_HDR);
  return out;
}

/**
 * §6.2.8 step 10: an authenticated fragment plaintext of at least 19 bytes
 * whose header satisfies every rule of §6.2.7. Null otherwise.
 */
export function parseFragment(pt: Uint8Array): Fragment | null {
  if (pt.length < FRAG_HDR + 1) return null;
  const v = new DataView(pt.buffer, pt.byteOffset, pt.byteLength);
  const header: FragmentHeader = {
    vcodec: pt[0],
    flags: pt[1],
    shareSeq: v.getUint32(2),
    frameNo: v.getUint32(6),
    fragIndex: v.getUint16(10),
    fragCount: v.getUint16(12),
    width: v.getUint16(14),
    height: v.getUint16(16),
  };
  const payload = pt.subarray(FRAG_HDR);
  return fragmentRulesHold(header, payload.length) ? { header, payload } : null;
}

// ---------------------------------------------------------------------------
// Fragmentation and sealing (REQ-46)
// ---------------------------------------------------------------------------

/** n = ⌈L / 16000⌉; throws unless 1 ≤ L ≤ 1,024,000. */
export function fragmentCount(length: number): number {
  if (!Number.isInteger(length) || length < 1 || length > VIDEO_FRAME_MAX) throw new RangeError('encoded frame size out of bounds');
  return Math.ceil(length / FRAG_PAYLOAD);
}

/** Fragment i carries bytes 16000·i up to min(L, 16000·(i+1)). */
export function splitFrame(data: Uint8Array): Uint8Array[] {
  const n = fragmentCount(data.length);
  const parts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) parts.push(data.subarray(i * FRAG_PAYLOAD, Math.min(data.length, (i + 1) * FRAG_PAYLOAD)));
  return parts;
}

/** One encoder output, numbered by the share (REQ-46). */
export interface EncodedScreenFrame {
  readonly data: Uint8Array;
  /** The encoder output's type is `key`. */
  readonly key: boolean;
  readonly shareSeq: number;
  readonly frameNo: number;
  /** The encoder's configured size. */
  readonly width: number;
  readonly height: number;
}

/**
 * Seal every fragment of one encoded frame under one epoch's video key, with
 * KID = that epoch and VCTR values `firstVctr`, `firstVctr + 1`, … — a range
 * of `fragmentCount(data.length)` values the caller reserved at frame start
 * (REQ-46). All fragments carry the same header except `frag_index`. The
 * result is in VCTR order, which is `frag_index` order, the order they must
 * be handed off in. `seal` defaults to `sealFrame`; tests pass a wrapper.
 */
export async function sealScreenFrame(frame: EncodedScreenFrame, keys: EpochKeys, firstVctr: number, ctx: FrameContext, seal: typeof sealFrame = sealFrame): Promise<Uint8Array[]> {
  const parts = splitFrame(frame.data);
  const base = {
    vcodec: VCODEC_VP8,
    flags: frame.key ? FRAG_FLAG_KEY : 0,
    shareSeq: frame.shareSeq,
    frameNo: frame.frameNo,
    fragCount: parts.length,
    width: frame.width,
    height: frame.height,
  };
  const plaintexts = parts.map((p, fragIndex) => encodeFragment({ ...base, fragIndex }, p));
  return Promise.all(plaintexts.map((pt, i) => seal(MEDIA_KIND_VIDEO, keys, firstVctr + i, ctx, pt)));
}

/**
 * `share_seq` and `frame_no` of a sender instance (REQ-46): `share_seq` is 1
 * for the instance's first share and grows by 1 per share; `frame_no` starts
 * at 0 and grows by 1 only for a frame of which at least one fragment was
 * handed off, so a frame with none leaves its number to the next.
 */
export class ShareNumbering {
  private seq = 0;
  private frame = 0;

  /** Start a share; returns its `share_seq`. */
  startShare(): number {
    if (this.seq >= U32_MAX) throw new RangeError('share_seq exhausted');
    this.seq += 1;
    this.frame = 0;
    return this.seq;
  }

  /** The current share's `share_seq` (0 before the first share). */
  get shareSeq(): number {
    return this.seq;
  }

  /** The `frame_no` the next frame takes. */
  get frameNo(): number {
    return this.frame;
  }

  /**
   * False once the next `frame_no` would exceed 2^32 − 1: the sender must
   * end the share instead of numbering another frame (REQ-46).
   */
  get canNumberFrame(): boolean {
    return this.seq > 0 && this.frame <= U32_MAX;
  }

  /** The current frame is done: it advances `frame_no` only if a fragment was handed off. */
  frameDone(handedOffAny: boolean): void {
    if (handedOffAny) this.frame += 1;
  }
}

// ---------------------------------------------------------------------------
// Binary relay messages (§6.12.2)
// ---------------------------------------------------------------------------

export const SCREEN_UP_TYPE = 0x01;
export const SCREEN_DOWN_TYPE = 0x02;
/** `SCREEN_UP`: type, channel id, fragment: 37 to 16,401 bytes. */
export const SCREEN_UP_MIN = 1 + 16 + FRAG_MIN;
export const SCREEN_UP_MAX = 1 + 16 + FRAG_MAX;
/** `SCREEN_DOWN`: type, channel id, `from`, fragment: 53 to 16,417 bytes. */
export const SCREEN_DOWN_MIN = 1 + 32 + FRAG_MIN;
export const SCREEN_DOWN_MAX = 1 + 32 + FRAG_MAX;

export interface ScreenUpMessage {
  readonly channelId: string;
  readonly fragment: Uint8Array;
}

export interface ScreenDownMessage {
  readonly channelId: string;
  /** The sharer's user id, stamped by the relay. */
  readonly from: string;
  readonly fragment: Uint8Array;
}

function checkFragmentSize(fragment: Uint8Array): void {
  if (fragment.length < FRAG_MIN || fragment.length > FRAG_MAX) throw new RangeError('fragment size out of bounds');
}

/** Build `SCREEN_UP`: 0x01 ‖ channel id (16 bytes, RFC 9562 order) ‖ fragment. */
export function encodeScreenUp(channelId: string, fragment: Uint8Array): Uint8Array<ArrayBuffer> {
  checkFragmentSize(fragment);
  const out = new Uint8Array(17 + fragment.length);
  out[0] = SCREEN_UP_TYPE;
  out.set(uuidToBytes(channelId), 1);
  out.set(fragment, 17);
  return out;
}

/** Parse `SCREEN_UP` (the relay's checks of size and type); null otherwise. */
export function decodeScreenUp(bytes: Uint8Array): ScreenUpMessage | null {
  if (bytes.length < SCREEN_UP_MIN || bytes.length > SCREEN_UP_MAX || bytes[0] !== SCREEN_UP_TYPE) return null;
  return { channelId: bytesToUuid(bytes.subarray(1, 17)), fragment: bytes.subarray(17) };
}

/** Build `SCREEN_DOWN`: 0x02 ‖ channel id ‖ from ‖ fragment (relay side, tests). */
export function encodeScreenDown(channelId: string, from: string, fragment: Uint8Array): Uint8Array<ArrayBuffer> {
  checkFragmentSize(fragment);
  const out = new Uint8Array(33 + fragment.length);
  out[0] = SCREEN_DOWN_TYPE;
  out.set(uuidToBytes(channelId), 1);
  out.set(uuidToBytes(from), 17);
  out.set(fragment, 33);
  return out;
}

/**
 * Parse a binary relay message as `SCREEN_DOWN`: 53 to 16,417 bytes and type
 * byte 0x02. Any other binary message is null and must be dropped (REQ-26).
 */
export function decodeScreenDown(bytes: Uint8Array): ScreenDownMessage | null {
  if (bytes.length < SCREEN_DOWN_MIN || bytes.length > SCREEN_DOWN_MAX || bytes[0] !== SCREEN_DOWN_TYPE) return null;
  return {
    channelId: bytesToUuid(bytes.subarray(1, 17)),
    from: bytesToUuid(bytes.subarray(17, 33)),
    fragment: bytes.subarray(33),
  };
}

// ---------------------------------------------------------------------------
// Budgets (§6.2.9 "Budgets")
// ---------------------------------------------------------------------------

/**
 * A per-sharer rate budget of REQ-49: a bucket of `limit` tokens in which
 * each token comes back `windowMs` after it was taken. `take(now)` succeeds,
 * and records the take, only when fewer than `limit` takes succeeded in the
 * last `windowMs` milliseconds, so every window of that length holds at most
 * `limit` takes ("at most 160 fragment decryptions per second", T-49), while
 * a burst up to `limit` (a 64-fragment key frame) still passes at once.
 *
 * A bucket of size N refilled continuously at N per second is not used: it
 * lets up to 2N through in the second after an idle one, which REQ-49's
 * numbers forbid.
 *
 * The last `limit` take times are kept in a ring, oldest first: `take` is
 * O(1) and the memory fixed. `now` is monotonic milliseconds; a time that is
 * not a number, or that went backwards past the window, is refused.
 */
export class RateBudget {
  readonly limit: number;
  readonly windowMs: number;
  private readonly times: Float64Array;
  private oldest = 0;

  constructor(limit: number, windowMs = 1000) {
    if (!Number.isInteger(limit) || limit < 1 || !(windowMs > 0)) throw new RangeError('RateBudget: bad limit or window');
    this.limit = limit;
    this.windowMs = windowMs;
    this.times = new Float64Array(limit).fill(-Infinity);
  }

  take(now: number): boolean {
    // The oldest of the last `limit` takes is still inside the window: full.
    if (!(now - this.times[this.oldest] >= this.windowMs)) return false;
    this.times[this.oldest] = now;
    this.oldest = (this.oldest + 1) % this.limit;
    return true;
  }
}

// ---------------------------------------------------------------------------
// Reassembly, validation and decoding (§6.2.9)
// ---------------------------------------------------------------------------

export type ShareDecodeState = 'awaiting_keyframe' | 'decoding';

/** The WebCodecs `VideoDecoderConfig` this module asks for. */
export interface Vp8DecoderConfig {
  readonly codec: 'vp8';
  readonly codedWidth: number;
  readonly codedHeight: number;
  readonly optimizeForLatency: boolean;
}

/** The parts of an `EncodedVideoChunk` this module produces. */
export interface Vp8Chunk {
  readonly type: 'key' | 'delta';
  readonly timestamp: number;
  readonly data: Uint8Array;
}

/** What the reassembler needs of a WebCodecs `VideoDecoder`. */
export interface VideoDecoderPort {
  readonly decodeQueueSize: number;
  /** `'closed'` once closed (WebCodecs `CodecState`). */
  readonly state: string;
  configure(config: Vp8DecoderConfig): void;
  decode(chunk: Vp8Chunk): void;
  close(): void;
}

/** What the reassembler reads of a decoded `VideoFrame`. */
export interface DecodedVideoFrame {
  readonly codedWidth: number;
  readonly codedHeight: number;
  readonly visibleRect: { readonly width: number; readonly height: number } | null;
  close(): void;
}

export interface ShareReassemblerHooks<F extends DecodedVideoFrame> {
  /** Milliseconds, monotonic. */
  now(): number;
  /** Construct a decoder whose outputs go to `output` and whose errors go to `error`. */
  createDecoder(output: (frame: F) => void, error: (e: unknown) => void): VideoDecoderPort;
  /** Run `callback` on the next animation frame. */
  requestAnimationFrame(callback: () => void): void;
  /** Draw the frame's visible rectangle into the sharer's canvas at `width` × `height`. */
  draw(frame: F, width: number, height: number): void;
  /**
   * A new awaiting-keyframe period began (a gap, a discarded chunk, a decoder
   * reset, a new `share_seq`, …): start the keyframe-request schedule of
   * REQ-50. Not called for the awaiting state a watch starts in, nor again
   * while the share is still awaiting and nothing was decoded since.
   */
  onAwaitingKeyframe(): void;
  /**
   * Decoder setups were refused 3 times within 30 s (REQ-49): the
   * reassembler has closed itself; the owner stops watching the share and
   * shows "Video from [name] can't be displayed".
   */
  onCantDisplay(): void;
}

interface PartialFrame {
  readonly kid: number;
  readonly count: number;
  readonly flags: number;
  readonly w: number;
  readonly h: number;
  readonly parts: (Uint8Array | undefined)[];
  received: number;
  readonly firstAt: number;
  lastAt: number;
}

/**
 * One watched sharer's viewer state of §6.2.9: `{ state, shareSeq,
 * lastFrameNo, floorEpoch, partial (at most 4), decoder, codedW, codedH,
 * lastSetupAt, setupRefusals, budgets, pendingDraw }`.
 *
 * The owner runs §6.2.8: it calls `takeDecryption()` at step 7, decrypts,
 * parses the plaintext with `parseFragment` (step 10) and passes the result
 * to `onFragment` (step 11). It calls `sweep()` from a timer (a few times per
 * second) so incomplete frames expire, `reset()` when the sharer's keys are
 * erased or its instance replaced (REQ-35), and `close()` when watching ends.
 *
 * A watch starts in `awaiting_keyframe` with `shareSeq` 0, `lastFrameNo`
 * unset and `floorEpoch` −1; the owner sends the watch's first keyframe
 * request itself.
 */
export class ShareReassembler<F extends DecodedVideoFrame = DecodedVideoFrame> {
  private readonly hooks: ShareReassemblerHooks<F>;
  private st: ShareDecodeState = 'awaiting_keyframe';
  private seq = 0;
  private lastNo: number | null = null;
  private floor = -1;
  private readonly partial = new Map<number, PartialFrame>();
  private decoder: VideoDecoderPort | null = null;
  private codedW = 0;
  private codedH = 0;
  private lastSetupAt = -Infinity;
  private refusals: number[] = [];
  private readonly decryptions = new RateBudget(VIEW_DECRYPT_RATE);
  private readonly decodes = new RateBudget(VIEW_DECODE_RATE);
  private readonly keyframes = new RateBudget(VIEW_KEYFRAME_RATE);
  private pendingDraw: { frame: F; width: number; height: number } | null = null;
  private drawScheduled = false;
  private decodedSinceAwaiting = false;
  private lastDecoded: number | null = null;
  private closedFlag = false;

  constructor(hooks: ShareReassemblerHooks<F>) {
    this.hooks = hooks;
  }

  get state(): ShareDecodeState {
    return this.st;
  }
  get shareSeq(): number {
    return this.seq;
  }
  get lastFrameNo(): number | null {
    return this.lastNo;
  }
  get floorEpoch(): number {
    return this.floor;
  }
  get incompleteFrames(): number {
    return this.partial.size;
  }
  /** When the last decoded frame was accepted for drawing, or null. */
  get lastDecodedAt(): number | null {
    return this.lastDecoded;
  }
  /** The visible size of the authenticated key frame the decoder is configured for. */
  get decoderSize(): { width: number; height: number } | null {
    return this.decoder ? { width: this.codedW, height: this.codedH } : null;
  }
  get closed(): boolean {
    return this.closedFlag;
  }

  /**
   * §6.2.8 step 7: take a token from the sharer's decryption budget
   * (`VIEW_DECRYPT_RATE`). Without one the fragment is discarded undecrypted;
   * that is not an AEAD failure.
   */
  takeDecryption(): boolean {
    return !this.closedFlag && this.decryptions.take(this.hooks.now());
  }

  /** `onFragment(S, kid, h, payload)`: an authenticated, rule-checked fragment under epoch `kid`. */
  onFragment(kid: number, h: FragmentHeader, payload: Uint8Array): void {
    if (this.closedFlag || !fragmentRulesHold(h, payload.length)) return;
    this.sweep();
    if (this.closedFlag) return;
    if ((h.flags & FRAG_FLAG_KEY) === FRAG_FLAG_KEY && kid > this.floor) {
      // The first key-frame fragment under a newer epoch resets the floors.
      this.seq = h.shareSeq;
      this.lastNo = null;
      this.partial.clear();
      this.floor = kid;
    }
    if (h.shareSeq < this.seq) return;
    if (h.shareSeq > this.seq) {
      // A new share.
      this.seq = h.shareSeq;
      this.lastNo = null;
      this.partial.clear();
      this.floor = Math.max(this.floor, kid);
      this.enterAwaiting();
      if (this.closedFlag) return;
    }
    if (this.lastNo !== null && h.frameNo <= this.lastNo) return; // never go backwards
    const now = this.hooks.now();
    let p = this.partial.get(h.frameNo);
    if (!p) {
      if (this.partial.size >= REASSEMBLY_MAX) this.partial.delete(Math.min(...this.partial.keys()));
      p = { kid, count: h.fragCount, flags: h.flags, w: h.width, h: h.height, parts: new Array(h.fragCount), received: 0, firstAt: now, lastAt: now };
      this.partial.set(h.frameNo, p);
    }
    if (p.kid !== kid || p.count !== h.fragCount || p.flags !== h.flags || p.w !== h.width || p.h !== h.height || p.parts[h.fragIndex] !== undefined) {
      // A splice, an epoch mix or a duplicate index: drop the whole frame.
      this.partial.delete(h.frameNo);
      return;
    }
    p.parts[h.fragIndex] = payload;
    p.received += 1;
    p.lastAt = now;
    if (p.received < p.count) return;
    let length = 0;
    for (const part of p.parts) length += part!.length;
    const data = new Uint8Array(length);
    let o = 0;
    for (const part of p.parts) {
      data.set(part!, o);
      o += part!.length;
    }
    for (const no of [...this.partial.keys()]) if (no <= h.frameNo) this.partial.delete(no);
    this.onFrame(kid, h, data);
  }

  /** Delete incomplete frames idle for 1 s or started 10 s ago; such a loss awaits a key frame. */
  sweep(): void {
    if (this.closedFlag) return;
    const now = this.hooks.now();
    let lost = false;
    for (const [no, p] of [...this.partial]) {
      if (now - p.lastAt >= REASSEMBLY_IDLE_MS || now - p.firstAt >= REASSEMBLY_MAX_AGE_MS) {
        this.partial.delete(no);
        lost = true;
      }
    }
    if (lost) this.enterAwaiting();
  }

  /**
   * REQ-35: the sharer's keys were erased, or a new instance of the sharer
   * was recorded (`newInstance`, which also resets `shareSeq`, `lastFrameNo`
   * and `floorEpoch` as for a new watch). Buffers are discarded, the decoder
   * is closed, and the share awaits a key frame.
   */
  reset(newInstance: boolean): void {
    if (this.closedFlag) return;
    this.partial.clear();
    this.closeDecoder();
    if (newInstance) {
      this.seq = 0;
      this.lastNo = null;
      this.floor = -1;
    }
    this.enterAwaiting();
  }

  /** Watching ended: release the decoder, a frame waiting to be drawn and every buffer. */
  close(): void {
    if (this.closedFlag) return;
    this.closedFlag = true;
    this.partial.clear();
    this.closeDecoder();
  }

  private onFrame(kid: number, h: FragmentHeader, data: Uint8Array): void {
    const key = (h.flags & FRAG_FLAG_KEY) === FRAG_FLAG_KEY;
    const now = this.hooks.now();
    if (!this.decodes.take(now) || (key && !this.keyframes.take(now))) return this.enterAwaiting();
    if (!vp8TagOk(data, key)) return this.enterAwaiting();
    if (key) {
      const size = vp8KeySize(data);
      if (!size || size.width !== h.width || size.height !== h.height || !withinCaps(size.width, size.height)) return this.enterAwaiting();
      if (!this.decoder || this.decoder.state === 'closed' || size.width !== this.codedW || size.height !== this.codedH) {
        if (now - this.lastSetupAt < DECODER_SETUP_MIN_GAP_MS) {
          this.refusals = this.refusals.filter(t => now - t < DECODER_SETUP_REFUSAL_WINDOW_MS);
          this.refusals.push(now);
          if (this.refusals.length >= DECODER_SETUP_REFUSALS_MAX) {
            this.close();
            this.hooks.onCantDisplay();
            return;
          }
          return this.enterAwaiting();
        }
        if (!this.setUpDecoder(size.width, size.height, now)) return;
      }
      this.st = 'decoding';
    } else if (this.st !== 'decoding' || this.lastNo === null || h.frameNo !== this.lastNo + 1) {
      return this.enterAwaiting();
    }
    const decoder = this.decoder;
    if (!decoder || decoder.state === 'closed') return this.enterAwaiting();
    if (decoder.decodeQueueSize > DECODE_QUEUE_MAX) return this.enterAwaiting();
    try {
      decoder.decode({ type: key ? 'key' : 'delta', timestamp: h.frameNo * FRAME_TIMESTAMP_US, data });
    } catch {
      return this.onDecoderError(decoder);
    }
    this.lastNo = h.frameNo;
    this.floor = Math.max(this.floor, kid);
  }

  private setUpDecoder(width: number, height: number, now: number): boolean {
    this.closeDecoder();
    let created: VideoDecoderPort | null = null;
    const decoder = this.hooks.createDecoder(
      frame => this.onDecoded(created, frame),
      () => this.onDecoderError(created),
    );
    created = decoder;
    this.decoder = decoder;
    this.codedW = width;
    this.codedH = height;
    this.lastSetupAt = now;
    try {
      decoder.configure({ codec: 'vp8', codedWidth: width, codedHeight: height, optimizeForLatency: true });
    } catch {
      this.onDecoderError(decoder);
      return false;
    }
    return true;
  }

  private closeDecoder(): void {
    const d = this.decoder;
    this.decoder = null;
    if (d) {
      try {
        if (d.state !== 'closed') d.close();
      } catch {
        // already closed
      }
    }
    // Closing a decoder also closes a frame waiting to be drawn.
    if (this.pendingDraw) {
      this.pendingDraw.frame.close();
      this.pendingDraw = null;
    }
  }

  private onDecoderError(source: VideoDecoderPort | null): void {
    if (this.closedFlag || source === null || source !== this.decoder) return;
    this.closeDecoder();
    this.enterAwaiting();
  }

  /** `onDecoded(S, frame)`: the decoder's output callback. */
  private onDecoded(source: VideoDecoderPort | null, frame: F): void {
    if (this.closedFlag || source === null || source !== this.decoder) {
      frame.close();
      return;
    }
    const vr = frame.visibleRect;
    if (!vr || vr.width !== this.codedW || vr.height !== this.codedH
      || frame.codedWidth < vr.width || frame.codedHeight < vr.height
      || frame.codedWidth > VIDEO_CODED_MAX || frame.codedHeight > VIDEO_CODED_MAX) {
      frame.close();
      this.enterAwaiting();
      return;
    }
    // Keep only the newest decoded frame.
    if (this.pendingDraw) this.pendingDraw.frame.close();
    this.pendingDraw = { frame, width: vr.width, height: vr.height };
    this.lastDecoded = this.hooks.now();
    this.decodedSinceAwaiting = true;
    if (!this.drawScheduled) {
      this.drawScheduled = true;
      this.hooks.requestAnimationFrame(() => this.drawPending());
    }
  }

  private drawPending(): void {
    this.drawScheduled = false;
    const p = this.pendingDraw;
    if (this.closedFlag || !p) return;
    this.pendingDraw = null;
    try {
      this.hooks.draw(p.frame, p.width, p.height);
    } finally {
      p.frame.close();
    }
  }

  private enterAwaiting(): void {
    if (this.closedFlag) return;
    // Still awaiting with nothing decoded since: the request schedule continues.
    if (this.st === 'awaiting_keyframe' && !this.decodedSinceAwaiting) return;
    this.st = 'awaiting_keyframe';
    this.decodedSinceAwaiting = false;
    this.hooks.onAwaitingKeyframe();
  }
}
