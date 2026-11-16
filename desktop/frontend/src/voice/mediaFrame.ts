/**
 * @module voice/mediaFrame
 * The Accord media frame, version 1 (AMF1; SPEC-03 §6.2.1 to §6.2.6).
 *
 * An AMF1 frame is `format (0x01) ‖ media_kind ‖ SFrame header ‖ ciphertext ‖
 * tag`, sealed with RFC 9605 cipher suite AES_256_GCM_SHA512_128 (0x0005):
 *
 * - the SFrame header (RFC 9605 §4.3) carries KID = the sender's epoch and
 *   CTR = the counter of the media kind (CTR for audio, VCTR for video);
 * - key and salt come from HKDF-SHA512 per epoch (RFC 9605 §4.4.2): from the
 *   epoch secret for audio (0x01), from the screen base key for video (0x02);
 * - nonce = salt XOR the counter as a 96-bit big-endian integer;
 * - AAD = the header bytes as transmitted ‖ the 50-byte metadata
 *   `format ‖ media_kind ‖ channel_id ‖ sender_user_id ‖ sender_inst`.
 *
 * Keys are kept per (media kind, KID): an `EpochKeys` holds one `KindKeys`
 * per kind, and sealing and opening pick the key of the frame's kind, so a
 * key of one kind is never used for the other (§6.2.4, REQ-14). Frame keys
 * and base keys are non-extractable Web Crypto keys; a sender's keys may only
 * encrypt and a receiver's only decrypt (REQ-14, REQ-27).
 *
 * This module never logs and never stores anything.
 */

import { isCanonicalUuid } from '../attachments/envelope';

// ---------------------------------------------------------------------------
// Constants (§6.2.1, §6.5)
// ---------------------------------------------------------------------------

/** `format` byte of AMF1. 0x02 is reserved for stage 2; all others reserved. */
export const AMF1_FORMAT = 0x01;
/** Media kind of audio frames, carried in `srtp_voice_packet`. */
export const MEDIA_KIND_AUDIO = 0x01;
/** Media kind of screen video fragments, carried in `SCREEN_DOWN` (A1). */
export const MEDIA_KIND_VIDEO = 0x02;
export type MediaKind = typeof MEDIA_KIND_AUDIO | typeof MEDIA_KIND_VIDEO;

/** RFC 9605 AES_256_GCM_SHA512_128. */
export const CALL_SUITE = 0x0005;

/** Audio frame size bounds (`FRAME_MIN`, `FRAME_MAX`). */
export const FRAME_MIN = 20;
export const FRAME_MAX = 4096;
/** Video fragment size bounds (`FRAG_MIN`, `FRAG_MAX`, A1). */
export const FRAG_MIN = 20;
export const FRAG_MAX = 16_384;

/** KIDs of v1 are below 2^32. */
export const KID_LIMIT = 2 ** 32;
/** CTR and VCTR are below 2^48 (`CTR_LIMIT`). */
export const CTR_LIMIT = 2 ** 48;

export const SECRET_LEN = 32;
export const INST_LEN = 16;
export const KEY_LEN = 32;
export const SALT_LEN = 12;
export const TAG_LEN = 16;
export const METADATA_LEN = 50;

/** Audio plaintext codec bytes (§6.2.1). Other values are reserved. */
export const AUDIO_CODEC_PCM16 = 0x00;
export const AUDIO_CODEC_OPUS = 0x01;

/** The 27 ASCII bytes of the screen base key label (§6.2.4, A1). */
export const SCREEN_BASE_LABEL = 'Accord AMF1 screen base key';

const ascii = new TextEncoder();
const KEY_LABEL = ascii.encode('SFrame 1.0 Secret key ');
const SALT_LABEL = ascii.encode('SFrame 1.0 Secret salt ');
const SCREEN_LABEL_BYTES = ascii.encode(SCREEN_BASE_LABEL);
const EMPTY = new Uint8Array(0);

/** The frame size bounds of a media kind. */
export function frameSizeBounds(kind: MediaKind): { min: number; max: number } {
  return kind === MEDIA_KIND_AUDIO ? { min: FRAME_MIN, max: FRAME_MAX } : { min: FRAG_MIN, max: FRAG_MAX };
}

export function isMediaKind(k: number): k is MediaKind {
  return k === MEDIA_KIND_AUDIO || k === MEDIA_KIND_VIDEO;
}

function isUint(n: number, limit: number): boolean {
  return Number.isSafeInteger(n) && n >= 0 && n < limit;
}

/** Web Crypto takes `BufferSource`; every buffer here is a plain ArrayBuffer view. */
function bs(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return u as Uint8Array<ArrayBuffer>;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// SFrame header (§6.2.2, RFC 9605 §4.3)
// ---------------------------------------------------------------------------

/** Minimal big-endian bytes of a non-negative safe integer (empty for 0). */
function minimalBigEndian(v: number): number[] {
  const out: number[] = [];
  while (v > 0) {
    out.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return out;
}

/**
 * Encode the SFrame header for (KID, CTR) with minimal encodings. Throws a
 * RangeError for KID ≥ 2^32 or CTR ≥ 2^48 (not representable in v1).
 */
export function encodeSFrameHeader(kid: number, ctr: number): Uint8Array<ArrayBuffer> {
  if (!isUint(kid, KID_LIMIT)) throw new RangeError('KID out of range');
  if (!isUint(ctr, CTR_LIMIT)) throw new RangeError('CTR out of range');
  const kb = kid < 8 ? [] : minimalBigEndian(kid);
  const cb = ctr < 8 ? [] : minimalBigEndian(ctr);
  const cfg = ((kid < 8 ? 0 : 1) << 7) | ((kid < 8 ? kid : kb.length - 1) << 4)
    | ((ctr < 8 ? 0 : 1) << 3) | (ctr < 8 ? ctr : cb.length - 1);
  return Uint8Array.from([cfg, ...kb, ...cb]);
}

export interface SFrameHeader {
  readonly kid: number;
  readonly ctr: number;
  /** Header length in bytes, config byte included. */
  readonly length: number;
}

/**
 * Read one extended field of `n` bytes at `at`. Null when it is not minimal
 * (a value below 8, or a leading zero byte) or does not fit below 2^(8·max).
 */
function readExtended(bytes: Uint8Array, at: number, n: number, maxBytes: number): number | null {
  if (n > 1 && bytes[at] === 0) return null; // leading zero byte
  if (n > maxBytes) return null; // ≥ 2^(8·maxBytes), since it is minimal
  let v = 0;
  for (let i = 0; i < n; i++) v = v * 256 + bytes[at + i];
  if (v < 8) return null; // belongs in the config byte
  return v;
}

/**
 * Decode an SFrame header at `offset` (§6.2.2). Returns null when the header
 * claims more bytes than remain, uses a non-minimal encoding, or has KID ≥
 * 2^32 or CTR ≥ 2^48.
 */
export function decodeSFrameHeader(bytes: Uint8Array, offset = 0): SFrameHeader | null {
  if (offset >= bytes.length) return null;
  const cfg = bytes[offset];
  const x = cfg >> 7;
  const k = (cfg >> 4) & 7;
  const y = (cfg >> 3) & 1;
  const c = cfg & 7;
  const kidLen = x ? k + 1 : 0;
  const ctrLen = y ? c + 1 : 0;
  const length = 1 + kidLen + ctrLen;
  if (offset + length > bytes.length) return null;
  let kid = k;
  if (x) {
    const v = readExtended(bytes, offset + 1, kidLen, 4);
    if (v === null) return null;
    kid = v;
  }
  let ctr = c;
  if (y) {
    const v = readExtended(bytes, offset + 1 + kidLen, ctrLen, 6);
    if (v === null) return null;
    ctr = v;
  }
  return { kid, ctr, length };
}

// ---------------------------------------------------------------------------
// Metadata (§6.2.3)
// ---------------------------------------------------------------------------

/**
 * The 16 bytes of a UUID in RFC 9562 order: the 32 hex digits of its
 * canonical form, compared in lowercase. Throws a TypeError if malformed.
 */
export function uuidToBytes(uuid: string): Uint8Array<ArrayBuffer> {
  const s = uuid.toLowerCase();
  if (!isCanonicalUuid(s)) throw new TypeError('not a canonical UUID');
  const hex = s.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** The lowercase canonical UUID of 16 bytes. */
export function bytesToUuid(b: Uint8Array): string {
  if (b.length !== 16) throw new TypeError('a UUID has 16 bytes');
  const h = Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Who and where a frame belongs to: the active channel, the sender's user id
 * and the sender's instance, as bytes. A sender uses its own id and `inst`;
 * a receiver the relay-stamped `from` and currentInst(from) (§6.2.3).
 */
export interface FrameContext {
  readonly channelId: Uint8Array;
  readonly senderId: Uint8Array;
  readonly inst: Uint8Array;
}

export function frameContext(channelId: string, senderId: string, inst: Uint8Array): FrameContext {
  if (inst.length !== INST_LEN) throw new TypeError('an instance has 16 bytes');
  return { channelId: uuidToBytes(channelId), senderId: uuidToBytes(senderId), inst: Uint8Array.from(inst) };
}

/** `format ‖ media_kind ‖ channel_id ‖ sender_user_id ‖ sender_inst` (50 bytes). */
export function buildMetadata(kind: MediaKind, ctx: FrameContext, format: number = AMF1_FORMAT): Uint8Array<ArrayBuffer> {
  if (ctx.channelId.length !== 16 || ctx.senderId.length !== 16 || ctx.inst.length !== INST_LEN) {
    throw new TypeError('malformed frame context');
  }
  return concat(Uint8Array.of(format, kind), ctx.channelId, ctx.senderId, ctx.inst);
}

// ---------------------------------------------------------------------------
// Key schedule (§6.2.4)
// ---------------------------------------------------------------------------

/** What a frame key may do: a sender's keys encrypt, a receiver's decrypt (REQ-14). */
export type KeyRole = 'encrypt' | 'decrypt';

/** The SFrame key and salt of one media kind for one epoch. */
export interface KindKeys {
  readonly kind: MediaKind;
  readonly epoch: number;
  readonly role: KeyRole;
  /** Non-extractable AES-256-GCM key, usable for `role` only. */
  readonly key: CryptoKey;
  /** 12-byte SFrame salt. Zero-filled by `eraseEpochKeys`. */
  readonly salt: Uint8Array;
}

/** Both media kinds' keys of one epoch, installed and erased together (REQ-45). */
export interface EpochKeys {
  readonly epoch: number;
  readonly role: KeyRole;
  readonly audio: KindKeys;
  readonly video: KindKeys;
}

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  const hi = Math.floor(n / 2 ** 32);
  const lo = n % 2 ** 32;
  new DataView(out.buffer).setUint32(0, hi);
  new DataView(out.buffer).setUint32(4, lo);
  return out;
}

function sframeLabel(prefix: Uint8Array, epoch: number): Uint8Array<ArrayBuffer> {
  return concat(prefix, u64be(epoch), Uint8Array.of(CALL_SUITE >> 8, CALL_SUITE & 0xff));
}

function hkdfParams(info: Uint8Array): HkdfParams {
  return { name: 'HKDF', hash: 'SHA-512', salt: bs(EMPTY), info: bs(info) };
}

/**
 * Import key bytes as a non-extractable HKDF base key. Web Crypto copies the
 * bytes before this returns its promise, so with `wipe` the caller's buffer is
 * zero-filled at once (REQ-27: a receiver zero-fills a decoded secret
 * immediately after importing it; screen base key bytes likewise).
 */
export function importHkdfKey(bytes: Uint8Array, opts: { wipe?: boolean } = {}): Promise<CryptoKey> {
  const p = crypto.subtle.importKey('raw', bs(bytes), 'HKDF', false, ['deriveKey', 'deriveBits']);
  if (opts.wipe) bytes.fill(0);
  return p;
}

/**
 * RFC 9605 §4.4.2 for suite 0x0005 (`deriveEpochKeys` of §6.2.4):
 *   prk  = HKDF-Extract-SHA512(salt = empty, ikm = baseKey)
 *   key  = HKDF-Expand-SHA512(prk, "SFrame 1.0 Secret key "  ‖ u64be(epoch) ‖ u16be(5), 32)
 *   salt = HKDF-Expand-SHA512(prk, "SFrame 1.0 Secret salt " ‖ u64be(epoch) ‖ u16be(5), 12)
 * `baseKey` is an HKDF key from `importHkdfKey`; any base key length works
 * (RFC 9605 Appendix C.3 uses 16 bytes).
 */
export async function deriveSFrameKeys(baseKey: CryptoKey, epoch: number, kind: MediaKind, role: KeyRole): Promise<KindKeys> {
  if (!isUint(epoch, KID_LIMIT)) throw new RangeError('epoch out of range');
  if (!isMediaKind(kind)) throw new RangeError('unknown media kind');
  const [key, saltBits] = await Promise.all([
    crypto.subtle.deriveKey(hkdfParams(sframeLabel(KEY_LABEL, epoch)), baseKey, { name: 'AES-GCM', length: 256 }, false, [role]),
    crypto.subtle.deriveBits(hkdfParams(sframeLabel(SALT_LABEL, epoch)), baseKey, SALT_LEN * 8),
  ]);
  return { kind, epoch, role, key, salt: new Uint8Array(saltBits) };
}

/**
 * The screen base key bytes, `screenBase(epochSecret)` of §6.2.4:
 * HKDF-Expand-SHA512(HKDF-Extract-SHA512(empty, epochSecret), "Accord AMF1
 * screen base key", 32). The caller must zero-fill the result once used.
 */
export async function deriveScreenBaseBytes(epochSecret: CryptoKey): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.deriveBits(hkdfParams(SCREEN_LABEL_BYTES), epochSecret, 256));
}

/**
 * The screen base key as a non-extractable HKDF key. Its bytes are
 * zero-filled right after the import (REQ-27).
 */
export async function deriveScreenBaseKey(epochSecret: CryptoKey): Promise<CryptoKey> {
  return importHkdfKey(await deriveScreenBaseBytes(epochSecret), { wipe: true });
}

/**
 * `keysFor` both media kinds of an epoch (§6.2.4, REQ-45): audio from the
 * epoch secret, video from the screen base key. `epochSecret` is the epoch
 * secret imported with `importHkdfKey`. Keys are derived once per epoch.
 */
export async function deriveEpochKeys(epochSecret: CryptoKey, epoch: number, role: KeyRole): Promise<EpochKeys> {
  const [audio, video] = await Promise.all([
    deriveSFrameKeys(epochSecret, epoch, MEDIA_KIND_AUDIO, role),
    deriveScreenBaseKey(epochSecret).then(base => deriveSFrameKeys(base, epoch, MEDIA_KIND_VIDEO, role)),
  ]);
  return { epoch, role, audio, video };
}

/** The keys of one media kind. Stores are keyed by (kind, KID), never KID alone. */
export function keysFor(keys: EpochKeys, kind: MediaKind): KindKeys {
  if (kind === MEDIA_KIND_AUDIO) return keys.audio;
  if (kind === MEDIA_KIND_VIDEO) return keys.video;
  throw new RangeError('unknown media kind');
}

/**
 * Zero-fill an epoch's salts. Web Crypto keys cannot be wiped; dropping every
 * reference to `keys` releases them.
 */
export function eraseEpochKeys(keys: EpochKeys): void {
  keys.audio.salt.fill(0);
  keys.video.salt.fill(0);
}

// ---------------------------------------------------------------------------
// SFrame encryption (§6.2.5, RFC 9605 §4.4.3 and §4.4.4)
// ---------------------------------------------------------------------------

/** salt XOR u96be(ctr). */
export function sframeNonce(salt: Uint8Array, ctr: number): Uint8Array<ArrayBuffer> {
  if (salt.length !== SALT_LEN) throw new TypeError('the salt has 12 bytes');
  if (!isUint(ctr, CTR_LIMIT)) throw new RangeError('CTR out of range');
  const nonce = Uint8Array.from(salt);
  let v = ctr;
  for (let i = SALT_LEN - 1; i >= SALT_LEN - 6; i--) {
    nonce[i] ^= v % 256;
    v = Math.floor(v / 256);
  }
  return nonce;
}

/**
 * RFC 9605 encrypt: `header ‖ AES-256-GCM(key, salt ⊕ ctr, header ‖ metadata,
 * plaintext)`, with a 16-byte tag. `metadata` is appended to the AAD as is.
 */
export async function sframeEncrypt(k: KindKeys, ctr: number, metadata: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  const header = encodeSFrameHeader(k.epoch, ctr);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: sframeNonce(k.salt, ctr), additionalData: concat(header, metadata), tagLength: 128 },
    k.key,
    bs(plaintext),
  );
  return concat(header, new Uint8Array(ct));
}

/**
 * RFC 9605 decrypt of `ciphertext ‖ tag` under `header` (the bytes exactly as
 * received). Null when authentication fails, or when `k` is not the key of
 * the header's KID.
 */
export async function sframeDecrypt(k: KindKeys, header: Uint8Array, metadata: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array<ArrayBuffer> | null> {
  const h = decodeSFrameHeader(header);
  if (!h || h.length !== header.length || h.kid !== k.epoch) return null;
  if (ciphertext.length < TAG_LEN) return null;
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: sframeNonce(k.salt, h.ctr), additionalData: concat(header, metadata), tagLength: 128 },
      k.key,
      bs(ciphertext),
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/**
 * `sealFrame` of §6.2.5: `[0x01, kind] ‖ SFrame(header(epoch, ctr), …)` with
 * AAD = header ‖ metadata(0x01, kind, ctx). The caller reserved `ctr` from the
 * kind's counter before calling (it is never reused, even if this fails), and
 * hands off each kind's frames in counter order (REQ-6). Throws if the frame
 * would fall outside the kind's size bounds.
 */
export async function sealFrame(kind: MediaKind, keys: EpochKeys, ctr: number, ctx: FrameContext, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (keys.role !== 'encrypt') throw new TypeError('sealing needs sender keys');
  const k = keysFor(keys, kind);
  const { min, max } = frameSizeBounds(kind);
  const size = 2 + encodeSFrameHeader(k.epoch, ctr).length + plaintext.length + TAG_LEN;
  if (plaintext.length < 1 || size < min || size > max) throw new RangeError('frame size out of bounds');
  const body = await sframeEncrypt(k, ctr, buildMetadata(kind, ctx), plaintext);
  return concat(Uint8Array.of(AMF1_FORMAT, kind), body);
}

/** Why `parseFrame` discarded a frame: the check of §6.2.6 or §6.2.8 that failed. */
export type FrameRejection = 'length' | 'format' | 'kind' | 'header';

export type ParsedFrame =
  | {
    readonly ok: true;
    readonly kind: MediaKind;
    readonly kid: number;
    readonly ctr: number;
    /** The SFrame header bytes as received (part of the AAD). */
    readonly header: Uint8Array;
    /** Ciphertext ‖ tag. */
    readonly ciphertext: Uint8Array;
  }
  | { readonly ok: false; readonly reason: FrameRejection };

/**
 * The pre-decryption checks of §6.2.6 steps 2 to 4 (audio) and §6.2.8 steps 2
 * to 4 (video), in order: size bounds of the transport's kind; format 0x01;
 * media kind equal to `transportKind` (0x01 for `srtp_voice_packet`, 0x02
 * for `SCREEN_DOWN`; REQ-14, REQ-26); a minimal header with KID < 2^32 and
 * CTR < 2^48. No state changes and no decryption.
 */
export function parseFrame(bytes: Uint8Array, transportKind: MediaKind): ParsedFrame {
  const { min, max } = frameSizeBounds(transportKind);
  if (bytes.length < min || bytes.length > max) return { ok: false, reason: 'length' };
  if (bytes[0] !== AMF1_FORMAT) return { ok: false, reason: 'format' };
  if (bytes[1] !== transportKind) return { ok: false, reason: 'kind' };
  const h = decodeSFrameHeader(bytes, 2);
  if (!h) return { ok: false, reason: 'header' };
  if (bytes.length - 2 - h.length < TAG_LEN) return { ok: false, reason: 'header' };
  return {
    ok: true,
    kind: transportKind,
    kid: h.kid,
    ctr: h.ctr,
    header: bytes.subarray(2, 2 + h.length),
    ciphertext: bytes.subarray(2 + h.length),
  };
}

/**
 * The AEAD step of §6.2.6 step 7 and §6.2.8 step 8: decrypt with the key of
 * the frame's media kind for its KID, and AAD = received header ‖
 * metadata(0x01, kind, ctx), where `ctx` is built from the receiver's own
 * state (C, the relay-stamped sender, currentInst(sender); REQ-14). Null on
 * any failure, including keys of another epoch. Committing the replay window
 * and the epoch floor is the caller's next step.
 */
export async function openFrame(frame: Extract<ParsedFrame, { ok: true }>, keys: EpochKeys, ctx: FrameContext): Promise<Uint8Array<ArrayBuffer> | null> {
  if (keys.role !== 'decrypt' || keys.epoch !== frame.kid) return null;
  return sframeDecrypt(keysFor(keys, frame.kind), frame.header, buildMetadata(frame.kind, ctx), frame.ciphertext);
}
