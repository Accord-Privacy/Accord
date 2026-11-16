/**
 * Wire analysis and forgery for the SPEC-03 integration tests: what the
 * relay (HRP) sees of audio frames, fragments and call messages, how a
 * holder of a key (a departed member, the attacker of RG-C005 and
 * RG-C112) would try to open or seal them, and the legacy frame format of
 * bbf2f17 for the C005 reproductions.
 *
 * These helpers use the production AMF1 code (`voice/mediaFrame.ts`) only
 * as an attacker or analyst would: with keys taken from the harness's own
 * records, never through a client's state.
 */

import {
  AMF1_FORMAT,
  MEDIA_KIND_AUDIO,
  MEDIA_KIND_VIDEO,
  decodeSFrameHeader,
  deriveEpochKeys,
  frameContext,
  importHkdfKey,
  openFrame,
  parseFrame,
  sealFrame,
  type EpochKeys,
  type MediaKind,
} from '../../src/voice/mediaFrame';
import { encodeFragment, parseFragment, type FragmentHeader } from '../../src/voice/screenFrame';
import { decodeWireBase64, encodeBase64 } from '../../src/attachments/base64';
import { readMarker, syntheticVp8, type VideoMarker } from '../../src/voice/screenShare.testkit';
import { pcmMarker } from '../../src/voice/relay.testkit';
import { clientBody, screenDown, screenUp, typeOf, type HrpMessage } from './hrp';
import type { ReceivedKey } from './hc';

export { MEDIA_KIND_AUDIO, MEDIA_KIND_VIDEO, pcmMarker, syntheticVp8 };

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** An audio or video frame as it crossed the HRP. */
export interface WireFrame {
  readonly msg: HrpMessage;
  readonly kind: MediaKind;
  /** The sender: the relay-stamped `from` (s2c), or the connection's user (c2s). */
  readonly from: string;
  readonly channelId: string;
  readonly bytes: Uint8Array;
}

/** The audio frame or video fragment a recorded message carries, or null. */
export function wireFrame(m: HrpMessage): WireFrame | null {
  const t = typeOf(m);
  if (t === 'srtp_voice_packet' && m.json) {
    const bytes = typeof m.json.packet_data === 'string' ? decodeWireBase64(m.json.packet_data) : null;
    if (!bytes) return null;
    return { msg: m, kind: MEDIA_KIND_AUDIO, from: String(m.json.from).toLowerCase(), channelId: String(m.json.channel_id).toLowerCase(), bytes };
  }
  if (t === 'SrtpVoicePacket') {
    const body = clientBody(m);
    const bytes = body && typeof body.packet_data === 'string' ? decodeWireBase64(body.packet_data) : null;
    if (!bytes || !body) return null;
    return { msg: m, kind: MEDIA_KIND_AUDIO, from: m.conn.userId ?? '', channelId: String(body.channel_id).toLowerCase(), bytes };
  }
  if (t === 'SCREEN_DOWN') {
    const d = screenDown(m);
    return d ? { msg: m, kind: MEDIA_KIND_VIDEO, from: d.from, channelId: d.channelId, bytes: d.fragment } : null;
  }
  if (t === 'SCREEN_UP') {
    const u = screenUp(m);
    return u ? { msg: m, kind: MEDIA_KIND_VIDEO, from: m.conn.userId ?? '', channelId: u.channelId, bytes: u.fragment } : null;
  }
  return null;
}

/** KID and counter of an AMF1 frame's cleartext header, or null. */
export function frameHeader(bytes: Uint8Array): { format: number; kind: number; kid: number; ctr: number } | null {
  if (bytes.length < 3) return null;
  const h = decodeSFrameHeader(bytes, 2);
  return h ? { format: bytes[0], kind: bytes[1], kid: h.kid, ctr: h.ctr } : null;
}

const keyCache = new Map<string, Promise<EpochKeys>>();

/** Receiver (decrypt) or sender (encrypt) keys of an epoch secret, as any holder of the secret can derive them. */
export function keysOf(secret: Uint8Array, epoch: number, role: 'encrypt' | 'decrypt'): Promise<EpochKeys> {
  const id = `${hex(secret)}:${epoch}:${role}`;
  let p = keyCache.get(id);
  if (!p) {
    p = importHkdfKey(Uint8Array.from(secret)).then(base => deriveEpochKeys(base, epoch, role));
    keyCache.set(id, p);
  }
  return p;
}

export function instBytes(b64: string): Uint8Array {
  const b = decodeWireBase64(b64);
  if (!b || b.length !== 16) throw new Error('bad inst');
  return b;
}

/**
 * Try to open a frame with every key in `keys` that a holder could apply
 * (same sender, KID = epoch), as the attacker of RG-C112 or RG-SCR-9 would.
 * Returns the plaintext of the first success, or null.
 */
export async function openWithAny(frame: WireFrame, keys: readonly ReceivedKey[]): Promise<Uint8Array | null> {
  const parsed = parseFrame(frame.bytes, frame.kind);
  if (!parsed.ok) return null;
  for (const k of keys) {
    if (k.from !== frame.from || k.epoch !== parsed.kid) continue;
    const ek = await keysOf(k.secret, k.epoch, 'decrypt');
    const pt = await openFrame(parsed, ek, frameContext(frame.channelId, frame.from, instBytes(k.inst)));
    if (pt) return pt;
  }
  return null;
}

/** Try to open with `secret` used as the base key under the frame's KID, for every instance in `insts` (RG-C005-1). */
export async function openWithBaseKey(frame: WireFrame, secret: Uint8Array, insts: readonly Uint8Array[]): Promise<boolean> {
  const parsed = parseFrame(frame.bytes, frame.kind);
  if (!parsed.ok) return false;
  const ek = await keysOf(secret, parsed.kid, 'decrypt');
  for (const inst of insts) {
    if (await openFrame(parsed, ek, frameContext(frame.channelId, frame.from, inst))) return true;
  }
  return false;
}

/** Seal an AMF1 frame under `secret` as epoch `epoch`, as a key holder forging frames would. */
export async function sealWith(
  secret: Uint8Array,
  epoch: number,
  kind: MediaKind,
  ctr: number,
  ctx: { channelId: string; senderId: string; inst: Uint8Array },
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const ek = await keysOf(secret, epoch, 'encrypt');
  return sealFrame(kind, ek, ctr, frameContext(ctx.channelId, ctx.senderId, ctx.inst), plaintext);
}

/** The audio marker (tag, frame number) in a decrypted audio plaintext (`codec ‖ samples`). */
export function audioMarker(plaintext: Uint8Array): { tag: number; n: number } | null {
  if (plaintext.length < 5 || plaintext[0] !== 0x00) return null;
  const v = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);
  return { tag: v.getInt16(1, true), n: v.getInt16(3, true) };
}

/** The fragment header and, for fragment 0, the video marker of a decrypted fragment plaintext. */
export function videoFragmentInfo(plaintext: Uint8Array): { header: FragmentHeader; marker: VideoMarker | null } | null {
  const f = parseFragment(plaintext);
  if (!f) return null;
  return { header: f.header, marker: f.header.fragIndex === 0 ? readMarker(f.payload) : null };
}

/** One forged single-fragment video frame plaintext (§6.2.7) carrying a synthetic VP8 frame. */
export function forgedFragmentPlaintext(h: Omit<FragmentHeader, 'fragIndex' | 'fragCount'> & { fragIndex?: number; fragCount?: number }, vp8: Uint8Array): Uint8Array {
  return encodeFragment({ fragIndex: 0, fragCount: 1, ...h }, vp8);
}

// ---------------------------------------------------------------------------
// The legacy client of bbf2f17 (C005): raw AES-GCM keys and its frame layout
// ---------------------------------------------------------------------------

/** `voiceCrypto.ts` at bbf2f17: 12-byte nonce (4-byte LE sequence, 8 random) ‖ AES-GCM ciphertext, no AAD. */
export async function legacyEncrypt(rawKey: Uint8Array, plaintext: Uint8Array, sequence: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', Uint8Array.from(rawKey), 'AES-GCM', false, ['encrypt']);
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setUint32(0, sequence, true);
  crypto.getRandomValues(nonce.subarray(4));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, Uint8Array.from(plaintext)));
  const out = new Uint8Array(12 + ct.length);
  out.set(nonce);
  out.set(ct, 12);
  return out;
}

/** `decryptVoiceFrame` of bbf2f17. */
export async function legacyDecrypt(rawKey: Uint8Array, data: Uint8Array): Promise<Uint8Array | null> {
  if (data.length < 28 || ![16, 24, 32].includes(rawKey.length)) return null;
  try {
    const key = await crypto.subtle.importKey('raw', Uint8Array.from(rawKey), 'AES-GCM', false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), tagLength: 128 }, key, data.slice(12)));
  } catch {
    return null;
  }
}

/** base64 of bytes (the legacy `wrapped_key` of a raw key). */
export function b64(bytes: Uint8Array): string {
  return encodeBase64(bytes);
}

/** Decode a `wrapped_key` as the C005 reproduction does: plain `atob`, also after stripping a prefix. */
export function decodeWrappedCandidates(wrapped: string): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const s of [wrapped, wrapped.replace(/^[a-z0-9]+:/, '')]) {
    try {
      out.push(Uint8Array.from(atob(s), c => c.charCodeAt(0)));
    } catch {
      // not base64
    }
  }
  return out;
}

export const AMF1 = AMF1_FORMAT;
