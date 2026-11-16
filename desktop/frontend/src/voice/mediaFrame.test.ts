// @vitest-environment node
/**
 * SPEC-03 T-14 (REQ-14), with the frame parts of T-3 and T-26: AMF1 against
 * the shared vector file `core/tests/vectors/amf1-v1.json` (§6.11), which
 * `core/tests/amf1_vectors.rs` checks in Rust, plus RFC 9605 Appendix C.1 and
 * C.3, key usages, non-extractable keys and the per-kind key separation of A1.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  AMF1_FORMAT,
  FRAG_MAX,
  FRAME_MAX,
  MEDIA_KIND_AUDIO,
  MEDIA_KIND_VIDEO,
  SCREEN_BASE_LABEL,
  buildMetadata,
  decodeSFrameHeader,
  deriveEpochKeys,
  deriveScreenBaseBytes,
  deriveSFrameKeys,
  encodeSFrameHeader,
  eraseEpochKeys,
  frameContext,
  importHkdfKey,
  keysFor,
  openFrame,
  parseFrame,
  sealFrame,
  sframeDecrypt,
  sframeEncrypt,
  type EpochKeys,
  type FrameContext,
  type KindKeys,
  type MediaKind,
} from './mediaFrame';
import { encodeFragment, parseFragment, decodeScreenDown, decodeScreenUp, encodeScreenDown, encodeScreenUp, type FragmentHeader } from './screenFrame';
import { parseCallPayload } from './callPayload';

const REPO_ROOT = join(process.cwd(), '..', '..');
const V: any = JSON.parse(readFileSync(join(REPO_ROOT, 'core/tests/vectors/amf1-v1.json'), 'utf8'));

const unhex = (h: string): Uint8Array => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};
const hex = (b: Uint8Array): string => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');

/** Epoch keys of both kinds from secret bytes. */
async function epochKeys(secretHex: string, epoch: number, role: 'encrypt' | 'decrypt'): Promise<EpochKeys> {
  return deriveEpochKeys(await importHkdfKey(unhex(secretHex)), epoch, role);
}

/** True when `k` (an encrypt key) is the AES-256-GCM key `rawHex`: same output on the same input. */
async function sameKey(k: KindKeys, rawHex: string): Promise<boolean> {
  const raw = await crypto.subtle.importKey('raw', unhex(rawHex) as Uint8Array<ArrayBuffer>, 'AES-GCM', false, ['encrypt']);
  const iv = new Uint8Array(12).fill(7);
  const pt = new TextEncoder().encode('known-answer probe for a non-extractable key');
  const a = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k.key, pt));
  const b = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, raw, pt));
  return hex(a) === hex(b);
}

function ctxOf(v: { channel_id: string; sender_id: string; inst: string }): FrameContext {
  return frameContext(v.channel_id, v.sender_id, unhex(v.inst));
}

/**
 * The receiver of §6.2.6 / §6.2.8 for a vector context: parse for the
 * transport's kind, derive the context's keys for the frame's KID, open, and
 * for video apply the §6.2.7 rules. Returns the first failing stage, or the
 * plaintext.
 */
async function receive(bytes: Uint8Array, kind: MediaKind, secretHex: string, ctx: FrameContext): Promise<{ stage: string } | { pt: Uint8Array }> {
  const parsed = parseFrame(bytes, kind);
  if (!parsed.ok) return { stage: parsed.reason };
  const keys = await epochKeys(secretHex, parsed.kid, 'decrypt');
  const pt = await openFrame(parsed, keys, ctx);
  if (!pt) return { stage: 'aead' };
  if (kind === MEDIA_KIND_VIDEO && !parseFragment(pt)) return { stage: 'fragment' };
  return { pt };
}

describe('vector file', () => {
  it('is version 1 of suite 5 and has every section of §6.11', () => {
    expect(V.version).toBe(1);
    expect(V.suite).toBe(5);
    for (const s of ['headers', 'key_schedule', 'metadata', 'frames', 'negative', 'call_payloads', 'screen_base', 'video_key_schedule', 'video_fragments', 'video_negative', 'screen_wire', 'vp8_headers']) {
      expect(Array.isArray(V[s]) && V[s].length > 0, s).toBe(true);
    }
  });
});

describe('SFrame header (§6.2.2, RFC 9605 §4.3 and Appendix C.1)', () => {
  it('encodes and decodes every in-range vector exactly', () => {
    const rfc = V.headers.filter((h: { source: string }) => h.source === 'rfc9605-c1');
    expect(rfc.length).toBeGreaterThan(100);
    for (const h of V.headers) {
      expect(hex(encodeSFrameHeader(h.kid, h.ctr)), `${h.kid}/${h.ctr}`).toBe(h.hex);
      const bytes = unhex(h.hex);
      expect(decodeSFrameHeader(bytes)).toEqual({ kid: h.kid, ctr: h.ctr, length: bytes.length });
    }
  });

  it('covers the KIDs and CTRs §6.11 names', () => {
    const kids = new Set(V.headers.map((h: { kid: number }) => h.kid));
    const ctrs = new Set(V.headers.map((h: { ctr: number }) => h.ctr));
    for (const k of [0, 7, 8, 255, 256, 0x123, 2 ** 32 - 1]) expect(kids.has(k)).toBe(true);
    for (const c of [0, 7, 8, 255, 256, 0x4567, 2 ** 48 - 1]) expect(ctrs.has(c)).toBe(true);
  });

  it('rejects RFC 9605 headers with KID ≥ 2^32 or CTR ≥ 2^48', () => {
    expect(V.headers_out_of_range.length).toBeGreaterThan(100);
    for (const h of V.headers_out_of_range) expect(decodeSFrameHeader(unhex(h.hex)), h.hex).toBeNull();
    expect(() => encodeSFrameHeader(2 ** 32, 0)).toThrow(RangeError);
    expect(() => encodeSFrameHeader(0, 2 ** 48)).toThrow(RangeError);
  });

  it('matches the §6.2.2 example and rejects non-minimal and truncated headers', () => {
    expect(hex(encodeSFrameHeader(0x123, 0x4567))).toBe('9901234567');
    expect(decodeSFrameHeader(unhex('8005'))).toBeNull(); // extended KID below 8
    expect(decodeSFrameHeader(unhex('900009'))).toBeNull(); // leading zero byte
    expect(decodeSFrameHeader(unhex('3803'))).toBeNull(); // extended CTR below 8
    expect(decodeSFrameHeader(unhex('390012'))).toBeNull();
    expect(decodeSFrameHeader(unhex('ff0102'))).toBeNull(); // claims 16 more bytes
    expect(decodeSFrameHeader(new Uint8Array(0))).toBeNull();
    for (const name of ['kid_too_large', 'ctr_too_large', 'truncated_header', 'non_minimal_kid', 'non_minimal_ctr']) {
      const v = V.negative.find((n: { name: string }) => n.name === name);
      expect(decodeSFrameHeader(unhex(v.frame), 2), name).toBeNull();
    }
  });
});

describe('key schedule (§6.2.4, RFC 9605 §4.4.2 and Appendix C.3)', () => {
  it('reproduces the RFC 9605 Appendix C.3 suite 0x0005 vector with its 16-byte base key', async () => {
    const c3 = V.rfc9605_c3;
    expect(unhex(c3.base_key).length).toBe(16);
    const base = await importHkdfKey(unhex(c3.base_key));
    const enc = await deriveSFrameKeys(base, c3.kid, MEDIA_KIND_AUDIO, 'encrypt');
    expect(hex(enc.salt)).toBe(c3.salt);
    expect(await sameKey(enc, c3.key)).toBe(true);
    const ct = await sframeEncrypt(enc, c3.ctr, unhex(c3.metadata), unhex(c3.pt));
    expect(hex(ct)).toBe(c3.ct);
    const dec = await deriveSFrameKeys(base, c3.kid, MEDIA_KIND_AUDIO, 'decrypt');
    const h = decodeSFrameHeader(unhex(c3.ct))!;
    const pt = await sframeDecrypt(dec, unhex(c3.ct).subarray(0, h.length), unhex(c3.metadata), unhex(c3.ct).subarray(h.length));
    expect(hex(pt!)).toBe(c3.pt);
  });

  it('matches every key_schedule entry', async () => {
    for (const v of V.key_schedule) {
      const k = await deriveSFrameKeys(await importHkdfKey(unhex(v.base_key)), v.kid, MEDIA_KIND_AUDIO, 'encrypt');
      expect(hex(k.salt), `${v.kid}`).toBe(v.salt);
      expect(await sameKey(k, v.key), `${v.kid}`).toBe(true);
    }
  });

  it('A1: screen_base and video_key_schedule match, and audio and video keys of an epoch differ', async () => {
    expect(new TextEncoder().encode(SCREEN_BASE_LABEL).length).toBe(27);
    for (const v of V.screen_base) {
      expect(hex(await deriveScreenBaseBytes(await importHkdfKey(unhex(v.epoch_secret))))).toBe(v.screen_base);
    }
    const secrets = new Set(V.video_key_schedule.map((v: { epoch_secret: string }) => v.epoch_secret));
    expect(secrets.has('00'.repeat(32)) && secrets.has('ff'.repeat(32)) && secrets.size >= 3).toBe(true);
    for (const v of V.video_key_schedule) {
      const keys = await epochKeys(v.epoch_secret, v.kid, 'encrypt');
      expect(hex(keys.video.salt)).toBe(v.salt);
      expect(await sameKey(keys.video, v.key)).toBe(true);
      expect(hex(keys.audio.salt)).toBe(v.audio_salt);
      expect(await sameKey(keys.audio, v.audio_key)).toBe(true);
      expect(v.key).not.toBe(v.audio_key);
      expect(await sameKey(keys.video, v.audio_key)).toBe(false);
    }
  });
});

describe('metadata (§6.2.3)', () => {
  it('matches every vector', () => {
    for (const v of V.metadata) {
      const md = buildMetadata(v.kind, ctxOf(v), v.format);
      expect(md.length).toBe(50);
      expect(hex(md)).toBe(v.hex);
    }
  });

  it('takes UUIDs in any case as their RFC 9562 bytes, and refuses malformed ones', () => {
    const v = V.metadata[2];
    expect(hex(buildMetadata(v.kind, frameContext(v.channel_id.toUpperCase(), v.sender_id, unhex(v.inst))))).toBe(v.hex);
    expect(() => frameContext('not-a-uuid', v.sender_id, unhex(v.inst))).toThrow(TypeError);
    expect(() => frameContext(v.channel_id, v.sender_id, new Uint8Array(15))).toThrow(TypeError);
  });
});

describe('audio frames (§6.2.5, §6.2.6)', () => {
  it('seals every frames vector byte for byte and opens it again', async () => {
    for (const v of V.frames) {
      const ctx = ctxOf(v);
      const tx = await epochKeys(v.base_key, v.kid, 'encrypt');
      const frame = await sealFrame(MEDIA_KIND_AUDIO, tx, v.ctr, ctx, unhex(v.plaintext));
      expect(hex(frame), `${v.kid}/${v.ctr}`).toBe(v.frame);
      const r = await receive(frame, MEDIA_KIND_AUDIO, v.base_key, ctx);
      expect('pt' in r && hex(r.pt)).toBe(v.plaintext);
    }
    const sizes = V.frames.map((f: { frame: string }) => f.frame.length / 2);
    expect(Math.min(...sizes)).toBe(20);
    expect(Math.max(...sizes)).toBe(FRAME_MAX);
  });

  it('rejects every negative vector at its stage', async () => {
    const names = V.negative.map((n: { name: string }) => n.name);
    for (const n of ['kid_too_large', 'ctr_too_large', 'truncated_header', 'non_minimal_kid', 'non_minimal_ctr', 'bad_format', 'bad_kind', 'short_frame', 'long_frame', 'tag_flip', 'aad_channel', 'aad_sender', 'aad_inst']) {
      expect(names).toContain(n);
    }
    for (const v of V.negative) {
      const r = await receive(unhex(v.frame), v.context.kind, v.context.base_key, ctxOf(v.context));
      expect(r, v.name).toEqual({ stage: v.stage });
    }
  });

  it('T-14: changing any metadata byte or any header byte fails authentication', async () => {
    const v = V.frames[0];
    const ctx = ctxOf(v);
    const rx = await epochKeys(v.base_key, v.kid, 'decrypt');
    const frame = unhex(v.frame);
    const parsed = parseFrame(frame, MEDIA_KIND_AUDIO);
    if (!parsed.ok) throw new Error('vector frame must parse');
    const md = buildMetadata(MEDIA_KIND_AUDIO, ctx);
    for (let i = 0; i < md.length; i++) {
      const bad = Uint8Array.from(md);
      bad[i] ^= 0x01;
      expect(await sframeDecrypt(rx.audio, parsed.header, bad, parsed.ciphertext), `metadata byte ${i}`).toBeNull();
    }
    for (let i = 2; i < 2 + parsed.header.length; i++) {
      for (const flip of [0x01, 0x10, 0x80]) {
        const bad = Uint8Array.from(frame);
        bad[i] ^= flip;
        const p = parseFrame(bad, MEDIA_KIND_AUDIO);
        if (!p.ok) continue; // the header no longer parses: rejected before decryption
        const keys = await epochKeys(v.base_key, p.kid, 'decrypt');
        expect(await openFrame(p, keys, ctx), `header byte ${i} ^ ${flip}`).toBeNull();
      }
    }
  });

  it('T-26: other formats and media kinds are discarded before decryption', () => {
    const frame = unhex(V.frames[0].frame);
    for (const format of [0x00, 0x02, 0xff]) {
      const b = Uint8Array.from(frame);
      b[0] = format;
      expect(parseFrame(b, MEDIA_KIND_AUDIO)).toEqual({ ok: false, reason: 'format' });
    }
    for (const kind of [0x00, 0x02, 0x03]) {
      const b = Uint8Array.from(frame);
      b[1] = kind;
      expect(parseFrame(b, MEDIA_KIND_AUDIO)).toEqual({ ok: false, reason: 'kind' });
    }
    const fragment = unhex(V.video_fragments[0].fragment);
    for (const kind of [0x00, 0x01, 0x03]) {
      const b = Uint8Array.from(fragment);
      b[1] = kind;
      expect(parseFrame(b, MEDIA_KIND_VIDEO)).toEqual({ ok: false, reason: 'kind' });
    }
    // T-3 (A1): an authenticated audio frame re-wrapped as a SCREEN_DOWN never reaches decryption.
    expect(parseFrame(frame, MEDIA_KIND_VIDEO)).toEqual({ ok: false, reason: 'kind' });
    expect(AMF1_FORMAT).toBe(1);
  });

  it('refuses to seal frames outside the size bounds or with a CTR at the limit', async () => {
    const v = V.frames[0];
    const tx = await epochKeys(v.base_key, v.kid, 'encrypt');
    await expect(sealFrame(MEDIA_KIND_AUDIO, tx, 1, ctxOf(v), new Uint8Array(0))).rejects.toThrow(RangeError);
    await expect(sealFrame(MEDIA_KIND_AUDIO, tx, 1, ctxOf(v), new Uint8Array(FRAME_MAX))).rejects.toThrow(RangeError);
    await expect(sealFrame(MEDIA_KIND_AUDIO, tx, 2 ** 48, ctxOf(v), new Uint8Array(10))).rejects.toThrow(RangeError);
    await expect(sealFrame(MEDIA_KIND_VIDEO, tx, 1, ctxOf(v), new Uint8Array(FRAG_MAX))).rejects.toThrow(RangeError);
  });
});

describe('video fragments (A1, §6.2.7, §6.2.8)', () => {
  it('seals every video_fragments vector byte for byte and opens it to the same header and payload', async () => {
    const vctrs = new Set(V.video_fragments.map((f: { vctr: number }) => f.vctr));
    for (const c of [0, 7, 8, 2 ** 48 - 1]) expect(vctrs.has(c)).toBe(true);
    for (const v of V.video_fragments) {
      const h = v.header;
      const header: FragmentHeader = { vcodec: h.vcodec, flags: h.flags, shareSeq: h.share_seq, frameNo: h.frame_no, fragIndex: h.frag_index, fragCount: h.frag_count, width: h.width, height: h.height };
      const ctx = ctxOf(v);
      const tx = await epochKeys(v.epoch_secret, v.kid, 'encrypt');
      const fragment = await sealFrame(MEDIA_KIND_VIDEO, tx, v.vctr, ctx, encodeFragment(header, unhex(v.payload)));
      expect(hex(fragment), `${v.kid}/${v.vctr}`).toBe(v.fragment);
      const r = await receive(fragment, MEDIA_KIND_VIDEO, v.epoch_secret, ctx);
      if (!('pt' in r)) throw new Error(`fragment rejected at ${r.stage}`);
      const f = parseFragment(r.pt)!;
      expect(f.header).toEqual(header);
      expect(hex(f.payload)).toBe(v.payload);
    }
  });

  it('covers a single-fragment key frame and a 16,000 + 16,000 + 1 frame', () => {
    const three = V.video_fragments.filter((f: { header: { frag_count: number } }) => f.header.frag_count === 3);
    expect(three.map((f: { payload: string }) => f.payload.length / 2)).toEqual([16000, 16000, 1]);
    expect(V.video_fragments.some((f: { header: { frag_count: number; flags: number } }) => f.header.frag_count === 1 && f.header.flags === 1)).toBe(true);
  });

  it('rejects every video_negative vector at its stage', async () => {
    const names = V.video_negative.map((n: { name: string }) => n.name);
    for (const n of ['kind_mismatch', 'audio_key_on_video', 'video_on_audio', 'aad_kind', 'vcodec_2', 'reserved_flag_bit', 'frag_count_0', 'frag_count_65', 'frag_index_ge_count', 'short_non_last', 'payload_16001', 'width_15', 'width_1921', 'pixels_1920x1200', 'share_seq_0', 'fragment_16385']) {
      expect(names).toContain(n);
    }
    for (const v of V.video_negative) {
      const r = await receive(unhex(v.fragment), v.context.kind, v.context.epoch_secret, ctxOf(v.context));
      expect(r, v.name).toEqual({ stage: v.stage });
    }
  });

  it('T-14 A1: a fragment fails with metadata of kind 0x01 or the audio key; an audio frame with kind 0x02 or the video key', async () => {
    const fv = V.video_fragments[0];
    const ctx = ctxOf(fv);
    const rx = await epochKeys(fv.epoch_secret, fv.kid, 'decrypt');
    const frag = parseFrame(unhex(fv.fragment), MEDIA_KIND_VIDEO);
    if (!frag.ok) throw new Error('fragment must parse');
    expect(await sframeDecrypt(rx.video, frag.header, buildMetadata(MEDIA_KIND_VIDEO, ctx), frag.ciphertext)).not.toBeNull();
    expect(await sframeDecrypt(rx.video, frag.header, buildMetadata(MEDIA_KIND_AUDIO, ctx), frag.ciphertext)).toBeNull();
    expect(await sframeDecrypt(rx.audio, frag.header, buildMetadata(MEDIA_KIND_VIDEO, ctx), frag.ciphertext)).toBeNull();

    const av = V.frames[0];
    const actx = ctxOf(av);
    const arx = await epochKeys(av.base_key, av.kid, 'decrypt');
    const audio = parseFrame(unhex(av.frame), MEDIA_KIND_AUDIO);
    if (!audio.ok) throw new Error('audio must parse');
    expect(await sframeDecrypt(arx.audio, audio.header, buildMetadata(MEDIA_KIND_AUDIO, actx), audio.ciphertext)).not.toBeNull();
    expect(await sframeDecrypt(arx.audio, audio.header, buildMetadata(MEDIA_KIND_VIDEO, actx), audio.ciphertext)).toBeNull();
    expect(await sframeDecrypt(arx.video, audio.header, buildMetadata(MEDIA_KIND_AUDIO, actx), audio.ciphertext)).toBeNull();
  });

  it('T-14 A1: audio CTR c and video VCTR c under one epoch never share a key, nonce or ciphertext', async () => {
    const v = V.frames[0];
    const ctx = ctxOf(v);
    const secret = await importHkdfKey(unhex(v.base_key));
    const tx = await deriveEpochKeys(secret, 5, 'encrypt');
    const rx = await deriveEpochKeys(secret, 5, 'decrypt');
    // Identical plaintext prefixes: the fragment header's first bytes double as audio plaintext.
    const header: FragmentHeader = { vcodec: 1, flags: 1, shareSeq: 1, frameNo: 0, fragIndex: 0, fragCount: 1, width: 640, height: 360 };
    const videoPt = encodeFragment(header, new Uint8Array(40).fill(9));
    const audioPt = videoPt.slice(0, 58);
    const c = 1234;
    const audio = await sealFrame(MEDIA_KIND_AUDIO, tx, c, ctx, audioPt);
    const video = await sealFrame(MEDIA_KIND_VIDEO, tx, c, ctx, videoPt);
    expect(hex(audio.subarray(5, 5 + 58))).not.toBe(hex(video.subarray(5, 5 + 58)));
    expect(hex(tx.audio.salt)).not.toBe(hex(tx.video.salt));
    const pa = parseFrame(audio, MEDIA_KIND_AUDIO);
    const pv = parseFrame(video, MEDIA_KIND_VIDEO);
    if (!pa.ok || !pv.ok) throw new Error('both must parse');
    expect(hex((await openFrame(pa, rx, ctx))!)).toBe(hex(audioPt));
    expect(hex((await openFrame(pv, rx, ctx))!)).toBe(hex(videoPt));
    expect(await sframeDecrypt(keysFor(rx, MEDIA_KIND_VIDEO), pa.header, buildMetadata(MEDIA_KIND_AUDIO, ctx), pa.ciphertext)).toBeNull();
    expect(await sframeDecrypt(keysFor(rx, MEDIA_KIND_AUDIO), pv.header, buildMetadata(MEDIA_KIND_VIDEO, ctx), pv.ciphertext)).toBeNull();
  });
});

describe('key handling (REQ-14, REQ-27)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('sender keys only encrypt, receiver keys only decrypt, and no key is extractable', async () => {
    const secret = await importHkdfKey(new Uint8Array(32).fill(3));
    await expect(crypto.subtle.exportKey('raw', secret)).rejects.toThrow();
    const tx = await deriveEpochKeys(secret, 1, 'encrypt');
    const rx = await deriveEpochKeys(secret, 1, 'decrypt');
    for (const k of [tx.audio, tx.video]) {
      expect(k.key.extractable).toBe(false);
      expect(k.key.usages).toEqual(['encrypt']);
      await expect(crypto.subtle.exportKey('raw', k.key)).rejects.toThrow();
    }
    for (const k of [rx.audio, rx.video]) {
      expect(k.key.extractable).toBe(false);
      expect(k.key.usages).toEqual(['decrypt']);
      await expect(crypto.subtle.exportKey('raw', k.key)).rejects.toThrow();
    }
    const ctx = frameContext(V.fixed.channel_id, V.fixed.sender_id, unhex(V.fixed.inst));
    await expect(sealFrame(MEDIA_KIND_AUDIO, rx, 0, ctx, new Uint8Array(4))).rejects.toThrow();
    const frame = await sealFrame(MEDIA_KIND_AUDIO, tx, 0, ctx, new Uint8Array(4));
    const p = parseFrame(frame, MEDIA_KIND_AUDIO);
    if (!p.ok) throw new Error('must parse');
    expect(await openFrame(p, tx, ctx)).toBeNull(); // sender keys cannot decrypt
    expect(await openFrame(p, rx, ctx)).not.toBeNull();
    // Keys of another epoch never open a frame.
    expect(await openFrame(p, await deriveEpochKeys(secret, 0, 'decrypt'), ctx)).toBeNull();
  });

  it('A1: the screen base key bytes are zero right after their import, and video keys reject exportKey', async () => {
    const imported: Uint8Array[] = [];
    const real = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, 'importKey').mockImplementation(((format: string, data: BufferSource, alg: AlgorithmIdentifier, ext: boolean, usages: KeyUsage[]) => {
      const p = real(format as 'raw', data, alg, ext, usages);
      if (data instanceof Uint8Array) imported.push(data);
      return p;
    }) as typeof crypto.subtle.importKey);
    const secretBytes = new Uint8Array(32).fill(0x5a);
    const secret = await importHkdfKey(secretBytes, { wipe: true });
    expect(secretBytes.every(b => b === 0)).toBe(true); // a receiver's decoded secret
    const keys = await deriveEpochKeys(secret, 9, 'decrypt');
    // The epoch secret and the screen base key are the HKDF imports.
    expect(imported.length).toBe(2);
    expect(imported[1].length).toBe(32);
    expect(imported[1].every(b => b === 0)).toBe(true);
    await expect(crypto.subtle.exportKey('raw', keys.video.key)).rejects.toThrow();
  });

  it('eraseEpochKeys zero-fills both salts', async () => {
    const keys = await deriveEpochKeys(await importHkdfKey(new Uint8Array(32).fill(1)), 2, 'encrypt');
    eraseEpochKeys(keys);
    expect(keys.audio.salt.every(b => b === 0) && keys.video.salt.every(b => b === 0)).toBe(true);
  });
});

describe('call payloads (§6.3.2 to §6.3.5, REQ-12)', () => {
  const ctx = { from: V.fixed.sender_id, ch: V.fixed.channel_id };

  it('accepts and rejects every call_payloads vector', () => {
    const names = V.call_payloads.map((c: { name: string }) => c.name);
    for (const n of ['valid_hello', 'valid_key', 'valid_ack', 'missing_tag', 'v_2', 'key_31_bytes', 'inst_15_bytes', 'key_null_to_inst', 'from_mismatch']) {
      expect(names).toContain(n);
    }
    for (const v of V.call_payloads) {
      const bytes = unhex(v.plaintext);
      const asString = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      for (const input of [bytes, asString]) {
        const p = parseCallPayload(input, ctx);
        if (v.expect === 'accept') {
          expect(p, v.name).not.toBeNull();
          expect(p!.type, v.name).toBe(v.type);
        } else {
          expect(p, v.name).toBeNull();
        }
      }
    }
  });

  it('decodes the fields of a valid call_key', () => {
    const v = V.call_payloads.find((c: { name: string }) => c.name === 'valid_key');
    const p = parseCallPayload(unhex(v.plaintext), ctx);
    if (!p || p.type !== 'call_key') throw new Error('call_key expected');
    expect(p.epoch).toBe(3);
    expect(p.key.length).toBe(32);
    expect(hex(p.inst)).toBe(V.fixed.inst);
    expect(p.toInst.length).toBe(16);
    // The channel check compares in lowercase.
    expect(parseCallPayload(unhex(v.plaintext), { from: ctx.from.toUpperCase(), ch: ctx.ch.toUpperCase() })).not.toBeNull();
  });
});

describe('screen wire messages (§6.12.2)', () => {
  it('parses every screen_wire vector as its direction requires', () => {
    for (const v of V.screen_wire) {
      const bytes = unhex(v.bytes);
      if (v.direction === 'up') {
        const up = decodeScreenUp(bytes);
        if (v.expect === 'reject') {
          expect(up, v.name).toBeNull();
          continue;
        }
        expect(up, v.name).not.toBeNull();
        expect(up!.channelId).toBe(v.channel_id);
        expect(up!.fragment.length).toBe(v.fragment_length);
        expect(hex(encodeScreenUp(v.channel_id, up!.fragment))).toBe(v.bytes);
      } else {
        const down = decodeScreenDown(bytes);
        if (v.expect === 'reject') {
          expect(down, v.name).toBeNull();
          continue;
        }
        expect(down, v.name).not.toBeNull();
        expect(down!.channelId).toBe(v.channel_id);
        expect(down!.from).toBe(v.from);
        expect(down!.fragment.length).toBe(v.fragment_length);
        expect(hex(encodeScreenDown(v.channel_id, v.from, down!.fragment))).toBe(v.bytes);
      }
    }
  });
});
