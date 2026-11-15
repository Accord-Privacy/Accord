/**
 * @module attachments/format
 * The A256GCM-STREAM64K blob format of SPEC-02 §6.3.
 *
 * - Padmé padding (§6.3.1) with arithmetic that is exact up to 2^53.
 * - The plaintext, zero-padded to `padded_size`, is cut into 65,536-byte
 *   records. Record i is sealed with AES-256-GCM under the per-file key, the
 *   nonce `nonce_prefix ‖ u32be(i) ‖ final_flag` and empty associated data.
 *   The blob is the concatenation of the record outputs; it has no header.
 * - `openAttachment` checks length, SHA-256, every record and the padding
 *   before it returns a single byte (REQ-5). On any failure it discards all
 *   decrypted output and throws `AttachmentIntegrityError`.
 *
 * Two AES-GCM engines produce identical output: WebCrypto (native, used when
 * `crypto.subtle` exists) and @noble/ciphers (the fallback). Both reproduce
 * the known-answer vectors of SPEC-02 §6.7 (REQ-2). Keys and nonce prefixes
 * come only from `crypto.getRandomValues` (REQ-1): `sealAttachment` takes no
 * key or prefix, and the fixed-value entry point of the vectors works only in
 * the test build.
 */

import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const SCHEME = 'A256GCM-STREAM64K' as const;
/** Record plaintext size R. */
export const RECORD_SIZE = 65_536;
export const TAG_SIZE = 16;
export const KEY_SIZE = 32;
export const NONCE_PREFIX_SIZE = 7;
export const NONCE_SIZE = 12;
export const SHA256_SIZE = 32;
/** Largest blob the client creates or accepts (SPEC-02 §6.8). */
export const CLIENT_MAX_BLOB_BYTES = 104_857_600;

type Bytes = Uint8Array<ArrayBuffer>;

function assertLength(name: string, n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`${name} must be a non-negative safe integer`);
}

/** floor(log2(x)) for a safe integer x ≥ 1, by exact halving. */
function floorLog2(x: number): number {
  let e = 0;
  while (x >= 2) {
    x = Math.floor(x / 2);
    e++;
  }
  return e;
}

/** Number of binary digits of x ≥ 1. */
function bitLength(x: number): number {
  return floorLog2(x) + 1;
}

/** Padmé (SPEC-02 §6.3.1): the padded size for a plaintext of `length` bytes. */
export function padme(length: number): number {
  assertLength('length', length);
  if (length < 2) return length;
  const e = floorLog2(length);
  const s = bitLength(e);
  const unit = 2 ** (e - s);
  return Math.ceil(length / unit) * unit;
}

/** Number of records for a padded size: max(1, ceil(P / R)). */
export function recordCount(paddedSize: number): number {
  assertLength('paddedSize', paddedSize);
  return Math.max(1, Math.ceil(paddedSize / RECORD_SIZE));
}

/** blob_length(P) = P + 16 * max(1, ceil(P / R)). */
export function blobLength(paddedSize: number): number {
  return paddedSize + TAG_SIZE * recordCount(paddedSize);
}

/** The 12-byte nonce of record `index`: prefix ‖ u32be(index) ‖ final flag. */
export function recordNonce(noncePrefix: Uint8Array, index: number, final: boolean): Bytes {
  if (noncePrefix.length !== NONCE_PREFIX_SIZE) throw new RangeError('nonce prefix must be 7 bytes');
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new RangeError('record index out of range');
  const nonce = new Uint8Array(NONCE_SIZE);
  nonce.set(noncePrefix, 0);
  new DataView(nonce.buffer).setUint32(NONCE_PREFIX_SIZE, index, false);
  nonce[11] = final ? 0x01 : 0x00;
  return nonce;
}

// ---------------------------------------------------------------------------
// AES-256-GCM engines
// ---------------------------------------------------------------------------

export type CipherEngine = 'webcrypto' | 'noble';

/** WebCrypto when the platform offers it, otherwise noble. */
export function defaultEngine(): CipherEngine {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  return subtle && typeof subtle.importKey === 'function' && typeof subtle.encrypt === 'function'
    ? 'webcrypto'
    : 'noble';
}

interface RecordCipher {
  seal(nonce: Bytes, plain: Bytes): Promise<Bytes>;
  /** Throws when authentication fails. */
  open(nonce: Bytes, sealed: Bytes): Promise<Bytes>;
}

function copyBytes(u: Uint8Array): Bytes {
  const out = new Uint8Array(u.length);
  out.set(u);
  return out;
}

async function createRecordCipher(engine: CipherEngine, key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<RecordCipher> {
  if (key.length !== KEY_SIZE) throw new RangeError('key must be 32 bytes');
  if (engine === 'webcrypto') {
    const subtle = globalThis.crypto.subtle;
    const cryptoKey = await subtle.importKey('raw', copyBytes(key), { name: 'AES-GCM' }, false, [usage]);
    return {
      async seal(nonce, plain) {
        return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, cryptoKey, plain));
      },
      async open(nonce, sealed) {
        return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, cryptoKey, sealed));
      },
    };
  }
  const k = copyBytes(key);
  return {
    async seal(nonce, plain) {
      return copyBytes(gcm(k, nonce).encrypt(plain));
    },
    async open(nonce, sealed) {
      return copyBytes(gcm(k, nonce).decrypt(sealed));
    },
  };
}

// ---------------------------------------------------------------------------
// Seal
// ---------------------------------------------------------------------------

export interface SealOptions {
  engine?: CipherEngine;
}

export interface SealedAttachment {
  /** The record outputs in order; their concatenation is the blob. */
  readonly parts: readonly Bytes[];
  readonly blobLength: number;
  readonly key: Bytes;
  readonly noncePrefix: Bytes;
  /** SHA-256 of the complete blob (REQ-4). */
  readonly sha256: Bytes;
  readonly size: number;
  readonly paddedSize: number;
}

function randomBytes(n: number): Bytes {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

async function readRange(input: Uint8Array | Blob, start: number, end: number): Promise<Uint8Array> {
  if (input instanceof Uint8Array) return input.subarray(start, end);
  const slice = input.slice(start, end);
  if (typeof slice.arrayBuffer === 'function') return new Uint8Array(await slice.arrayBuffer());
  return new Promise<Uint8Array>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(new Error('file read failed'));
    reader.readAsArrayBuffer(slice);
  });
}

/**
 * Encrypt one attachment (SPEC-02 §6.3.2 `seal`) under a new 32-byte key and
 * a new 7-byte nonce prefix from `crypto.getRandomValues` (REQ-1). The input
 * is read record by record, so a `File` is never loaded whole. Any failure
 * throws; the caller aborts the message (REQ-13).
 */
export async function sealAttachment(input: Uint8Array | Blob, options: SealOptions = {}): Promise<SealedAttachment> {
  return sealRecords(input, () => ({ key: randomBytes(KEY_SIZE), noncePrefix: randomBytes(NONCE_PREFIX_SIZE) }), options.engine);
}

/**
 * Tests only: seal under the fixed key and nonce prefix of the known-answer
 * vectors (SPEC-02 §6.7). Sealing two files under one key and prefix reuses
 * AES-GCM nonces, which REQ-1 forbids, so this throws unless it runs in the
 * test build: Vitest sets `import.meta.env.MODE` to `test`, and a production
 * build replaces it with `production`, which leaves only the throw. A static
 * check in `format.test.ts` keeps every non-test module from naming it.
 */
export async function sealAttachmentWithFixedKeyForVectors(
  input: Uint8Array | Blob,
  key: Uint8Array,
  noncePrefix: Uint8Array,
  options: SealOptions = {},
): Promise<SealedAttachment> {
  if (import.meta.env.MODE !== 'test') throw new Error('fixed-key sealing is available only in tests');
  return sealRecords(input, () => ({ key: copyBytes(key), noncePrefix: copyBytes(noncePrefix) }), options.engine);
}

async function sealRecords(
  input: Uint8Array | Blob,
  drawKeys: () => { key: Bytes; noncePrefix: Bytes },
  engine: CipherEngine | undefined,
): Promise<SealedAttachment> {
  const size = input instanceof Uint8Array ? input.length : input.size;
  assertLength('size', size);
  const paddedSize = padme(size);
  if (blobLength(paddedSize) > CLIENT_MAX_BLOB_BYTES) throw new RangeError('attachment exceeds CLIENT_MAX_BLOB_BYTES');

  const { key, noncePrefix } = drawKeys();
  if (key.length !== KEY_SIZE || noncePrefix.length !== NONCE_PREFIX_SIZE) throw new RangeError('bad key or nonce prefix');

  const cipher = await createRecordCipher(engine ?? defaultEngine(), key, 'encrypt');
  const n = recordCount(paddedSize);
  const hash = sha256.create();
  const parts: Bytes[] = [];
  for (let i = 0; i < n; i++) {
    const start = i * RECORD_SIZE;
    const plen = i < n - 1 ? RECORD_SIZE : paddedSize - (n - 1) * RECORD_SIZE;
    const record = new Uint8Array(plen); // zero padding beyond `size`
    if (start < size) {
      const end = Math.min(size, start + plen);
      const chunk = await readRange(input, start, end);
      // A file that changed while being read is a read failure (REQ-13), never zero-filled.
      if (chunk.length !== end - start) throw new Error('file read failed');
      record.set(chunk);
    }
    const out = await cipher.seal(recordNonce(noncePrefix, i, i === n - 1), record);
    record.fill(0);
    if (out.length !== plen + TAG_SIZE) throw new Error('cipher output has the wrong length');
    hash.update(out);
    parts.push(out);
  }
  return { parts, blobLength: blobLength(paddedSize), key, noncePrefix, sha256: copyBytes(hash.digest()), size, paddedSize };
}

/** The upload body of a sealed attachment (REQ-14). */
export function sealedBlob(sealed: SealedAttachment): Blob {
  return new Blob(sealed.parts as Bytes[], { type: 'application/octet-stream' });
}

/** The blob of a sealed attachment as one byte array (tests and small blobs). */
export function sealedBytes(sealed: SealedAttachment): Bytes {
  const out = new Uint8Array(sealed.blobLength);
  let off = 0;
  for (const p of sealed.parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

export interface OpenParams {
  readonly key: Uint8Array;
  readonly noncePrefix: Uint8Array;
  readonly sha256: Uint8Array;
  readonly size: number;
  readonly paddedSize: number;
}

export type IntegrityFailure = 'params' | 'length' | 'hash' | 'aead' | 'padding';

/** A blob failed a REQ-5 check. Carries no received or decrypted bytes. */
export class AttachmentIntegrityError extends Error {
  readonly reason: IntegrityFailure;
  constructor(reason: IntegrityFailure) {
    super('Attachment failed its integrity check');
    this.name = 'AttachmentIntegrityError';
    this.reason = reason;
  }
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** Validate descriptor parameters as REQ-3 requires of receivers. */
export function validOpenParams(p: OpenParams): boolean {
  return p.key.length === KEY_SIZE
    && p.noncePrefix.length === NONCE_PREFIX_SIZE
    && p.sha256.length === SHA256_SIZE
    && Number.isSafeInteger(p.size) && p.size >= 0
    && Number.isSafeInteger(p.paddedSize) && p.size <= p.paddedSize
    && blobLength(p.paddedSize) <= CLIENT_MAX_BLOB_BYTES;
}

/**
 * Decrypt and verify a blob (SPEC-02 §6.3.2 `open`, REQ-5). Returns the
 * plaintext only after the length, the SHA-256, every record (with the final
 * flag on the last expected record only) and the zero padding have all been
 * checked. Throws `AttachmentIntegrityError` otherwise, after wiping every
 * decrypted byte.
 */
export async function openAttachment(blob: Uint8Array, params: OpenParams, options: { engine?: CipherEngine } = {}): Promise<Bytes> {
  if (!validOpenParams(params)) throw new AttachmentIntegrityError('params');
  if (blob.length !== blobLength(params.paddedSize)) throw new AttachmentIntegrityError('length');
  if (!equalBytes(sha256(blob), params.sha256)) throw new AttachmentIntegrityError('hash');

  const cipher = await createRecordCipher(options.engine ?? defaultEngine(), params.key, 'decrypt');
  const n = recordCount(params.paddedSize);
  const out = new Uint8Array(params.paddedSize);
  let off = 0;
  for (let i = 0; i < n; i++) {
    const plen = i < n - 1 ? RECORD_SIZE : params.paddedSize - (n - 1) * RECORD_SIZE;
    let plain: Bytes;
    try {
      plain = await cipher.open(recordNonce(params.noncePrefix, i, i === n - 1), copyBytes(blob.subarray(off, off + plen + TAG_SIZE)));
    } catch {
      out.fill(0);
      throw new AttachmentIntegrityError('aead');
    }
    if (plain.length !== plen) {
      plain.fill(0);
      out.fill(0);
      throw new AttachmentIntegrityError('aead');
    }
    out.set(plain, i * RECORD_SIZE);
    plain.fill(0);
    off += plen + TAG_SIZE;
  }
  for (let i = params.size; i < out.length; i++) {
    if (out[i] !== 0) {
      out.fill(0);
      throw new AttachmentIntegrityError('padding');
    }
  }
  return out.subarray(0, params.size);
}
