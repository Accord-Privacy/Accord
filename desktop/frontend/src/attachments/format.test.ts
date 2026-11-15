// @vitest-environment node
/**
 * SPEC-02 §6.3 (A256GCM-STREAM64K) and the known-answer vectors of §6.7:
 * T-1 (REQ-1), T-2 (REQ-2), T-3 (REQ-3), T-4 (REQ-4) and T-5 (REQ-5). The
 * vectors come from `core/tests/vectors/attachments-v1.json`, which the
 * accord-core reference reads too.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  AttachmentIntegrityError,
  blobLength,
  CLIENT_MAX_BLOB_BYTES,
  openAttachment,
  padme,
  recordCount,
  recordNonce,
  RECORD_SIZE,
  sealAttachment,
  sealAttachmentWithFixedKeyForVectors,
  sealedBlob,
  sealedBytes,
  type CipherEngine,
  type OpenParams,
} from './format';
import { encodeBase64 } from './base64';
import { serializeDescriptor } from './envelope';

const REPO_ROOT = fileURLToPath(new URL('../../../../', import.meta.url));

interface BlobVector {
  id: string;
  plaintext: { kind: 'hex'; hex: string } | { kind: 'repeat'; byte: number; length: number } | { kind: 'mod251'; length: number };
  size: number;
  padded_size: number;
  records: number;
  blob_length: number;
  record_tags_hex: string[];
  sha256_hex: string;
  sha256_b64: string;
  blob_hex?: string;
}

const V = JSON.parse(readFileSync(join(REPO_ROOT, 'core/tests/vectors/attachments-v1.json'), 'utf8')) as {
  key_hex: string;
  key_b64: string;
  nonce_prefix_hex: string;
  nonce_prefix_b64: string;
  gcm_primitive_checks: { id: string; key_hex: string; nonce_hex: string; plaintext_hex: string; ciphertext_hex: string; tag_hex: string }[];
  padme: { size: number; padded_size: number }[];
  blobs: BlobVector[];
};

function hex(h: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Byte equality without vitest's element-by-element deep equality, which is slow on large arrays. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return Buffer.from(a.buffer, a.byteOffset, a.byteLength).equals(Buffer.from(b.buffer, b.byteOffset, b.byteLength));
}

function toHex(b: Uint8Array): string {
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}

function plaintextOf(v: BlobVector): Uint8Array<ArrayBuffer> {
  const p = v.plaintext;
  if (p.kind === 'hex') return hex(p.hex);
  if (p.kind === 'repeat') return new Uint8Array(p.length).fill(p.byte);
  const out = new Uint8Array(p.length);
  for (let i = 0; i < out.length; i++) out[i] = i % 251;
  return out;
}

const KEY = hex(V.key_hex);
const PREFIX = hex(V.nonce_prefix_hex);
const ENGINES: CipherEngine[] = ['webcrypto', 'noble'];

/** The record tags of a blob: the last 16 bytes of each record output. */
function recordTags(blob: Uint8Array, paddedSize: number): string[] {
  const tags: string[] = [];
  const n = recordCount(paddedSize);
  let off = 0;
  for (let i = 0; i < n; i++) {
    const plen = i < n - 1 ? RECORD_SIZE : paddedSize - (n - 1) * RECORD_SIZE;
    off += plen + 16;
    tags.push(toHex(blob.subarray(off - 16, off)));
  }
  return tags;
}

/**
 * An independent sealer for the tamper matrix (noble, record by record), so
 * tests can build blobs that `sealAttachment` never produces: other padding,
 * a wrong final flag, non-zero padding bytes.
 */
function sealRaw(padded: Uint8Array, opts: { finalFlags?: (i: number, n: number) => boolean } = {}): Uint8Array<ArrayBuffer> {
  const n = recordCount(padded.length);
  const parts: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const rec = padded.subarray(i * RECORD_SIZE, Math.min(padded.length, (i + 1) * RECORD_SIZE));
    const final = opts.finalFlags ? opts.finalFlags(i, n) : i === n - 1;
    parts.push(gcm(KEY, recordNonce(PREFIX, i, final)).encrypt(rec));
  }
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function paramsFor(blob: Uint8Array, size: number, paddedSize: number): OpenParams {
  return { key: KEY, noncePrefix: PREFIX, sha256: sha256(blob), size, paddedSize };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AES-256-GCM primitive (McGrew and Viega test cases 13 and 14)', () => {
  for (const tc of V.gcm_primitive_checks) {
    it(`${tc.id}: noble and WebCrypto agree with the published values`, async () => {
      const key = hex(tc.key_hex);
      const nonce = hex(tc.nonce_hex);
      const pt = hex(tc.plaintext_hex);
      const expected = tc.ciphertext_hex + tc.tag_hex;
      expect(toHex(gcm(key, nonce).encrypt(pt))).toBe(expected);
      const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
      expect(toHex(new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, k, pt)))).toBe(expected);
    });
  }
});

describe('T-3 Padmé and REQ-3', { timeout: 30_000 }, () => {
  it('matches the Padmé table of §6.7', () => {
    for (const { size, padded_size } of V.padme) expect(padme(size)).toBe(padded_size);
  });

  it('is exact up to 2^53', () => {
    // 2^52 + 1: E = 52, S = 6, unit = 2^46, so the result rounds up to 2^52 + 2^46.
    expect(padme(2 ** 52 + 1)).toBe(2 ** 52 + 2 ** 46);
    expect(padme(Number.MAX_SAFE_INTEGER)).toBe(2 ** 53);
    expect(() => padme(-1)).toThrow(RangeError);
    expect(() => padme(1.5)).toThrow(RangeError);
  });

  it('computes blob_length', () => {
    expect(blobLength(0)).toBe(16);
    expect(blobLength(5)).toBe(21);
    expect(blobLength(RECORD_SIZE)).toBe(RECORD_SIZE + 16);
    expect(blobLength(RECORD_SIZE + 1)).toBe(RECORD_SIZE + 1 + 32);
    expect(blobLength(104_857_600)).toBe(104_857_600 + 16 * 1600);
  });

  it('pads the sender side with padme(size)', async () => {
    for (const size of [0, 1, 1000, 140_000]) {
      const sealed = await sealAttachment(new Uint8Array(size), { engine: 'noble' });
      expect(sealed.paddedSize).toBe(padme(size));
      expect(sealed.blobLength).toBe(blobLength(padme(size)));
    }
  });

  it('receives padded_size = size and padded_size = padme(size)', async () => {
    const plain = plaintextOf(V.blobs.find(b => b.id === 'TV3')!); // 1000 bytes, padme 1024
    for (const padded of [plain.length, padme(plain.length)]) {
      const p = new Uint8Array(padded);
      p.set(plain);
      const blob = sealRaw(p);
      const out = await openAttachment(blob, paramsFor(blob, plain.length, padded));
      expect(sameBytes(out, plain)).toBe(true);
    }
  });

  it('rejects size > padded_size and a padded_size beyond CLIENT_MAX_BLOB_BYTES', async () => {
    const blob = sealRaw(new Uint8Array(10));
    await expect(openAttachment(blob, paramsFor(blob, 11, 10))).rejects.toMatchObject({ reason: 'params' });
    // The largest padded_size whose blob still fits, and the next one.
    expect(blobLength(104_832_000)).toBe(CLIENT_MAX_BLOB_BYTES);
    expect(blobLength(104_832_001)).toBeGreaterThan(CLIENT_MAX_BLOB_BYTES);
    await expect(openAttachment(blob, paramsFor(blob, 10, 104_832_001))).rejects.toMatchObject({ reason: 'params' });
    await expect(sealAttachment(new Uint8Array(104_857_601))).rejects.toThrow(RangeError);
  });
});

describe('T-2 known-answer vectors (REQ-2)', { timeout: 30_000 }, () => {
  for (const engine of ENGINES) {
    for (const v of V.blobs) {
      it(`${engine}: ${v.id}`, async () => {
        const plain = plaintextOf(v);
        const sealed = await sealAttachmentWithFixedKeyForVectors(plain, KEY, PREFIX, { engine });
        const blob = sealedBytes(sealed);
        expect(sealed.size).toBe(v.size);
        expect(sealed.paddedSize).toBe(v.padded_size);
        expect(sealed.parts.length).toBe(v.records);
        expect(sealed.blobLength).toBe(v.blob_length);
        expect(blob.length).toBe(v.blob_length);
        expect(recordTags(blob, v.padded_size)).toEqual(v.record_tags_hex);
        expect(toHex(sealed.sha256)).toBe(v.sha256_hex);
        expect(toHex(sha256(blob))).toBe(v.sha256_hex);
        if (v.blob_hex !== undefined) expect(toHex(blob)).toBe(v.blob_hex);
        // The upload body is the same bytes.
        expect(sameBytes(new Uint8Array(await sealedBlob(sealed).arrayBuffer()), blob)).toBe(true);
        // Both engines open what either produced.
        for (const opener of ENGINES) {
          const out = await openAttachment(blob, paramsFor(blob, v.size, v.padded_size), { engine: opener });
          expect(sameBytes(out, plain)).toBe(true);
        }
      });
    }
  }

  it('fails, and never zero-fills, when the file is shorter than its declared size', async () => {
    const shrinking = { size: 70_000, slice: (a: number, b: number) => new Blob([new Uint8Array(Math.max(0, Math.min(b, 1000) - a))]) } as unknown as Blob;
    await expect(sealAttachment(shrinking, { engine: 'noble' })).rejects.toThrow('file read failed');
  });

  it('reads a File-like Blob record by record and gives the same blob', async () => {
    const v = V.blobs.find(b => b.id === 'TV4')!;
    const plain = plaintextOf(v);
    const sealed = await sealAttachmentWithFixedKeyForVectors(new Blob([plain]), KEY, PREFIX, { engine: 'noble' });
    expect(toHex(sealed.sha256)).toBe(v.sha256_hex);
  });
});

describe('T-1 fresh key and nonce prefix from the CSPRNG (REQ-1)', () => {
  it('draws 32-byte keys and 7-byte prefixes from getRandomValues, never Math.random', async () => {
    const requests: number[] = [];
    const original = crypto.getRandomValues.bind(crypto);
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
      if (array) requests.push(array.byteLength);
      return original(array as never) as T;
    });
    const mathRandom = vi.spyOn(Math, 'random');
    const input = new Uint8Array(2048).fill(7);
    const a = await sealAttachment(input);
    const b = await sealAttachment(input);
    expect(toHex(a.key)).not.toBe(toHex(b.key));
    expect(toHex(a.noncePrefix)).not.toBe(toHex(b.noncePrefix));
    expect(a.key.length).toBe(32);
    expect(a.noncePrefix.length).toBe(7);
    expect(requests.filter(n => n === 32).length).toBeGreaterThanOrEqual(2);
    expect(requests.filter(n => n === 7).length).toBeGreaterThanOrEqual(2);
    expect(mathRandom).not.toHaveBeenCalled();
    // Identical inputs give unrelated blobs.
    expect(toHex(a.sha256)).not.toBe(toHex(b.sha256));
  });
});

describe('REQ-1 the fixed key and prefix of the vectors never reach production', () => {
  const SRC = fileURLToPath(new URL('../', import.meta.url));

  function sourceFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap(e => {
      const path = join(dir, e.name);
      if (e.isDirectory()) return sourceFiles(path);
      return /\.(ts|tsx)$/.test(e.name) ? [path] : [];
    });
  }

  it('sealAttachment takes no key or nonce prefix', async () => {
    const forced = { engine: 'noble', testKey: KEY, testNoncePrefix: PREFIX, key: KEY, noncePrefix: PREFIX };
    const sealed = await sealAttachment(new Uint8Array(10), forced as never);
    expect(toHex(sealed.key)).not.toBe(toHex(KEY));
    expect(toHex(sealed.noncePrefix)).not.toBe(toHex(PREFIX));
  });

  it('the fixed-value sealer refuses to run outside the test build', async () => {
    vi.stubEnv('MODE', 'production');
    try {
      await expect(sealAttachmentWithFixedKeyForVectors(new Uint8Array(1), KEY, PREFIX)).rejects.toThrow('only in tests');
    } finally {
      vi.unstubAllEnvs();
    }
    expect(import.meta.env.MODE).toBe('test');
  });

  it('static: no module outside the tests names the fixed-value sealer', () => {
    const offenders = sourceFiles(SRC)
      .filter(f => !/\.test\.tsx?$/.test(f) && relative(SRC, f) !== join('attachments', 'format.ts'))
      .filter(f => /sealAttachmentWithFixedKeyForVectors|testNoncePrefix|testKey/.test(readFileSync(f, 'utf8')))
      .map(f => relative(SRC, f));
    expect(offenders).toEqual([]);
  });
});

describe('T-4 descriptor sha256 (REQ-4)', () => {
  it('is base64 of the SHA-256 of the blob, for TV4', async () => {
    const v = V.blobs.find(b => b.id === 'TV4')!;
    const sealed = await sealAttachmentWithFixedKeyForVectors(plaintextOf(v), KEY, PREFIX, { engine: 'noble' });
    const descriptor = JSON.parse(serializeDescriptor({
      blobId: '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04',
      key: sealed.key,
      noncePrefix: sealed.noncePrefix,
      sha256: sealed.sha256,
      size: sealed.size,
      paddedSize: sealed.paddedSize,
      name: 'data.bin',
      mime: 'application/octet-stream',
    })) as Record<string, unknown>;
    expect(descriptor.sha256).toBe(encodeBase64(sha256(sealedBytes(sealed))));
    expect(descriptor.sha256).toBe(v.sha256_b64);
    expect(descriptor.key).toBe(V.key_b64);
    expect(descriptor.nonce_prefix).toBe(V.nonce_prefix_b64);
    expect(descriptor.padded_size).toBe(v.padded_size);
  });
});

describe('T-5 tamper matrix on TV4 (REQ-5)', { timeout: 30_000 }, () => {
  const v = V.blobs.find(b => b.id === 'TV4')!;
  const plain = plaintextOf(v);
  const padded = new Uint8Array(v.padded_size);
  padded.set(plain);
  const good = sealRaw(padded);
  const recordLen = (i: number) => (i < v.records - 1 ? RECORD_SIZE : v.padded_size - (v.records - 1) * RECORD_SIZE) + 16;
  const recordStart = (i: number) => {
    let off = 0;
    for (let k = 0; k < i; k++) off += recordLen(k);
    return off;
  };

  function flip(blob: Uint8Array, at: number): Uint8Array<ArrayBuffer> {
    const out = blob.slice();
    out[at] ^= 0x01;
    return out;
  }

  function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }

  /** Each case: the blob, and whether the descriptor hash is recomputed for it (a colluding key holder). */
  const cases: [string, Uint8Array, boolean][] = [];
  for (let i = 0; i < v.records; i++) {
    cases.push([`bit flipped in record ${i} body`, flip(good, recordStart(i) + 5), true]);
    cases.push([`bit flipped in record ${i} tag`, flip(good, recordStart(i) + recordLen(i) - 3), true]);
    cases.push([`bit flipped in record ${i} body (hash unchanged)`, flip(good, recordStart(i) + 5), false]);
  }
  cases.push(['final record removed', good.subarray(0, recordStart(v.records - 1)), true]);
  cases.push(['last byte removed', good.subarray(0, good.length - 1), true]);
  cases.push(['16 bytes appended', concat(good, new Uint8Array(16)), true]);
  cases.push(['records 0 and 1 swapped', concat(
    good.subarray(recordStart(1), recordStart(2)),
    good.subarray(recordStart(0), recordStart(1)),
    good.subarray(recordStart(2)),
  ), true]);
  cases.push(['record 2 re-sealed without the final flag', sealRaw(padded, { finalFlags: () => false }), true]);
  cases.push(['record 1 sealed with the final flag', sealRaw(padded, { finalFlags: (i, n) => i === 1 || i === n - 1 }), true]);
  {
    const other = padded.slice();
    other[0] ^= 0xff;
    cases.push(['another plaintext under the same key and prefix (valid AEAD, wrong hash)', sealRaw(other), false]);
  }
  {
    const badPadding = padded.slice();
    badPadding[v.padded_size - 1] = 1;
    cases.push(['correctly hashed blob whose padding holds a non-zero byte', sealRaw(badPadding), true]);
  }

  for (const engine of ENGINES) {
    for (const [name, blob, rehash] of cases) {
      it(`${engine}: ${name}`, async () => {
        const params: OpenParams = { ...paramsFor(good, v.size, v.padded_size), sha256: rehash ? sha256(blob) : sha256(good) };
        const consumer = vi.fn();
        await expect(openAttachment(blob, params, { engine }).then(consumer)).rejects.toBeInstanceOf(AttachmentIntegrityError);
        expect(consumer).not.toHaveBeenCalled();
      });
    }
  }

  it('opens the untampered blob', async () => {
    expect(sameBytes(await openAttachment(good, paramsFor(good, v.size, v.padded_size)), plain)).toBe(true);
  });

  it('carries no received or decrypted bytes in its error', async () => {
    const err = await openAttachment(flip(good, 3), paramsFor(good, v.size, v.padded_size)).catch(e => e);
    expect(err).toBeInstanceOf(AttachmentIntegrityError);
    expect(Object.keys(err).sort()).toEqual(['name', 'reason']);
    expect(err.message).toBe('Attachment failed its integrity check');
  });
});
