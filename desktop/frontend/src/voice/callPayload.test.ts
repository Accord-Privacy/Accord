// @vitest-environment node
/**
 * SPEC-03 REQ-27 for call payloads: no rejection of a `call_key` leaves a
 * decoded epoch secret behind. The key is decoded only after every other
 * check passed, and the base64 decoder zero-fills what it decoded when it
 * rejects a value (non-canonical, wrong length or malformed).
 *
 * The vector acceptance itself is T-14's, in `mediaFrame.test.ts`.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeCanonicalBase64 } from '../attachments/base64';
import { parseCallPayload } from './callPayload';
import { SECRET_LEN } from './mediaFrame';

vi.mock('../attachments/base64', async importOriginal => {
  const orig = await importOriginal<typeof import('../attachments/base64')>();
  return { ...orig, decodeCanonicalBase64: vi.fn(orig.decodeCanonicalBase64) };
});

const REPO_ROOT = join(process.cwd(), '..', '..');
const V: any = JSON.parse(readFileSync(join(REPO_ROOT, 'core/tests/vectors/amf1-v1.json'), 'utf8'));
const ctx = { from: V.fixed.sender_id, ch: V.fixed.channel_id };
const decode = vi.mocked(decodeCanonicalBase64);

const unhex = (h: string): Uint8Array => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
};
const text = (name: string): string => {
  const v = V.call_payloads.find((c: { name: string }) => c.name === name);
  return new TextDecoder().decode(unhex(v.plaintext));
};
/** Every secret-sized buffer the decoder handed out since the last clear. */
const decodedSecrets = (): Uint8Array[] =>
  decode.mock.results.flatMap(r => (r.type === 'return' && r.value instanceof Uint8Array && r.value.length === SECRET_LEN ? [r.value] : []));

describe('call_key rejections leave no decoded secret (REQ-27)', () => {
  afterEach(() => {
    decode.mockClear();
    vi.restoreAllMocks();
  });

  it('decodes the key only after every other check: a bad epoch never decodes it', () => {
    const valid = text('valid_key');
    const bad = [
      text('epoch_too_large'),
      valid.replace('"epoch":3', '"epoch":-1'),
      valid.replace('"epoch":3', '"epoch":"3"'),
      valid.replace('"epoch":3', '"epoch":1.5'),
      valid.replace('"epoch":3,', ''),
      valid.replace('"suite":5', '"suite":4'),
    ];
    for (const pt of bad) {
      expect(pt).toContain('"key":"');
      expect(parseCallPayload(pt, ctx)).toBeNull();
      expect(decodedSecrets()).toEqual([]);
      decode.mockClear();
    }
    // The control: a valid call_key decodes exactly its key.
    const p = parseCallPayload(valid, ctx);
    expect(p?.type).toBe('call_key');
    expect(decodedSecrets().length).toBe(1);
  });

  it('every rejected call_payloads vector leaves any secret-sized buffer zero-filled', () => {
    for (const v of V.call_payloads.filter((c: { expect: string }) => c.expect === 'reject')) {
      decode.mockClear();
      expect(parseCallPayload(unhex(v.plaintext), ctx), v.name).toBeNull();
      for (const b of decodedSecrets()) expect(b.every(x => x === 0), v.name).toBe(true);
    }
  });

  it('a non-canonical, short or malformed key is zero-filled inside the decoder before it is dropped', () => {
    const valid = text('valid_key');
    const canonical = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
    expect(valid).toContain(canonical);
    const fill = vi.spyOn(Uint8Array.prototype, 'fill');
    const cases = [
      canonical.replace('Hh8=', 'Hh9='), // the same 32 bytes with non-zero padding bits
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==', // 31 bytes
      'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd*h8=', // a bad character after 30 decoded bytes
    ];
    for (const key of cases) {
      fill.mockClear();
      expect(parseCallPayload(valid.replace(canonical, key), ctx)).toBeNull();
      const wiped = fill.mock.contexts.filter(
        (b, i): b is Uint8Array => b instanceof Uint8Array && b.length >= 30 && fill.mock.calls[i][0] === 0,
      );
      expect(wiped.length, key).toBeGreaterThan(0);
      for (const b of wiped) expect(b.every(x => x === 0), key).toBe(true);
    }
  });
});
