/**
 * @module attachments/base64
 * Base64 helpers for SPEC-02 (RFC 4648 §4, standard alphabet, with padding).
 *
 * - `encodeBase64` works through a byte buffer, so it never spreads a large
 *   array into `String.fromCharCode` (the N003 failure mode).
 * - `decodeCanonicalBase64` implements the descriptor rule of SPEC-02 §6.2:
 *   padding required, no whitespace, and the value is rejected unless
 *   re-encoding the decoded bytes gives back the input.
 * - `decodeWireBase64` decodes a relay payload (`encrypted_data`,
 *   `encrypted_payload`) for hashing; it accepts only the standard alphabet
 *   with padding.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const ENCODE = new TextEncoder().encode(ALPHABET);
const DECODE = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();
const PAD = 0x3d; // '='
const ascii = new TextDecoder('ascii');

export function encodeBase64(bytes: Uint8Array): string {
  const out = new Uint8Array(4 * Math.ceil(bytes.length / 3));
  const full = bytes.length - (bytes.length % 3);
  let o = 0;
  let i = 0;
  for (; i < full; i += 3) {
    const x = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out[o++] = ENCODE[x >>> 18];
    out[o++] = ENCODE[(x >>> 12) & 63];
    out[o++] = ENCODE[(x >>> 6) & 63];
    out[o++] = ENCODE[x & 63];
  }
  if (bytes.length - full === 1) {
    const x = bytes[i] << 16;
    out[o++] = ENCODE[x >>> 18];
    out[o++] = ENCODE[(x >>> 12) & 63];
    out[o++] = PAD;
    out[o++] = PAD;
  } else if (bytes.length - full === 2) {
    const x = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out[o++] = ENCODE[x >>> 18];
    out[o++] = ENCODE[(x >>> 12) & 63];
    out[o++] = ENCODE[(x >>> 6) & 63];
    out[o++] = PAD;
  }
  // Every output byte is ASCII, which every TextDecoder label decodes alike.
  return ascii.decode(out);
}

function sextet(s: string, i: number): number {
  const c = s.charCodeAt(i);
  return c < 128 ? DECODE[c] : -1;
}

/** Padded standard base64 to bytes; null on any other character or layout. */
function decodeStrict(s: string): Uint8Array | null {
  const len = s.length;
  if (len % 4 !== 0) return null;
  let pad = 0;
  if (len > 0 && s.charCodeAt(len - 1) === PAD) pad = s.charCodeAt(len - 2) === PAD ? 2 : 1;
  const out = new Uint8Array((len / 4) * 3 - pad);
  // A rejection zero-fills what was decoded so far: the value may be key
  // material (SPEC-03 REQ-27).
  const fail = (): null => {
    out.fill(0);
    return null;
  };
  let o = 0;
  for (let i = 0; i < len; i += 4) {
    const a = sextet(s, i);
    const b = sextet(s, i + 1);
    if (a < 0 || b < 0) return fail();
    const last = i + 4 === len;
    if (last && pad === 2) {
      out[o++] = (a << 2) | (b >> 4);
      break;
    }
    const c = sextet(s, i + 2);
    if (c < 0) return fail();
    if (last && pad === 1) {
      out[o++] = (a << 2) | (b >> 4);
      out[o++] = ((b & 15) << 4) | (c >> 2);
      break;
    }
    const d = sextet(s, i + 3);
    if (d < 0) return fail();
    out[o++] = (a << 2) | (b >> 4);
    out[o++] = ((b & 15) << 4) | (c >> 2);
    out[o++] = ((c & 3) << 6) | d;
  }
  return out;
}

/**
 * Decode canonical base64 (SPEC-02 §6.2): padded, no whitespace, and
 * re-encoding must reproduce the input exactly. Returns null otherwise, or
 * when `expectedLength` is given and differs.
 */
export function decodeCanonicalBase64(s: string, expectedLength?: number): Uint8Array | null {
  const bytes = decodeStrict(s);
  if (bytes === null) return null;
  if ((expectedLength !== undefined && bytes.length !== expectedLength) || encodeBase64(bytes) !== s) {
    // Rejected values are zero-filled before they are dropped (REQ-27).
    bytes.fill(0);
    return null;
  }
  return bytes;
}

/** Decode a relay wire payload (standard base64 with padding). Null if malformed. */
export function decodeWireBase64(s: string): Uint8Array | null {
  return decodeStrict(s);
}
