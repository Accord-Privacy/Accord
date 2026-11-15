/**
 * Searches captured bytes (traffic, database files, blob store, relay logs)
 * for secrets in every form a leak could take (SPEC-02 RG-C004-1, T-7, T-47):
 * raw bytes, base64 with and without padding, base64url, hex in either case,
 * and, for text, UTF-8 and percent-encoded UTF-8.
 *
 * Base64 runs in text are also decoded and searched, so a plaintext that was
 * merely base64-wrapped (as the legacy fallbacks did) is found too.
 */

export interface Needle {
  readonly label: string;
  readonly bytes: Buffer;
}

/** Every encoding of a binary secret (a key or nonce prefix). */
export function binaryNeedles(label: string, secret: Uint8Array): Needle[] {
  const raw = Buffer.from(secret);
  const b64 = raw.toString('base64');
  const b64url = raw.toString('base64url');
  const hex = raw.toString('hex');
  const forms = new Map<string, Buffer>([
    [`${label} raw`, raw],
    [`${label} base64`, Buffer.from(b64)],
    [`${label} base64 unpadded`, Buffer.from(b64.replace(/=+$/, ''))],
    [`${label} base64url`, Buffer.from(b64url)],
    [`${label} hex`, Buffer.from(hex)],
    [`${label} HEX`, Buffer.from(hex.toUpperCase())],
  ]);
  return [...forms].map(([l, bytes]) => ({ label: l, bytes }));
}

/** Every encoding of a text secret (a file name, a body canary). */
export function textNeedles(label: string, text: string): Needle[] {
  const utf8 = Buffer.from(text, 'utf8');
  const forms = new Map<string, Buffer>([
    [`${label} utf8`, utf8],
    [`${label} percent-encoded`, Buffer.from(encodeURIComponent(text))],
    [`${label} json-escaped`, Buffer.from(JSON.stringify(text).slice(1, -1))],
    [`${label} hex`, Buffer.from(utf8.toString('hex'))],
  ]);
  return [...forms].map(([l, bytes]) => ({ label: l, bytes }));
}

const BASE64_RUN = /[A-Za-z0-9+/_-]{24,}={0,2}/g;

/** The haystacks plus the decodings of every base64 run found in them. */
function withDecodedRuns(haystacks: readonly Buffer[]): Buffer[] {
  const out: Buffer[] = [...haystacks];
  for (const h of haystacks) {
    const text = h.toString('latin1');
    for (const m of text.matchAll(BASE64_RUN)) {
      const run = m[0];
      const url = /[-_]/.test(run);
      for (let shift = 0; shift < 4; shift++) {
        const part = run.slice(shift);
        const decoded = Buffer.from(part, url ? 'base64url' : 'base64');
        if (decoded.length > 0) out.push(decoded);
      }
    }
  }
  return out;
}

/** The labels of the needles found in any haystack (empty when nothing leaked). */
export function findLeaks(haystacks: readonly Buffer[], needles: readonly Needle[]): string[] {
  const all = withDecodedRuns(haystacks);
  const found = new Set<string>();
  for (const n of needles) {
    if (n.bytes.length === 0) continue;
    if (all.some(h => h.includes(n.bytes))) found.add(n.label);
  }
  return [...found];
}
