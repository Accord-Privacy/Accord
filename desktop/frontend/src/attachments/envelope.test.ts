// @vitest-environment node
/**
 * SPEC-02 §6.2 (content envelope v1, attachment descriptor v1), §6.2.4 (the
 * plaintext cache record) and the REQ-10 escape: the T-9 cases beyond the
 * shared vector table (`e2ee/plaintext.test.ts`), T-10, and the codecs the
 * decode function builds on.
 */
import { describe, expect, it } from 'vitest';
import { acceptedPaths, classifyPlaintext, ENVELOPE_PREFIX } from '../e2ee/plaintext';
import { decodeCanonicalBase64, decodeWireBase64, encodeBase64 } from './base64';
import {
  ATTACHMENT_NOTICE,
  buildEscapeEnvelope,
  isCanonicalUuid,
  isValidMime,
  makeCacheRecord,
  MAX_BODY_BYTES,
  MAX_ENVELOPE_BYTES,
  parseEnvelope,
  readCacheValue,
  relayOrigin,
  serializeDescriptor,
  serializeEnvelope,
  textPlaintextFor,
  type DescriptorInput,
} from './envelope';
import { decodeEdit, decodeMessage } from './decode';
import { AttachmentStore } from './store';

const C = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const BLOB = '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04';

function fromHex(h: string): Uint8Array {
  return Uint8Array.from(h.match(/../g)!.map(x => parseInt(x, 16)));
}

/** The TV2 descriptor of §6.2.3. */
const TV2: DescriptorInput = {
  blobId: BLOB,
  key: fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
  noncePrefix: fromHex('a0a1a2a3a4a5a6'),
  sha256: fromHex('1fd4278e2fb28271798c55e7801ed95d7f57b5c16f417e87ce74eed0dfd71aa6'),
  size: 5,
  paddedSize: 5,
  name: 'hello.txt',
  mime: 'text/plain',
};

/** §6.2.3, without insignificant whitespace (REQ-10). */
const EXAMPLE = '{"type":"accord.content","v":1,'
  + '"notice":"This message has end-to-end encrypted attachments. Update Accord to view them.",'
  + '"channel_id":"7c9e6679-7425-40de-944b-e07fc1f90ae7","body":"notes from today","attachments":[{"v":1,'
  + '"blob_id":"6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04","scheme":"A256GCM-STREAM64K",'
  + '"key":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","nonce_prefix":"oKGio6Slpg==",'
  + '"sha256":"H9Qnji+ygnF5jFXngB7ZXX9XtcFvQX6HznTu0N/XGqY=","size":5,"padded_size":5,'
  + '"name":"hello.txt","mime":"text/plain"}]}';

describe('base64 (RFC 4648 §4, canonical)', () => {
  it('round-trips and rejects every non-canonical form', () => {
    const key = TV2.key;
    expect(encodeBase64(key)).toBe('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=');
    expect(decodeCanonicalBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', 32)).toEqual(key);
    expect(decodeCanonicalBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', 31)).toBeNull();
    expect(decodeCanonicalBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8')).toBeNull(); // no padding
    expect(decodeCanonicalBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=')).toBeNull(); // non-zero pad bits
    expect(decodeCanonicalBase64('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n')).toBeNull();
    expect(decodeCanonicalBase64('AAEC AwQF')).toBeNull();
    expect(decodeCanonicalBase64('AAEC-_QF')).toBeNull(); // base64url
    expect(decodeCanonicalBase64('A===')).toBeNull();
    expect(decodeCanonicalBase64('AA=A')).toBeNull();
    expect(decodeCanonicalBase64('')).toEqual(new Uint8Array(0));
    expect(decodeCanonicalBase64('oKGio6Slpg==', 7)).toEqual(TV2.noncePrefix);
  });

  it('encodes large inputs without spreading them into one call', () => {
    const big = new Uint8Array(3 * 1024 * 1024 + 1).fill(0xab);
    const s = encodeBase64(big);
    expect(s.length).toBe(4 * Math.ceil(big.length / 3));
    expect(s).toBe(Buffer.from(big).toString('base64'));
    const back = decodeWireBase64(s)!;
    expect(back.length).toBe(big.length);
    expect(Buffer.from(back).equals(Buffer.from(big))).toBe(true);
  });
});

describe('descriptor and envelope serialization (§6.2.1 to §6.2.3)', () => {
  it('reproduces the §6.2.3 example byte for byte', () => {
    const env = serializeEnvelope({ channelId: C, body: 'notes from today', attachments: [TV2] });
    expect(env).toBe(EXAMPLE);
    expect(env.startsWith(ENVELOPE_PREFIX)).toBe(true);
    expect(JSON.parse(env).notice).toBe(ATTACHMENT_NOTICE);
  });

  it('reads back what it writes', () => {
    const r = parseEnvelope(EXAMPLE);
    expect(r?.status).toBe('valid');
    if (r?.status !== 'valid') return;
    expect(r.envelope.channelId).toBe(C);
    expect(r.envelope.body).toBe('notes from today');
    expect(r.envelope.hasAttachmentsMember).toBe(true);
    const slot = r.envelope.attachments[0];
    expect(slot.usable).toBe(true);
    if (!slot.usable) return;
    expect(slot.descriptor).toMatchObject({ blobId: BLOB, scheme: 'A256GCM-STREAM64K', size: 5, paddedSize: 5, name: 'hello.txt', mime: 'text/plain' });
    expect(slot.descriptor.key).toEqual(TV2.key);
    expect(slot.descriptor.noncePrefix).toEqual(TV2.noncePrefix);
    expect(slot.descriptor.sha256).toEqual(TV2.sha256);
  });

  it('refuses to build envelopes a receiver would reject', () => {
    expect(() => serializeEnvelope({ channelId: C.toUpperCase(), body: 'x' })).toThrow(RangeError);
    const eleven = Array.from({ length: 11 }, (_, i) => ({ ...TV2, blobId: `6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f${String(i).padStart(2, '0')}` }));
    expect(() => serializeEnvelope({ channelId: C, attachments: eleven })).toThrow(RangeError);
    expect(() => serializeEnvelope({ channelId: C, attachments: [TV2, TV2] })).toThrow(RangeError);
    expect(() => serializeEnvelope({ channelId: C, body: '\ud800' })).toThrow(RangeError);
    expect(() => serializeDescriptor({ ...TV2, name: '' })).toThrow(RangeError);
    expect(() => serializeDescriptor({ ...TV2, name: 'a'.repeat(256) })).toThrow(RangeError);
    expect(() => serializeDescriptor({ ...TV2, mime: 'Text/Plain' })).toThrow(RangeError);
    expect(() => serializeDescriptor({ ...TV2, size: 6 })).toThrow(RangeError);
    expect(() => serializeDescriptor({ ...TV2, key: new Uint8Array(31) })).toThrow(RangeError);
  });

  it('escapes JSON so that quotes and control characters survive', () => {
    const body = 'a"b\\c\n\u0001 😀';
    const r = parseEnvelope(serializeEnvelope({ channelId: C, body, attachments: [TV2] }));
    expect(r?.status === 'valid' && r.envelope.body).toBe(body);
  });

  it('checks UUIDs and MIME types as §6.2.2 defines them', () => {
    expect(isCanonicalUuid(BLOB)).toBe(true);
    expect(isCanonicalUuid(BLOB.toUpperCase())).toBe(false);
    expect(isCanonicalUuid(`{${BLOB}}`)).toBe(false);
    expect(isCanonicalUuid(BLOB.replace(/-/g, ''))).toBe(false);
    for (const ok of ['text/plain', 'application/octet-stream', 'image/svg+xml', 'application/vnd.ms-excel', 'a/b', 'x-a!#$&^_.+/y']) {
      expect(isValidMime(ok)).toBe(true);
    }
    for (const bad of ['Text/plain', 'text/plain; charset=utf-8', 'text', '/plain', 'text/', '-text/plain', 'text/pl ain', `${'a'.repeat(128)}/b`, 'a/b/c']) {
      expect(isValidMime(bad)).toBe(false);
    }
    expect(isValidMime(`${'a'.repeat(127)}/${'b'.repeat(127)}`)).toBe(true);
  });
});

describe('T-9 extra cases', () => {
  const withDescriptor = (patch: Record<string, unknown>) => {
    const d = { ...JSON.parse(serializeDescriptor(TV2)), ...patch };
    return `{"type":"accord.content","v":1,"channel_id":"${C}","attachments":[${JSON.stringify(d)}]}`;
  };
  const unusable = (text: string) => {
    const r = parseEnvelope(text);
    return r?.status === 'valid' ? r.envelope.attachments.map(a => !a.usable) : r?.status;
  };

  it('marks a descriptor unusable, and keeps the envelope, for each descriptor rule', () => {
    expect(unusable(withDescriptor({}))).toEqual([false]);
    expect(unusable(withDescriptor({ key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==' }))).toEqual([true]); // 31 bytes
    expect(unusable(withDescriptor({ nonce_prefix: 'oKGio6Sl' }))).toEqual([true]); // 6 bytes
    expect(unusable(withDescriptor({ sha256: 'H9Qnji+ygnF5jFXngB7ZXX9XtcFvQX6HznTu0N/XGqY' }))).toEqual([true]);
    expect(unusable(withDescriptor({ blob_id: BLOB.toUpperCase() }))).toEqual([true]);
    expect(unusable(withDescriptor({ scheme: 'A256GCM-STREAM1M' }))).toEqual([true]);
    expect(unusable(withDescriptor({ v: 2 }))).toEqual([true]);
    expect(unusable(withDescriptor({ size: 6 }))).toEqual([true]);
    expect(unusable(withDescriptor({ padded_size: 104_857_600 }))).toEqual([true]);
    expect(unusable(withDescriptor({ name: 7 }))).toEqual([true]);
    expect(unusable(withDescriptor({ mime: 'text/plain;charset=utf-8' }))).toEqual([true]);
    expect(unusable(withDescriptor({ width: 640, thumbnail: { x: [1] } }))).toEqual([false]);
  });

  it('invalidates the envelope for number forms anywhere, also in descriptors', () => {
    for (const n of ['-1', '0.5', '5.0', '5e0', '9007199254740992']) {
      const text = withDescriptor({}).replace('"size":5,', `"size":${n},`);
      expect(parseEnvelope(text)).toMatchObject({ status: 'invalid', reason: 'number' });
    }
  });

  it('invalidates the envelope for a prefix followed by bytes that are not UTF-8', () => {
    const bytes = new TextEncoder().encode(`${ENVELOPE_PREFIX},"v":1,"channel_id":"${C}","body":"x"}`);
    const bad = new Uint8Array(bytes.length + 1);
    bad.set(bytes.subarray(0, bytes.length - 2));
    bad.set([0xc3, 0x22, 0x7d], bytes.length - 2);
    expect(parseEnvelope(bad)).toMatchObject({ status: 'invalid', reason: 'utf8' });
  });

  it('gives the newer-version placeholder for v > 1 and invalidates a non-integer v', () => {
    expect(parseEnvelope(`{"type":"accord.content","v":3}`)).toEqual({ status: 'newer_version' });
    expect(parseEnvelope(`{"type":"accord.content","v":true,"channel_id":"${C}"}`)).toMatchObject({ status: 'invalid' });
    expect(parseEnvelope(`{"type":"accord.content","channel_id":"${C}"}`)).toMatchObject({ status: 'invalid' });
  });

  it('is null for anything that is not a content envelope', () => {
    expect(parseEnvelope('hello')).toBeNull();
    expect(parseEnvelope('\u001eaccord-call\u001e{"type":"call_hello","v":1}')).toBeNull();
  });
});

describe('T-10 the REQ-10 escape', () => {
  const store = new AttachmentStore();
  const ctx = { origin: 'https://relay.example', renderedChannelId: C, ownUserId: '11111111-1111-4111-8111-111111111111' };
  const peer = '22222222-2222-4222-8222-222222222222';
  const b64 = (s: string) => encodeBase64(new TextEncoder().encode(s));

  /** Receive `plaintext` as a Sender Keys message from `peer`. */
  async function receive(plaintext: string) {
    const payload = b64(`sk:${plaintext}`);
    return decodeMessage(ctx, { channelId: C, messageId: 'm-1', senderId: peer, payload }, {
      decryptors: { senderKeys: (_c, _s, p) => new TextDecoder().decode(decodeWireBase64(p)!).slice(3) },
      cache: { get: () => undefined, put: () => {} },
      store,
    });
  }

  it('sends envelope-looking text as an escape envelope, shown verbatim', async () => {
    const typed = '{"type":"accord.content","v":1,"attachments":[]}';
    const out = textPlaintextFor(C, typed);
    expect(out).toEqual({ ok: true, escaped: true, plaintext: buildEscapeEnvelope(C, typed) });
    if (!out.ok) return;
    expect(JSON.parse(out.plaintext)).toEqual({ type: 'accord.content', v: 1, channel_id: C, body: typed });
    expect(out.plaintext.startsWith(ENVELOPE_PREFIX)).toBe(true);
    const shown = await receive(out.plaintext);
    expect(shown).toMatchObject({ display: 'content', body: typed, attachmentCount: 0, attachmentsIgnored: false });
    expect(store.size).toBe(0);
  });

  it('sends text that begins with U+001E as an escape envelope, never as a control payload', async () => {
    const typed = '\u001eaccord-call\u001e{"type":"call_hello","v":1}';
    const out = textPlaintextFor(C, typed);
    expect(out.ok && out.escaped).toBe(true);
    if (!out.ok) return;
    const c = classifyPlaintext(out.plaintext);
    expect(c.class).toBe('envelope');
    expect(acceptedPaths(c)).toEqual(['display']);
    expect((await receive(out.plaintext)).body).toBe(typed);
  });

  it('sends ordinary text unchanged', () => {
    expect(textPlaintextFor(C, 'hello')).toEqual({ ok: true, plaintext: 'hello', escaped: false });
    expect(textPlaintextFor(C, ' \u001e x')).toEqual({ ok: true, plaintext: ' \u001e x', escaped: false });
  });

  it('applies the size limits to escape envelopes (REQ-52)', () => {
    const prefixText = '{"type":"accord.content"';
    expect(textPlaintextFor(C, prefixText + 'x'.repeat(9000))).toEqual({ ok: false, reason: 'too_long' });
    expect(textPlaintextFor(C, prefixText + 'x'.repeat(MAX_BODY_BYTES - prefixText.length)).ok).toBe(true);
    // Within MAX_BODY_BYTES raw, but quotes double when escaped.
    const quotes = prefixText + '"'.repeat(MAX_BODY_BYTES - prefixText.length);
    expect(buildEscapeEnvelope(C, quotes).length).toBeGreaterThan(MAX_ENVELOPE_BYTES);
    expect(textPlaintextFor(C, quotes)).toEqual({ ok: false, reason: 'too_long' });
    expect(textPlaintextFor(C, '{"type":"accord.content"\ud800')).toEqual({ ok: false, reason: 'malformed' });
  });

  it('shows the body of an escaped edit (REQ-50 rule 3)', async () => {
    const typed = '{"type":"accord.content","v":1}';
    const out = textPlaintextFor(C, typed);
    if (!out.ok) throw new Error('escape failed');
    const decision = await decodeEdit(ctx, { channelId: C, messageId: 'm-2', senderId: peer, payload: b64(out.plaintext) },
      { channelId: C, messageId: 'm-2', senderId: peer },
      { decryptors: { senderKeys: (_c, _s, p) => new TextDecoder().decode(decodeWireBase64(p)!) }, store });
    expect(decision).toEqual({ action: 'apply', body: typed, verified: true, source: 'sk' });
  });
});

describe('plaintext cache record v1 (§6.2.4)', () => {
  const fields = {
    origin: 'https://relay.example:8443',
    channel_id: C,
    sender_id: '22222222-2222-4222-8222-222222222222',
    message_id: 'msg-1',
    wire_sha256: 'H9Qnji+ygnF5jFXngB7ZXX9XtcFvQX6HznTu0N/XGqY=',
    source: 'own' as const,
    plaintext: EXAMPLE,
  };

  it('builds and reads a record', () => {
    const r = makeCacheRecord(fields);
    expect(r).toEqual({ v: 1, ...fields });
    expect(readCacheValue(JSON.parse(JSON.stringify(r)), 'msg-1')).toEqual({ kind: 'record', record: r });
  });

  it('refuses malformed records', () => {
    expect(() => makeCacheRecord({ ...fields, channel_id: C.toUpperCase() })).toThrow(RangeError);
    expect(() => makeCacheRecord({ ...fields, origin: 'https://Relay.example:8443' })).toThrow(RangeError);
    expect(() => makeCacheRecord({ ...fields, origin: 'https://relay.example:8443/' })).toThrow(RangeError);
    expect(() => makeCacheRecord({ ...fields, wire_sha256: 'AA==' })).toThrow(RangeError);
    expect(() => makeCacheRecord({ ...fields, source: 'x' as never })).toThrow(RangeError);
  });

  it('treats strings and incomplete or unknown records as legacy entries', () => {
    const record = { v: 1, ...fields };
    expect(readCacheValue(undefined, 'msg-1')).toEqual({ kind: 'absent' });
    expect(readCacheValue('hello', 'msg-1')).toEqual({ kind: 'legacy', text: 'hello' });
    expect(readCacheValue({ ...record, v: 2 }, 'msg-1')).toEqual({ kind: 'legacy', text: EXAMPLE });
    const { sender_id: _drop, ...missing } = record;
    void _drop;
    expect(readCacheValue(missing, 'msg-1').kind).toBe('legacy');
    expect(readCacheValue(record, 'msg-2').kind).toBe('legacy'); // key differs from message_id
    expect(readCacheValue({ ...record, source: 'sk2' }, 'msg-1').kind).toBe('legacy');
    expect(readCacheValue([EXAMPLE], 'msg-1')).toEqual({ kind: 'legacy', text: null });
  });

  it('derives the relay origin from the API base URL', () => {
    expect(relayOrigin('https://Relay.Example:8443/api/')).toBe('https://relay.example:8443');
    expect(relayOrigin('http://localhost:8080')).toBe('http://localhost:8080');
    expect(relayOrigin('https://relay.example:443')).toBe('https://relay.example');
    expect(relayOrigin('not a url')).toBeNull();
  });
});
