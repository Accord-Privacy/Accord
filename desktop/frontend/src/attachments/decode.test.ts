// @vitest-environment node
/**
 * SPEC-02 T-8 (REQ-8), T-50 (REQ-50) and T-51 (REQ-51): the decode function,
 * the attachment store and the explicit relay field copy.
 *
 * The decryptors are fakes with the properties that matter here: a Double
 * Ratchet payload opens only once and only for its sender (message keys are
 * consumed), a Sender Keys payload opens only with the key held for its
 * sender in its channel, and the legacy channel key opens anything the relay
 * could have encrypted. T-8 (h) is a pairing case and belongs with the send
 * module's tests (REQ-49).
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeEach, describe, expect, it } from 'vitest';
import { decodeWireBase64, encodeBase64 } from './base64';
import {
  decodeEdit,
  decodeMessage,
  isVerifiedAttachmentSet,
  isVerifiedDescriptor,
  PLACEHOLDER_TEXT,
  wireSha256,
  type DecodeContext,
  type Decryptors,
  type PlaintextCacheAccess,
  type VerifiedAttachmentSet,
  type WireMessage,
} from './decode';
import { readCacheValue, serializeEnvelope, type DescriptorInput, type PlaintextCacheRecord } from './envelope';
import { AttachmentStore, type StoreEvent } from './store';
import { relayMessageFields } from '../relayMessage';

const SRC = fileURLToPath(new URL('../', import.meta.url));
const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7'; // node channel
const Y = '0b6e5a1c-3d2f-4e8a-9c7b-1a2b3c4d5e6f'; // another node channel
const D = 'd1d1d1d1-0000-4000-8000-000000000001'; // DM channel
const ME = '11111111-1111-4111-8111-111111111111';
const ALICE = '22222222-2222-4222-8222-222222222222';
const MALLORY = '33333333-3333-4333-8333-333333333333';

const DESCRIPTOR: DescriptorInput = {
  blobId: '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04',
  key: new Uint8Array(32).map((_, i) => i),
  noncePrefix: new Uint8Array([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6]),
  sha256: new Uint8Array(32).fill(9),
  size: 5,
  paddedSize: 5,
  name: 'hello.txt',
  mime: 'text/plain',
};

const envelope = (channelId: string, body = 'look', attachments: DescriptorInput[] = [DESCRIPTOR]) =>
  serializeEnvelope({ channelId, body, attachments });

const b64 = (s: string) => encodeBase64(new TextEncoder().encode(s));
const unb64 = (p: string) => {
  const bytes = decodeWireBase64(p);
  return bytes ? new TextDecoder().decode(bytes) : null;
};

type Sealed = { kind: 'dr' | 'sk' | 'legacy'; from?: string; ch?: string; pt: string; n: number };
let nonce = 0;
/** A fake ciphertext: base64 of a JSON wrapper (unique per call, like real ciphertexts). */
function seal(kind: Sealed['kind'], pt: string, opts: { from?: string; ch?: string } = {}): string {
  return b64(JSON.stringify({ kind, pt, n: nonce++, ...opts }));
}
function open(payload: string): Sealed | null {
  try {
    return JSON.parse(unb64(payload) ?? '') as Sealed;
  } catch {
    return null;
  }
}

class World {
  readonly store = new AttachmentStore();
  readonly cache = new Map<string, unknown>();
  readonly puts: PlaintextCacheRecord[] = [];
  readonly consumed = new Set<string>();
  /** Sender keys held: `${channel}|${sender}`. */
  readonly senderKeys = new Set<string>([`${X}|${ALICE}`]);

  readonly decryptors: Decryptors = {
    doubleRatchet: (senderId, payload) => {
      const s = open(payload);
      if (!s || s.kind !== 'dr' || s.from !== senderId || this.consumed.has(payload)) return null;
      this.consumed.add(payload);
      return s.pt;
    },
    senderKeys: (channelId, senderId, payload) => {
      const s = open(payload);
      if (!s || s.kind !== 'sk' || !this.senderKeys.has(`${channelId}|${senderId}`) || s.ch !== channelId) return null;
      return s.pt;
    },
    legacyChannelKey: (channelId, payload) => {
      const s = open(payload);
      return s && s.kind === 'legacy' && s.ch === channelId ? s.pt : null;
    },
  };

  readonly cacheAccess: PlaintextCacheAccess = {
    get: id => this.cache.get(id),
    put: record => {
      this.puts.push(record);
      this.cache.set(record.message_id, record);
    },
  };

  ctx(channel: string): DecodeContext {
    return { origin: ORIGIN, renderedChannelId: channel, ownUserId: ME };
  }

  decode(channel: string, item: WireMessage) {
    return decodeMessage(this.ctx(channel), item, { decryptors: this.decryptors, cache: this.cacheAccess, store: this.store });
  }

  edit(channel: string, edit: { messageId: string; senderId: string; payload: string }, target: { messageId: string; senderId: string }) {
    return decodeEdit(this.ctx(channel), { channelId: channel, ...edit }, { channelId: channel, ...target },
      { decryptors: this.decryptors, store: this.store });
  }

  entry(channel: string, messageId: string) {
    return this.store.get({ origin: ORIGIN, channelId: channel, messageId });
  }
}

let w: World;
beforeEach(() => {
  w = new World();
});

describe('T-8 attachment state only from authenticated, bound plaintext (REQ-8)', () => {
  it('(a) an unencrypted envelope in a live frame: body with the warning, no attachment state', async () => {
    const out = await w.decode(X, { channelId: X, messageId: 'm-a', senderId: ALICE, payload: b64(envelope(X)) });
    expect(out).toMatchObject({ display: 'content', body: 'look', verified: false, source: 'raw', attachmentCount: 0, attachmentsIgnored: true });
    expect(w.store.size).toBe(0);
    expect(w.puts).toEqual([]);
  });

  it('(b) an envelope under the legacy channel key: body with the warning, no attachment state', async () => {
    const out = await w.decode(X, { channelId: X, messageId: 'm-b', senderId: ALICE, payload: seal('legacy', envelope(X), { ch: X }) });
    expect(out).toMatchObject({ display: 'content', body: 'look', source: 'legacy_key', verified: false, attachmentsIgnored: true });
    expect(w.store.size).toBe(0);
    expect(w.puts).toEqual([]);
  });

  it('(c) relay JSON fields never become attachment state', async () => {
    const relayItem = {
      id: 'm-c', channel_id: X, sender_id: ALICE, encrypted_payload: seal('sk', 'just text', { ch: X }),
      files: [{ id: 'f', encrypted_filename: 'x' }], attachments: [{ blob_id: DESCRIPTOR.blobId }],
      attachment_ids: [DESCRIPTOR.blobId], created_at: 1, edited_at: null,
    };
    const fields = relayMessageFields(relayItem) as unknown as Record<string, unknown>;
    expect(fields).not.toHaveProperty('files');
    expect(fields).not.toHaveProperty('attachments');
    expect(fields).not.toHaveProperty('attachment_ids');
    const out = await w.decode(X, { channelId: X, messageId: 'm-c', senderId: ALICE, payload: relayItem.encrypted_payload });
    expect(out).toMatchObject({ body: 'just text', attachmentCount: 0, attachmentsIgnored: false });
    expect(w.store.size).toBe(0);
  });

  it('(d) a Sender Keys envelope naming the frame channel: attachment shown, with no keyPair gate', async () => {
    // No legacy decryptor and no keyPair or encryptionEnabled input: Sender Keys alone suffices.
    const deps = { decryptors: { senderKeys: w.decryptors.senderKeys }, cache: w.cacheAccess, store: w.store };
    const out = await decodeMessage(w.ctx(X), { channelId: X, messageId: 'm-d', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) }, deps);
    expect(out).toMatchObject({ display: 'content', body: 'look', verified: true, source: 'sk', attachmentCount: 1, attachmentsIgnored: false });
    const entry = w.entry(X, 'm-d')!;
    expect(entry.senderId).toBe(ALICE);
    expect(entry.attachments).toHaveLength(1);
    const slot = entry.attachments[0];
    expect(slot.usable).toBe(true);
    if (slot.usable) {
      expect(isVerifiedDescriptor(slot.descriptor)).toBe(true);
      expect(slot.descriptor.name).toBe('hello.txt');
      expect(slot.descriptor.key).toEqual(DESCRIPTOR.key);
    }
    // Peer channel plaintext is not cached before P0 item 7 (OD-45).
    expect(w.puts).toEqual([]);
  });

  it('(d) a Sender Keys envelope needs the key held for that sender in that channel', async () => {
    const payload = seal('sk', envelope(Y), { ch: Y });
    const out = await w.decode(Y, { channelId: Y, messageId: 'm-d2', senderId: ALICE, payload });
    expect(out.verified).toBe(false);
    expect(w.store.size).toBe(0);
  });

  describe('(e) a cached message id served again', () => {
    const dmPayload = () => seal('dr', envelope(D), { from: ALICE });

    async function receiveDm() {
      const payload = dmPayload();
      const out = await w.decode(D, { channelId: D, messageId: 'm-e', senderId: ALICE, payload });
      expect(out).toMatchObject({ source: 'dr', attachmentCount: 1 });
      expect(w.puts).toHaveLength(1);
      w.store.clear();
      return payload;
    }

    it('writes a dr record in the §6.2.4 format and re-creates state from it when everything matches', async () => {
      const payload = await receiveDm();
      const record = w.puts[0];
      expect(record).toEqual({
        v: 1, origin: ORIGIN, channel_id: D, sender_id: ALICE, message_id: 'm-e',
        wire_sha256: wireSha256(payload), source: 'dr', plaintext: envelope(D),
      });
      const again = await w.decode(D, { channelId: D, messageId: 'm-e', senderId: ALICE, payload });
      expect(again).toMatchObject({ source: 'cache', cacheSource: 'dr', verified: true, attachmentCount: 1 });
      expect(w.entry(D, 'm-e')).toBeDefined();
      expect(w.puts).toHaveLength(1);
    });

    it('in another channel', async () => {
      const payload = await receiveDm();
      const out = await w.decode(X, { channelId: X, messageId: 'm-e', senderId: ALICE, payload });
      expect(out).toMatchObject({ display: 'placeholder', placeholder: 'wrong_conversation', body: '' });
      expect(w.store.size).toBe(0);
    });

    it('with another sender', async () => {
      const payload = await receiveDm();
      const out = await w.decode(D, { channelId: D, messageId: 'm-e', senderId: MALLORY, payload });
      expect(out).toMatchObject({ verified: false, source: 'legacy_cache', attachmentCount: 0, attachmentsIgnored: true });
      expect(w.store.size).toBe(0);
    });

    it('with a different payload', async () => {
      await receiveDm();
      const out = await w.decode(D, { channelId: D, messageId: 'm-e', senderId: ALICE, payload: b64('something else') });
      expect(out).toMatchObject({ verified: false, attachmentCount: 0, attachmentsIgnored: true });
      expect(w.store.size).toBe(0);
    });

    it('from another relay origin', async () => {
      const payload = await receiveDm();
      const out = await decodeMessage({ origin: 'https://other.example', renderedChannelId: D, ownUserId: ME },
        { channelId: D, messageId: 'm-e', senderId: ALICE, payload },
        { decryptors: w.decryptors, cache: w.cacheAccess, store: w.store });
      expect(out.verified).toBe(false);
      expect(w.store.size).toBe(0);
    });
  });

  it('(f) a forged own echo reusing a cached id with another payload', async () => {
    const own: PlaintextCacheRecord = {
      v: 1, origin: ORIGIN, channel_id: X, sender_id: ME, message_id: 'm-f',
      wire_sha256: wireSha256(b64('sealed bytes'))!, source: 'own', plaintext: envelope(X),
    };
    w.cache.set('m-f', own);
    const genuine = await w.decode(X, { channelId: X, messageId: 'm-f', senderId: ME, payload: b64('sealed bytes') });
    expect(genuine).toMatchObject({ source: 'cache', cacheSource: 'own', attachmentCount: 1 });
    w.store.clear();
    const forged = await w.decode(X, { channelId: X, messageId: 'm-f', senderId: ME, payload: b64('forged bytes') });
    expect(forged).toMatchObject({ verified: false, attachmentCount: 0 });
    expect(w.store.size).toBe(0);
  });

  it('(g) a DM Double Ratchet ciphertext delivered into a node channel', async () => {
    const payload = seal('dr', envelope(D), { from: ALICE });
    const out = await w.decode(X, { channelId: X, messageId: 'm-g', senderId: ALICE, payload });
    expect(out).toMatchObject({ display: 'placeholder', placeholder: 'wrong_conversation', body: '', attachmentCount: 0 });
    expect(PLACEHOLDER_TEXT[out.placeholder!]).toBe('Message not verified for this conversation');
    expect(w.store.size).toBe(0);
    expect(w.puts).toEqual([]); // no record for an envelope of another channel (REQ-19)
  });

  it('(i) a plain-string legacy cache entry holding an envelope: text at most', async () => {
    w.cache.set('m-i', envelope(X));
    const out = await w.decode(X, { channelId: X, messageId: 'm-i', senderId: ALICE, payload: b64('undecryptable') });
    expect(out).toMatchObject({ display: 'content', body: 'look', source: 'legacy_cache', verified: false, attachmentCount: 0 });
    expect(w.store.size).toBe(0);
  });

  it('an item whose own channel differs from the requested history gets no attachment state', async () => {
    const out = await w.decode(X, { channelId: Y, messageId: 'm-j', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) });
    expect(out).toMatchObject({ body: 'look', attachmentCount: 0, attachmentsIgnored: true });
    expect(w.store.size).toBe(0);
  });

  it('keeps unusable descriptors as unusable entries (REQ-9)', async () => {
    const text = envelope(X).replace('"scheme":"A256GCM-STREAM64K"', '"scheme":"X"');
    await w.decode(X, { channelId: X, messageId: 'm-k', senderId: ALICE, payload: seal('sk', text, { ch: X }) });
    expect(w.entry(X, 'm-k')!.attachments).toEqual([{ usable: false }]);
  });
});

describe('placeholders and the display path (§8.2, REQ-9, REQ-53)', () => {
  it('discards control payloads and legacy key JSON silently, caching nothing', async () => {
    for (const pt of ['\u001eaccord-call\u001e{"type":"call_hello","v":1}', '\u001eaccord-xyz\u001e{}', '{"type":"skdm","ch":"c"}']) {
      const out = await w.decode(D, { channelId: D, messageId: `m-${pt.length}`, senderId: ALICE, payload: seal('dr', pt, { from: ALICE }) });
      expect(out.display).toBe('hidden');
      expect(out.body).toBe('');
    }
    expect(w.puts).toEqual([]);
    expect(w.store.size).toBe(0);
  });

  it('shows invalid and newer envelopes as placeholders only', async () => {
    const invalid = await w.decode(X, { channelId: X, messageId: 'm-1', senderId: ALICE, payload: seal('sk', `{"type":"accord.content","v":1,"channel_id":"${X}","body":"a","body":"b"}`, { ch: X }) });
    expect(invalid).toMatchObject({ display: 'placeholder', placeholder: 'invalid_format', body: '' });
    const newer = await w.decode(X, { channelId: X, messageId: 'm-2', senderId: ALICE, payload: seal('sk', `{"type":"accord.content","v":2,"channel_id":"${X}","body":"x"}`, { ch: X }) });
    expect(newer).toMatchObject({ display: 'placeholder', placeholder: 'newer_version', body: '' });
    expect(w.store.size).toBe(0);
  });

  it('writes dr records for Double Ratchet text, in the record format', async () => {
    const payload = seal('dr', 'hi there', { from: ALICE });
    const out = await w.decode(D, { channelId: D, messageId: 'm-t', senderId: ALICE, payload });
    expect(out).toMatchObject({ body: 'hi there', source: 'dr', verified: true });
    expect(readCacheValue(w.cache.get('m-t'), 'm-t')).toMatchObject({ kind: 'record', record: { source: 'dr', plaintext: 'hi there', channel_id: D } });
  });

  it('shows the other-session placeholder for an unpaired own message with nothing cached', async () => {
    const out = await w.decode(X, { channelId: X, messageId: 'm-o', senderId: ME, payload: b64('opaque') });
    expect(out).toMatchObject({ display: 'placeholder', placeholder: 'other_session' });
    w.cache.set('m-o', 'old text');
    expect(await w.decode(X, { channelId: X, messageId: 'm-o', senderId: ME, payload: b64('opaque') })).toMatchObject({ body: 'old text' });
  });

  it('shows an undecryptable payload as the relay sent it', async () => {
    const payload = b64('ÿþ binary-ish') + '';
    const out = await w.decode(X, { channelId: X, messageId: 'm-r', senderId: ALICE, payload: 'not base64!' });
    expect(out).toMatchObject({ display: 'content', body: 'not base64!', source: 'raw' });
    const out2 = await w.decode(X, { channelId: X, messageId: 'm-r2', senderId: ALICE, payload });
    expect(out2.body).toBe(payload);
  });

  it('survives decryptors and caches that throw', async () => {
    const deps = {
      decryptors: { doubleRatchet: () => { throw new Error('boom'); }, senderKeys: async () => { throw new Error('boom'); } },
      cache: { get: () => { throw new Error('boom'); }, put: () => { throw new Error('boom'); } },
      store: w.store,
    };
    const out = await decodeMessage(w.ctx(X), { channelId: X, messageId: 'm-z', senderId: ALICE, payload: b64('x') }, deps);
    expect(out.source).toBe('raw');
  });
});

describe('T-50 edits never touch attachment state (REQ-50)', () => {
  async function attachmentMessage(id: string) {
    await w.decode(X, { channelId: X, messageId: id, senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) });
    expect(w.entry(X, id)).toBeDefined();
  }

  it('drops an authenticated edit that turns a text message into an envelope with descriptors', async () => {
    await w.decode(X, { channelId: X, messageId: 't-1', senderId: ALICE, payload: seal('sk', 'plain text', { ch: X }) });
    const decision = await w.edit(X, { messageId: 't-1', senderId: ALICE, payload: seal('sk', envelope(X, 'swapped'), { ch: X }) }, { messageId: 't-1', senderId: ALICE });
    expect(decision).toEqual({ action: 'drop' });
    expect(w.store.size).toBe(0);
  });

  it('drops an edit whose envelope has an attachments member of any value', async () => {
    for (const value of ['[]', 'null', '"x"', '{}']) {
      const pt = `{"type":"accord.content","v":1,"channel_id":"${X}","body":"b","attachments":${value}}`;
      expect(await w.edit(X, { messageId: 't-2', senderId: ALICE, payload: seal('sk', pt, { ch: X }) }, { messageId: 't-2', senderId: ALICE }))
        .toEqual({ action: 'drop' });
    }
  });

  it('drops relay-forged edits (legacy key or raw) targeting an attachment message', async () => {
    await attachmentMessage('a-1');
    expect(await w.edit(X, { messageId: 'a-1', senderId: ALICE, payload: seal('legacy', 'new caption', { ch: X }) }, { messageId: 'a-1', senderId: ALICE }))
      .toEqual({ action: 'drop' });
    expect(await w.edit(X, { messageId: 'a-1', senderId: ALICE, payload: b64('new caption') }, { messageId: 'a-1', senderId: ALICE }))
      .toEqual({ action: 'drop' });
    // Even an authenticated one.
    expect(await w.edit(X, { messageId: 'a-1', senderId: ALICE, payload: seal('sk', 'new caption', { ch: X }) }, { messageId: 'a-1', senderId: ALICE }))
      .toEqual({ action: 'drop' });
    expect(w.entry(X, 'a-1')!.attachments).toHaveLength(1);
  });

  it('shows the body of the REQ-10 escape', async () => {
    const pt = `{"type":"accord.content","v":1,"channel_id":"${X}","body":"{\\"type\\":\\"accord.content\\"}"}`;
    expect(await w.edit(X, { messageId: 't-3', senderId: ALICE, payload: seal('sk', pt, { ch: X }) }, { messageId: 't-3', senderId: ALICE }))
      .toEqual({ action: 'apply', body: '{"type":"accord.content"}', verified: true, source: 'sk' });
  });

  it('drops an edit whose sender_id differs from the target sender', async () => {
    expect(await w.edit(X, { messageId: 't-4', senderId: MALLORY, payload: seal('sk', 'hijack', { ch: X }) }, { messageId: 't-4', senderId: ALICE }))
      .toEqual({ action: 'drop' });
  });

  it('applies a genuine Sender Keys edit of a text message, sender taken from sender_id', async () => {
    expect(await w.edit(X, { messageId: 't-5', senderId: ALICE, payload: seal('sk', 'fixed typo', { ch: X }) }, { messageId: 't-5', senderId: ALICE }))
      .toEqual({ action: 'apply', body: 'fixed typo', verified: true, source: 'sk' });
  });

  it('drops control payloads, invalid and newer envelopes, and escapes for another channel', async () => {
    const cases = [
      '\u001eaccord-call\u001e{"type":"call_hello","v":1}',
      `{"type":"accord.content","v":1,"channel_id":"${X}","body":1}`,
      `{"type":"accord.content","v":2,"channel_id":"${X}","body":"x"}`,
      `{"type":"accord.content","v":1,"channel_id":"${Y}","body":"x"}`,
      '{"type":"skdm","ch":"c"}',
    ];
    for (const pt of cases) {
      expect(await w.edit(X, { messageId: 't-6', senderId: ALICE, payload: seal('sk', pt, { ch: X }) }, { messageId: 't-6', senderId: ALICE }))
        .toEqual({ action: 'drop' });
    }
  });

  it('shows an edited history item that carries attachments as unverifiable', async () => {
    const out = await w.decode(X, { channelId: X, messageId: 'h-1', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }), editedAt: 1_700_000_000 });
    expect(out).toMatchObject({ display: 'placeholder', placeholder: 'edited_unverified', body: '' });
    expect(PLACEHOLDER_TEXT.edited_unverified).toBe('Edited message could not be verified');
    expect(w.store.size).toBe(0);
    // An edited escape is shown as its body, still without attachment state.
    const esc = await w.decode(X, { channelId: X, messageId: 'h-2', senderId: ALICE, payload: seal('sk', `{"type":"accord.content","v":1,"channel_id":"${X}","body":"e"}`, { ch: X }), editedAt: 1 });
    expect(esc).toMatchObject({ display: 'content', body: 'e', attachmentCount: 0 });
  });
});

describe('T-51 the attachment store and the explicit field copy (REQ-51)', () => {
  it('accepts only sets the decode function built', async () => {
    await w.decode(X, { channelId: X, messageId: 's-1', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) });
    const entry = w.entry(X, 's-1')!;
    const forged = { key: { origin: ORIGIN, channelId: X, messageId: 's-2' }, senderId: ALICE, attachments: entry.attachments };
    expect(() => w.store.put(forged as unknown as VerifiedAttachmentSet)).toThrow(TypeError);
    expect(isVerifiedAttachmentSet(forged)).toBe(false);
    expect(isVerifiedDescriptor({ ...(entry.attachments[0] as { descriptor: object }).descriptor })).toBe(false);
    expect(w.store.has({ origin: ORIGIN, channelId: X, messageId: 's-2' })).toBe(false);
  });

  it('keys entries by origin, channel and message id, and supports removal (REQ-24)', async () => {
    const events: StoreEvent['type'][] = [];
    const unsubscribe = w.store.subscribe(e => events.push(e.type));
    await w.decode(X, { channelId: X, messageId: 's-3', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) });
    await w.decode(X, { channelId: X, messageId: 's-4', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) });
    await decodeMessage({ origin: 'https://other.example', renderedChannelId: X, ownUserId: ME },
      { channelId: X, messageId: 's-3', senderId: ALICE, payload: seal('sk', envelope(X), { ch: X }) },
      { decryptors: w.decryptors, cache: w.cacheAccess, store: w.store });
    expect(w.store.size).toBe(3);
    expect(w.store.listChannel(ORIGIN, X).map(e => e.key.messageId).sort()).toEqual(['s-3', 's-4']);
    expect(w.store.remove({ origin: ORIGIN, channelId: X, messageId: 's-3' })?.key.messageId).toBe('s-3');
    expect(w.store.remove({ origin: ORIGIN, channelId: X, messageId: 's-3' })).toBeUndefined();
    expect(w.store.removeChannel(ORIGIN, X)).toHaveLength(1);
    expect(w.store.size).toBe(1);
    w.store.clear();
    unsubscribe();
    w.store.clear();
    expect(events).toEqual(['put', 'put', 'put', 'removed', 'removed', 'cleared']);
  });

  it('copies only known relay fields, with their types', () => {
    const f = relayMessageFields({
      id: 'm', channel_id: X, sender_id: ALICE, sender_public_key_hash: 'abc', display_name: 'Alice',
      edited_at: null, pinned_at: 5, pinned_by: ME, reply_to: 'r', reply_count: 2, read_gated: true, gate_ttl_secs: 60,
      replied_message: { id: 'r', sender_id: ALICE, encrypted_payload: 'p', created_at: 3, files: [1] },
      reactions: [{ emoji: ':)', count: 1, users: [ME, 7], created_at: 4 }, 'junk'],
      files: [{}], attachments: [{}], attachment_ids: ['x'], encrypted_payload: 'secret', content: 'relay text', __proto__: { evil: 1 },
    });
    expect(f).toEqual({
      id: 'm', channel_id: X, sender_id: ALICE, sender_public_key_hash: 'abc', display_name: 'Alice',
      edited_at: undefined, pinned_at: 5, pinned_by: ME, expires_at: undefined, read_gated: true, gate_ttl_secs: 60,
      reply_to: 'r', reply_count: 2,
      replied_message: { id: 'r', sender_id: ALICE, sender_public_key_hash: '', encrypted_payload: 'p', created_at: 3, content: undefined },
      reactions: [{ emoji: ':)', count: 1, users: [ME], created_at: 4 }],
    });
    expect(relayMessageFields(null)).toMatchObject({ id: '' });
  });

  it('static: the descriptor constructor stays private to the decode module', () => {
    const decodeSrc = readFileSync(join(SRC, 'attachments/decode.ts'), 'utf8');
    expect(decodeSrc).toMatch(/\nfunction mintAttachmentSet\(/);
    expect(decodeSrc).not.toMatch(/export\s+(async\s+)?function\s+mintAttachmentSet|export\s*\{[^}]*mintAttachmentSet/);
    for (const file of ['attachments/store.ts', 'attachments/envelope.ts', 'App.tsx', 'SearchOverlay.tsx', 'relayMessage.ts']) {
      expect(readFileSync(join(SRC, file), 'utf8')).not.toContain('mintAttachmentSet');
    }
    // Only the decode module writes the store.
    for (const file of ['App.tsx', 'SearchOverlay.tsx', 'FileManager.tsx', 'components/ChatArea.tsx', 'components/ImageGrid.tsx']) {
      expect(readFileSync(join(SRC, file), 'utf8')).not.toMatch(/attachmentStore\.put\(|store\.put\(/);
    }
  });

  it('static: Message has no attachment fields, and no view reads them off a relay object', () => {
    const types = readFileSync(join(SRC, 'types.ts'), 'utf8');
    const start = types.indexOf('export interface Message {');
    expect(start).toBeGreaterThanOrEqual(0);
    const messageType = types.slice(start, types.indexOf('\n}', start));
    expect(messageType).not.toMatch(/^\s*(files|attachments|attachment_ids)\??:/m);
    // History, pins, threads and search build Messages here; the pinned and
    // thread panels (Modals.tsx) and the message list (ChatArea.tsx) render them.
    for (const file of ['App.tsx', 'SearchOverlay.tsx', 'relayMessage.ts', 'components/ChatArea.tsx', 'components/Modals.tsx']) {
      expect(readFileSync(join(SRC, file), 'utf8'), file).not.toMatch(/[\w)\]]\.(files|attachments|attachment_ids)\b/);
    }
  });

  it('static: no relay object is spread into a Message (history, pins, threads, search)', () => {
    const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
    const segment = (start: string, end: string) => {
      const a = app.indexOf(start);
      expect(a, start).toBeGreaterThanOrEqual(0);
      const b = app.indexOf(end, a + start.length);
      expect(b, end).toBeGreaterThan(a);
      return app.slice(a, b);
    };
    // History goes through decodeHistoryItem (attachments/history.ts), whose
    // output is the only thing spread; pins and threads through the explicit
    // mappings of relayMessage.ts, with nothing spread in App.tsx.
    const history = segment('const mapServerMessage = useCallback(', '}, [decodeFor, pendingSends]);');
    expect(history).toMatch(/const fields = await decodeHistoryItem\(/);
    expect(history.replace(/\.\.\.fields\b/g, '')).not.toMatch(/\.\.\.\s*[A-Za-z_$]/);
    const pins = segment('const loadPinnedMessages = async', 'const openThread = async');
    expect(pins).toMatch(/pinnedMessageFromRelay\(/);
    const threads = segment('const openThread = async', 'finally {');
    expect(threads).toMatch(/threadMessageFromRelay\(/);
    for (const s of [pins, threads]) expect(s).not.toMatch(/\.\.\.\s*[A-Za-z_$]/);
    // The modules: only the explicit relay field copy and the decode
    // function's own output (`decodedFields`) are spread.
    const historyModule = readFileSync(join(SRC, 'attachments', 'history.ts'), 'utf8');
    expect(historyModule).toContain('...relayMessageFields(raw)');
    expect(historyModule.replace(/\.\.\.(relayMessageFields|decodedFields)\(/g, '')).not.toMatch(/\.\.\.\s*[A-Za-z_$]/);
    const relay = readFileSync(join(SRC, 'relayMessage.ts'), 'utf8');
    expect(relay).not.toMatch(/\.\.\.\s*(raw|m|r|msg)\b/);
    expect(relay.replace(/\.\.\.fields\b/g, '')).not.toMatch(/\.\.\.\s*[A-Za-z_$]/);
    expect(relay.match(/const fields = relayMessageFields\(m\);/g)).toHaveLength(2);
    const search = readFileSync(join(SRC, 'SearchOverlay.tsx'), 'utf8');
    expect(search).toMatch(/return searchResultFromRelay\(r, decrypted_content\);/);
    expect(search).not.toMatch(/\{\s*\.\.\.r\s*,/);
  });
});
