/**
 * SPEC-02 wiring of the client: T-11 (descriptors stay out of every consumer
 * of `Message.content`), T-19 (own attachments render after a reload from the
 * persisted cache), T-17 and T-45 (no channel-key file crypto, no legacy
 * upload route), and static checks that App.tsx routes every display path
 * through the decode function, pairs by hash only and cleans up (REQ-8,
 * REQ-24, REQ-49).
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeWireBase64, encodeBase64 } from './base64';
import { decodeMessage } from './decode';
import { readCacheValue, serializeEnvelope, type DescriptorInput } from './envelope';
import { AttachmentStore } from './store';
import { decodedFields } from './messageFields';
import { PendingSendManager } from './send';
import { createConversationSealer } from './sealer';
import { notificationBody } from '../notifications';
import { useBookmarks } from '../hooks/useBookmarks';
import { loadOwnMessages, saveOwnMessages } from '../e2ee/persistence';
import { SenderKeyStore } from '../e2ee/senderKeys';
import { E2EEManager, generateIdentityKeyPair, generateOneTimePreKeys, generateSignedPreKey } from '../e2ee';

const SRC = join(process.cwd(), 'src');
const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const D = 'd1d1d1d1-0000-4000-8000-000000000001';
const ME = '11111111-1111-4111-8111-111111111111';
const ALICE = '22222222-2222-4222-8222-222222222222';

const KEY = Uint8Array.from({ length: 32 }, (_, i) => 200 - i);
const NP = Uint8Array.from([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6]);
const DESCRIPTOR: DescriptorInput = {
  blobId: '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04', key: KEY, noncePrefix: NP, sha256: new Uint8Array(32).fill(9),
  size: 5, paddedSize: 5, name: 'secret-report.pdf', mime: 'application/pdf',
};

const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const b64url = (b: Uint8Array) => encodeBase64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const forms = (b: Uint8Array) => [encodeBase64(b), b64url(b), hex(b), new TextDecoder('latin1').decode(b)];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(p);
  }
  return out;
}

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('T-11 (REQ-11): descriptors never reach a consumer of Message.content', () => {
  it('content is the body; bookmarks, notifications and logs hold no key, prefix or name', async () => {
    const logs: unknown[][] = [];
    for (const level of ['log', 'info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(console, level).mockImplementation((...args: unknown[]) => { logs.push(args); });
    }
    const body = 'hi https://example.com';
    const envelope = serializeEnvelope({ channelId: X, body, attachments: [DESCRIPTOR] });
    const store = new AttachmentStore();
    const decoded = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: ME },
      { channelId: X, messageId: 'm1', senderId: ALICE, payload: encodeBase64(Uint8Array.from([7, 7, 7])) },
      { decryptors: { senderKeys: () => envelope }, cache: { get: () => undefined, put: () => {} }, store },
    );
    const fields = decodedFields(decoded, false);
    expect(fields.content).toBe(body);
    expect(fields._attachmentCount).toBe(1);
    expect(fields.e2eeType).toBe('sender-keys');
    expect(store.size).toBe(1);

    // Bookmarks copy Message.content into plaintext localStorage (C108).
    const { result } = renderHook(() => useBookmarks());
    act(() => result.current.addBookmark({ id: 'm1', content: fields.content, channelId: X, channelName: 'general', author: 'Alice', timestamp: 1, savedAt: 2 }));
    // The notification shows the body and the count, never names (OD-38).
    const note = notificationBody({ content: fields.content, _attachmentCount: fields._attachmentCount }, true);
    expect(note).toBe(`${body} (1 attachment)`);
    expect(notificationBody({ content: '', _attachmentCount: 3 }, true)).toBe('3 attachments');
    expect(notificationBody({ content: body, _attachmentCount: 1 }, false)).toBe('New message received');

    const everything = [JSON.stringify(localStorage), note, fields.content, JSON.stringify(logs)].join('\n');
    for (const secret of [KEY, NP]) for (const f of forms(secret)) expect(everything).not.toContain(f);
    expect(everything).not.toContain('secret-report');
    expect(everything).not.toContain('accord.content');
  });

  it('placeholders reach no consumer as plaintext', () => {
    expect(notificationBody({ content: 'Invalid message format', _placeholder: 'invalid_format' }, true)).toBe('New message received');
  });
});

describe('T-19 (REQ-19): own attachments render after a reload', () => {
  it('pairs, persists a §6.2.4 own record, and decodes it again from the reloaded cache', async () => {
    const keys = new SenderKeyStore();
    keys.getOrCreateMyKey(X);
    const sealer = createConversationSealer({
      e2ee: () => null, senderKeys: () => keys, bootstrapSenderKey: () => false,
      fetchBundle: async () => undefined, persistSenderKeys: () => {}, legacyText: () => null,
    });
    const cache = new Map<string, unknown>();
    let frame: { wire: string; ids: readonly string[] } | null = null;
    let blob: Uint8Array | null = null;
    const mgr = new PendingSendManager({
      transport: {
        async upload(_ch, b) {
          blob = new Uint8Array(await b.arrayBuffer());
          return { attachment_id: DESCRIPTOR.blobId, blob_size: blob.length, blob_sha256: hex(sha256(blob)), pending_expires_at: Date.now() / 1000 + 3600 };
        },
        deleteAttachment: async () => 204,
        sendFrame: (_ch, sealed, o) => {
          frame = { wire: sealed.wire, ids: o.attachmentIds ?? [] };
          return { handedOff: true, messageId: 'x' };
        },
        history: async () => ({ items: [], hasMore: false }),
      },
      sealer,
      cache: { put: r => { cache.set(r.message_id, r); } },
      ownUserId: () => ME,
      origin: () => ORIGIN,
      limits: () => ({ available: true, maxBlobBytes: null }),
    });
    const prepared = await mgr.prepare({ conversation: { kind: 'channel', channelId: X }, body: 'my file', files: [{ file: new Blob([Uint8Array.from([1, 2, 3, 4, 5])]), name: 'mine.pdf', type: 'application/pdf' }] });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) return;
    await mgr.start(prepared.send);
    const relayId = '99999999-9999-4999-8999-999999999999';
    expect(mgr.pairLiveEcho({ channelId: X, messageId: relayId, senderId: ME, payload: frame!.wire }, { attachment_ids: frame!.ids })).not.toBeNull();

    // The record: own, this channel, this sender and id, the wire hash, and the exact envelope.
    const value = readCacheValue(cache.get(relayId), relayId);
    expect(value.kind).toBe('record');
    if (value.kind !== 'record') return;
    expect(value.record).toMatchObject({ v: 1, origin: ORIGIN, channel_id: X, sender_id: ME, message_id: relayId, source: 'own' });
    expect(value.record.wire_sha256).toBe(encodeBase64(sha256(decodeWireBase64(frame!.wire)!)));
    expect(value.record.plaintext.startsWith('{"type":"accord.content","v":1,"notice":')).toBe(true);
    expect(value.record.plaintext).toContain('"body":"my file"');

    // Re-initialize from the persisted, encrypted cache.
    saveOwnMessages(ME, cache, 'pw');
    expect(localStorage.getItem(`accord_e2ee_ownmsgs_${ME}`)).not.toContain('mine.pdf');
    const reloaded = loadOwnMessages(ME, 'pw');
    const store = new AttachmentStore();
    const decoded = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: ME },
      { channelId: X, messageId: relayId, senderId: ME, payload: frame!.wire },
      { decryptors: {}, cache: { get: id => reloaded.get(id), put: () => {} }, store },
    );
    expect(decoded).toMatchObject({ verified: true, source: 'cache', cacheSource: 'own', body: 'my file', attachmentCount: 1 });
    expect(store.get({ origin: ORIGIN, channelId: X, messageId: relayId })?.attachments[0]).toMatchObject({ usable: true, descriptor: { blobId: DESCRIPTOR.blobId, name: 'mine.pdf' } });
  });

  it('variant: a DM attachment received while another conversation is open is stored as a dr record and renders after a reload', async () => {
    const mgr = (): E2EEManager => {
      const m = new E2EEManager();
      m.initializeWithKeys(generateIdentityKeyPair(), generateSignedPreKey(), generateOneTimePreKeys(4));
      return m;
    };
    const alice = mgr();
    const me = mgr();
    const envelope = serializeEnvelope({ channelId: D, body: 'for you', attachments: [DESCRIPTOR] });
    const wire = encodeBase64(new TextEncoder().encode(alice.encryptEnvelope(ME, envelope, me.getPreKeyBundle())));
    const cache = new Map<string, unknown>();
    const messageId = '88888888-8888-4888-8888-888888888888';
    const live = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: D, ownUserId: ME },
      { channelId: D, messageId, senderId: ALICE, payload: wire },
      {
        decryptors: { doubleRatchet: (sender, payload) => me.decryptEnvelope(sender, new TextDecoder().decode(decodeWireBase64(payload)!)) },
        cache: { get: id => cache.get(id), put: r => { cache.set(r.message_id, r); } },
        store: new AttachmentStore(),
      },
    );
    expect(live).toMatchObject({ source: 'dr', attachmentCount: 1 });
    saveOwnMessages(ME, cache, 'pw');
    const store = new AttachmentStore();
    const again = await decodeMessage(
      { origin: ORIGIN, renderedChannelId: D, ownUserId: ME },
      { channelId: D, messageId, senderId: ALICE, payload: wire },
      { decryptors: {}, cache: { get: id => loadOwnMessages(ME, 'pw').get(id), put: () => {} }, store },
    );
    expect(again).toMatchObject({ verified: true, source: 'cache', cacheSource: 'dr', body: 'for you', attachmentCount: 1 });
    expect(store.size).toBe(1);
  });
});

describe('T-17 (REQ-17) and T-45 (REQ-45): no channel-key file crypto, no legacy uploads', () => {
  const files = walk(SRC);

  it('exports no encryptFile, decryptFile, encryptFilename or decryptFilename', () => {
    for (const f of files) {
      expect(readFileSync(f, 'utf8'), relative(SRC, f)).not.toMatch(/export\s+(async\s+)?function\s+(encryptFile|decryptFile|encryptFilename|decryptFilename)\b/);
    }
  });

  it('no file or attachment module other than the legacy reader imports getChannelKey', () => {
    const fileModules = files.filter(f => /(^|\/)(attachments\/|FileManager|components\/(ImageGrid|MessageAttachments|LegacyUploads|AttachmentName))/.test(relative(SRC, f)));
    expect(fileModules.length).toBeGreaterThan(5);
    const importers = fileModules.filter(f => /\bgetChannelKey\b/.test(readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, '')));
    expect(importers.map(f => relative(SRC, f))).toEqual(['attachments/legacy.ts']);
  });

  it('no source POSTs to /channels/{id}/files or builds a multipart upload', () => {
    for (const f of files) {
      const src = readFileSync(f, 'utf8');
      expect(src, relative(SRC, f)).not.toMatch(/['"`]POST['"`][^;]*\/files\b|\/files[`'"]\s*,\s*\{[^}]*method:\s*['"]POST/);
      expect(src, relative(SRC, f)).not.toMatch(/new FormData\(\)[\s\S]{0,200}encrypted_filename/);
    }
    const api = readFileSync(join(SRC, 'api.ts'), 'utf8');
    expect(api).not.toMatch(/async uploadFile\(|async downloadFile\(|async getChannelFiles\(|async deleteFile\(/);
  });

  it('the Playwright mock of a contract the relay never had is gone (T-26, RG-C164)', () => {
    expect(() => readFileSync(join(SRC, '../e2e/file-upload.spec.ts'), 'utf8')).toThrow();
  });
});

describe('App.tsx wiring (static)', () => {
  const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
  const handler = (name: string) => {
    const a = app.indexOf(`socket.on('${name}'`);
    expect(a, name).toBeGreaterThanOrEqual(0);
    const b = app.indexOf('socket.on(', a + 10);
    return app.slice(a, b);
  };

  it('REQ-8: live frames, history and edits go through the decode function; no keyPair gate', () => {
    expect(handler('channel_message')).toMatch(/decodeFor\(/);
    expect(handler('message_edit')).toMatch(/decodeEdit\(/);
    expect(handler('message_edit')).toMatch(/data\.sender_id/);
    expect(handler('message_edit')).not.toMatch(/data\.from\b/);
    const history = app.slice(app.indexOf('const mapServerMessage = useCallback('), app.indexOf('}, [decodeFor, pendingSends]);'));
    expect(history).toMatch(/decodeFor\(/);
    for (const segment of [handler('channel_message'), handler('message_edit'), history]) {
      expect(segment).not.toMatch(/encryptionEnabled|keyPairRef|getChannelKey|ownMessagesRef/);
    }
  });

  it('REQ-49: own echoes pair by hash in every channel, never with the oldest temporary message', () => {
    const live = handler('channel_message');
    expect(live).toMatch(/pendingSends\.pairLiveEcho\(/);
    expect(live.indexOf('pairLiveEcho')).toBeLessThan(live.indexOf('isCurrentChannel'));
    expect(app).not.toMatch(/startsWith\('temp_'\)/);
    expect(app).toMatch(/pendingSends\.pairHistoryItem\(/);
    expect(app).toMatch(/pendingSends\.onClaimFailed\(/);
    expect(app).toMatch(/pendingSends\.onReconnect\(\)/);
  });

  it('REQ-24: delete, purge and the expiry sweep drop attachment state and cache records', () => {
    expect(handler('message_delete')).toMatch(/dropMessageState\(/);
    expect(handler('messages_purged')).toMatch(/dropMessageState\(/);
    const sweep = app.slice(app.indexOf('const sweepExpiredMessages = useCallback('), app.indexOf('const stampGatedReadsForChannel'));
    expect(sweep).toMatch(/dropMessageState\(/);
    expect(sweep).toMatch(/local_expires_at/);
    expect(app).toMatch(/forgetMessages\(ids,/);
  });

  it('REQ-48: every send goes through the pending-send manager or the sealed edit', () => {
    expect(app).not.toMatch(/_retryPayload/);
    expect(app.match(/\.sendChannelMessage\(/g)).toHaveLength(1); // the manager's transport
    expect(app).toMatch(/sealEdit\(/);
  });
});
