/**
 * SPEC-02 §10.3: the regression replays that run on the client alone, and
 * the index of every row of the table.
 *
 * | Row        | Where                                                                                   |
 * |------------|-----------------------------------------------------------------------------------------|
 * | RG-C004-1  | src/__integration__/spec02-two-client.test.ts (real relay, node channel and DM)          |
 * | RG-C004-2  | src/__integration__/spec02-two-client.test.ts (real relay, node channel and DM)          |
 * | RG-C004-3  | here: the history, pin, thread and search mappings App.tsx and SearchOverlay use, SearchOverlay rendered, forged live frames through the decode function |
 * | RG-C008    | src/__integration__/spec02-two-client.test.ts ((a) to (e) injected by the proxy, (f) history re-served by the relay); (f) also in src/__tests__/ChatArea.test.tsx and src/attachments/render.test.ts |
 * | RG-C024    | src/__integration__/spec02-two-client.test.ts; also send.test.ts                         |
 * | RG-C193    | src/attachments/send.test.ts                                                             |
 * | RG-C090    | src/__integration__/spec02-two-client.test.ts; the 30 s timer in send.test.ts; relay ids in server/tests/spec02_claim_legacy_test.rs |
 * | RG-C011    | here                                                                                    |
 * | RG-C192    | src/attachments/send.test.ts                                                             |
 * | RG-C140    | server/tests/spec02_attachment_store_test.rs; end to end in spec02-two-client.test.ts    |
 * | RG-C164    | (a) server/tests/spec02_claim_legacy_test.rs; (b) here (the bbf2f17 FileList and the new legacy section) and spec02-two-client.test.ts (the real relay's JSON); (c), (d) spec02-two-client.test.ts |
 * | RG-C150    | server/tests/spec02_attachment_store_test.rs                                             |
 * | RG-C156    | server/tests/spec02_attachment_store_test.rs                                             |
 * | RG-C161    | server/tests/spec02_attachment_store_test.rs, server/tests/spec02_claim_legacy_test.rs   |
 * | RG-C160    | server/tests/spec02_attachment_store_test.rs                                             |
 * | RG-C001    | server/tests/spec02_attachment_store_test.rs, server/tests/spec02_claim_legacy_test.rs   |
 * | RG-C054    | server/tests/spec02_claim_legacy_test.rs                                                 |
 * | RG-C196    | src/attachments/sanitize.test.tsx                                                        |
 */

import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createElement } from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { api } from '../api';
import { pinnedMessageFromRelay, threadMessageFromRelay } from '../relayMessage';
import { SearchOverlay, searchResultFromRelay } from '../SearchOverlay';
import { LegacyUploads, LEGACY_TOGGLE_TEXT, resetLegacyToggleForTests } from '../components/LegacyUploads';
import { LEGACY_NAME_UNAVAILABLE, resetLegacyStateForTests } from './legacy';
import { oldFileListNames, renderOldFileList } from '../__integration__/bbf2f17FileList';
import { decodeHistoryItem } from './history';
import { attachmentEntryFor } from './render';
import { decodeMessage, type Decryptors } from './decode';
import { serializeEnvelope } from './envelope';
import { AttachmentStore } from './store';
import { canOfferEdit, sealEdit } from './edit';
import { encryptMessage, decryptMessage } from '../crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import type { ConversationSealer } from './send';

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const D = '0b1c2d3e-4f50-4a61-8b72-9c8d7e6f5a4b';
const ALICE = '11111111-2222-4333-8444-555555555555';
const BOB = '66666666-7777-4888-8999-aaaaaaaaaaaa';

const DESCRIPTOR = {
  blobId: '6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f04',
  key: new Uint8Array(32).fill(7),
  noncePrefix: new Uint8Array(7).fill(9),
  sha256: new Uint8Array(32).fill(3),
  size: 5,
  paddedSize: 5,
  name: 'invoice.pdf',
  mime: 'application/pdf',
};

const ENVELOPE = serializeEnvelope({ channelId: X, body: 'forged caption', attachments: [DESCRIPTOR] });

const b64 = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

/** The legacy channel key a relay can compute (C004). */
const legacyKey = (channelId: string) => sha256(new TextEncoder().encode(`${channelId}:accord-channel-key-v1`));

function decoderFor(decryptors: Decryptors) {
  const store = new AttachmentStore();
  const cache = new Map<string, unknown>();
  const decode = (item: { channelId: string; messageId: string; senderId: string; payload: string; editedAt?: number | null }) =>
    decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: BOB },
      item,
      { decryptors, store, cache: { get: id => cache.get(id), put: r => void cache.set(r.message_id, r) } },
    );
  return { store, cache, decode };
}

describe('RG-C004-3: forgery through the old fallbacks creates no attachment UI', () => {
  // A client with the legacy keyPair and the opt-in: the legacy decryptor applies.
  const decryptors: Decryptors = {
    senderKeys: () => null,
    legacyChannelKey: (channelId, payload) => decryptMessage(legacyKey(channelId), payload),
  };

  /** A relay item carrying every attachment field a forgery could use. */
  function forgedItem(id: string): Record<string, unknown> {
    return {
      id, message_id: id, channel_id: X, channel_name: 'general', sender_id: ALICE, sender_public_key_hash: 'ab'.repeat(16),
      encrypted_payload: b64('hello'), content: 'hello', created_at: 1, pinned_at: 2,
      files: [{ id: 'f', channel_id: X, encrypted_filename: 'evil.exe', file_size_bytes: 1, storage_path: './x' }],
      attachments: [JSON.parse(ENVELOPE).attachments[0]],
      attachment_ids: [DESCRIPTOR.blobId],
    };
  }

  /** A verified entry under the same key, as a decode of the real message would leave it. */
  async function seedVerifiedEntry(store: AttachmentStore, id: string): Promise<void> {
    await decodeMessage(
      { origin: ORIGIN, renderedChannelId: X, ownUserId: BOB },
      { channelId: X, messageId: id, senderId: ALICE, payload: b64('sk') },
      { decryptors: { senderKeys: () => ENVELOPE }, store, cache: { get: () => undefined, put: () => {} } },
    );
    expect(store.has({ origin: ORIGIN, channelId: X, messageId: id })).toBe(true);
  }

  const NO_ATTACHMENT_FIELDS = (o: object, label: string) => {
    for (const f of ['files', 'attachments', 'attachment_ids']) expect(Object.keys(o), `${label} ${f}`).not.toContain(f);
    for (const f of ['_attachmentCount', '_attachmentRef']) expect((o as Record<string, unknown>)[f], `${label} ${f}`).toBeUndefined();
  };

  it('a files array on a history item: the history mapping App.tsx uses copies none of it and creates no state', async () => {
    const { store, cache, decode } = decoderFor(decryptors);
    const fields = await decodeHistoryItem(forgedItem('history-1'), X, false, item => decode(item));
    expect(fields).not.toBeNull();
    NO_ATTACHMENT_FIELDS(fields!, 'history');
    expect(attachmentEntryFor(fields!, ORIGIN, store)).toBeNull();
    expect(store.listChannel(ORIGIN, X)).toEqual([]);
    expect(cache.size).toBe(0);
  });

  it("pinned and thread items: App.tsx's mappings copy none of it and show no attachments, even over a verified entry", async () => {
    const store = new AttachmentStore();
    for (const [label, map] of [
      ['pinned', (raw: unknown) => pinnedMessageFromRelay(raw, h => h.slice(0, 8))],
      ['thread', (raw: unknown) => threadMessageFromRelay(raw)],
    ] as const) {
      const id = `${label}-1`;
      await seedVerifiedEntry(store, id);
      const msg = map(forgedItem(id));
      NO_ATTACHMENT_FIELDS(msg, label);
      expect(msg).toMatchObject({ id, channel_id: X, sender_id: ALICE, content: 'hello' });
      // Pins and threads are not decoded in stage 1: they never show attachment UI (REQ-51).
      expect(attachmentEntryFor(msg, ORIGIN, store), label).toBeNull();
    }
    // The pinned and thread panels render no attachment component at all.
    const modals = readFileSync(join(process.cwd(), 'src', 'components', 'Modals.tsx'), 'utf8');
    expect(modals).not.toMatch(/MessageAttachments|AttachmentCard|ImageGrid|attachmentStore/);
  });

  it("search results: SearchOverlay's field copy keeps none of it, and the rendered results show no attachment UI", async () => {
    const result = searchResultFromRelay(forgedItem('search-1'), undefined);
    NO_ATTACHMENT_FIELDS(result, 'search');
    expect(Object.keys(result).sort()).toEqual([
      'channel_id', 'channel_name', 'created_at', 'decrypted_content', 'encrypted_payload', 'message_id', 'sender_id', 'sender_public_key_hash',
    ]);

    const search = vi.spyOn(api, 'searchMessages').mockResolvedValue({ results: [forgedItem('search-1')] } as never);
    const { container } = render(createElement(SearchOverlay, {
      isVisible: true, onClose: () => {}, nodeId: 'node-1', token: 't', onNavigateToMessage: () => {},
      channels: [{ id: X, name: 'general', node_id: 'node-1', channel_type: 'text', position: 0, members: [], created_at: 1 } as never],
      keyPair: null, encryptionEnabled: false, currentMessages: [], currentChannelId: X,
    }));
    fireEvent.click(screen.getByText('Server'));
    fireEvent.change(screen.getByPlaceholderText(/^Search messages/), { target: { value: 'hello' } });
    await waitFor(() => expect(search).toHaveBeenCalled());
    await waitFor(() => expect(container.querySelector('.search-result')).not.toBeNull());
    expect(container.querySelector('.message-attachments, [data-testid="attachment-card"], .file-attachment, img')).toBeNull();
    expect(container.textContent).not.toMatch(/evil\.exe|invoice/);
    cleanup();
    search.mockRestore();
  });

  it('an unencrypted envelope as a live channel_message: body with the warning, no attachment state', async () => {
    const { store, cache, decode } = decoderFor(decryptors);
    const decoded = await decode({ channelId: X, messageId: 'live-1', senderId: ALICE, payload: b64(ENVELOPE) });
    expect(decoded.attachmentCount).toBe(0);
    expect(decoded.attachmentsIgnored).toBe(true);
    expect(decoded.body).toBe('forged caption');
    expect(store.listChannel(ORIGIN, X)).toEqual([]);
    expect(cache.size).toBe(0);
  });

  it('an envelope encrypted under the legacy channel key: body with the warning, no attachment state', async () => {
    const { store, cache, decode } = decoderFor(decryptors);
    const payload = await encryptMessage(legacyKey(X), ENVELOPE);
    const decoded = await decode({ channelId: X, messageId: 'live-2', senderId: ALICE, payload });
    expect(decoded.source).toBe('legacy_key');
    expect(decoded.attachmentCount).toBe(0);
    expect(decoded.attachmentsIgnored).toBe(true);
    expect(decoded.body).toBe('forged caption');
    expect(store.listChannel(ORIGIN, X)).toEqual([]);
    expect(cache.size).toBe(0);
  });
});

describe('RG-C011: a DM edit never leaves the client in plaintext', () => {
  it('DMs offer no Edit, and an edit invoked anyway is refused before any sealing or sending', async () => {
    const msg = { channel_id: D, _pendingId: undefined, _placeholder: undefined, _attachmentCount: 0, _attachmentsIgnored: false };
    const facts = { isDm: true, hasAttachmentState: false, pendingWithAttachments: false };
    expect(canOfferEdit(msg, facts)).toBe(false);
    const sealer: ConversationSealer = { ready: vi.fn(async () => true), seal: vi.fn() };
    const result = await sealEdit(msg, facts, 'edited secret text', sealer);
    expect(result).toMatchObject({ ok: false, reason: 'dm' });
    expect(sealer.ready).not.toHaveBeenCalled();
    expect(sealer.seal).not.toHaveBeenCalled();
  });

  it('App.tsx sends edits only through sealEdit, and the send functions take only a sealed payload (static)', () => {
    const app = readFileSync(join(process.cwd(), 'src', 'App.tsx'), 'utf8');
    expect(app).toMatch(/sealEdit\(/);
    // Every edit send passes the sealed payload sealEdit returned.
    for (const m of app.matchAll(/(?:sendEditMessage|api\.editMessage)\(([^)]*)\)/g)) {
      expect(m[1], m[0]).toMatch(/sealed/);
    }
  });
});

describe('RG-C164 (b): the Files panel, old and new, renders R1 legacy rows without crashing', () => {
  // GET /channels/{id}/files as R1 answers it (§6.4.5; the real relay's answer
  // is replayed in src/__integration__/spec02-two-client.test.ts): strings,
  // "" for a name over 4,096 bytes and for one that is not UTF-8, and no
  // storage_path or content_hash.
  async function r1List(): Promise<Array<Record<string, unknown>>> {
    const key = sha256(new TextEncoder().encode(`${X}:accord-channel-key-v1`));
    const row = (id: string, name: string) => ({ id, channel_id: X, uploader_id: ALICE, encrypted_filename: name, file_size_bytes: 1040, created_at: 1_791_600_000 });
    return [
      row('f-ok', await encryptMessage(key, 'report.pdf')),
      row('f-oversized', ''),
      row('f-not-utf8', ''),
    ];
  }

  // The same rows from the bbf2f17 relay: `encrypted_filename` serialized from
  // Vec<u8> as a JSON array of bytes, plus storage_path and content_hash.
  function bbf2f17List(): Array<Record<string, unknown>> {
    return [
      { id: 'f-ok', channel_id: X, uploader_id: ALICE, encrypted_filename: [...new TextEncoder().encode('QUJDRA==')], file_size_bytes: 1040, content_hash: 'h', storage_path: './data/files/f-ok', created_at: 1_791_600_000 },
      { id: 'f-not-utf8', channel_id: X, uploader_id: ALICE, encrypted_filename: [0xff, 0xfe, 0x80], file_size_bytes: 1, content_hash: 'h', storage_path: './data/files/f-not-utf8', created_at: 1_791_600_000 },
    ];
  }

  it('the bbf2f17 FileList renders the R1 JSON, with "" for the two bad names', async () => {
    const json = JSON.parse(JSON.stringify(await r1List())) as unknown;
    let markup = '';
    expect(() => { markup = renderOldFileList(json); }).not.toThrow();
    const names = oldFileListNames(markup);
    expect(names).toHaveLength(3);
    expect(names.slice(1)).toEqual(['', '']);
  });

  it('control: the same FileList crashes on the bbf2f17 relay output (the original C164 crash)', () => {
    const json = JSON.parse(JSON.stringify(bbf2f17List())) as unknown;
    expect(() => renderOldFileList(json)).toThrow(TypeError);
  });

  it('the new legacy section renders the R1 JSON: the good name, and "(name unavailable)" twice', async () => {
    const json = JSON.stringify(await r1List());
    vi.stubGlobal('fetch', vi.fn(async () => new Response(json, { status: 200, headers: { 'Content-Type': 'application/json' } })));
    try {
      resetLegacyStateForTests();
      resetLegacyToggleForTests();
      render(createElement(LegacyUploads, { channelId: X, keyPair: null }));
      fireEvent.click(screen.getByRole('button', { name: LEGACY_TOGGLE_TEXT }));
      await waitFor(() => expect(screen.getAllByText(LEGACY_NAME_UNAVAILABLE)).toHaveLength(2));
      expect(screen.getByText('report')).toBeInTheDocument();
    } finally {
      cleanup();
      vi.unstubAllGlobals();
    }
  });
});
