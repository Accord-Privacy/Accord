/**
 * SPEC-02 G2, REQ-8, REQ-51: a rendered message shows only the attachment
 * entry its own decode produced (`attachments/render.ts`), however long the
 * entry stays in the store and whatever the relay later serves under the
 * same id.
 */
import { describe, expect, it } from 'vitest';
import { decodeMessage, type Decryptors } from './decode';
import { serializeEnvelope, type DescriptorInput } from './envelope';
import { decodedFields } from './messageFields';
import { attachmentEntryFor, shownChannelAttachments, type AttachmentBearer } from './render';
import { AttachmentStore } from './store';

const ORIGIN = 'https://relay.example';
const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const ALICE = '22222222-2222-4222-8222-222222222222';
const CAROL = '33333333-3333-4333-8333-333333333333';
const M = '44444444-4444-4444-8444-444444444444';

function descriptor(name: string, fill: number): DescriptorInput {
  return {
    blobId: `6f1c2b7e-0d4a-4f53-9b8e-2a6d3c1e9f${fill.toString(16).padStart(2, '0')}`,
    key: new Uint8Array(32).fill(fill), noncePrefix: new Uint8Array(7).fill(fill), sha256: new Uint8Array(32).fill(fill),
    size: 5, paddedSize: 5, name, mime: 'application/pdf',
  };
}

const ENV_A = serializeEnvelope({ channelId: X, body: 'message A', attachments: [descriptor('a.pdf', 1)] });
const ENV_B = serializeEnvelope({ channelId: X, body: 'message B', attachments: [descriptor('b.pdf', 2)] });

/** Decode one frame or item as App.tsx does and build its `Message` fields. */
async function render(store: AttachmentStore, senderId: string, payload: string, decryptors: Decryptors): Promise<AttachmentBearer & { content: string }> {
  const decoded = await decodeMessage(
    { origin: ORIGIN, renderedChannelId: X, ownUserId: null },
    { channelId: X, messageId: M, senderId, payload },
    { decryptors, store, cache: { get: () => undefined, put: () => {} } },
  );
  return { id: M, channel_id: X, sender_id: senderId, ...decodedFields(decoded, false) };
}

const sk = (plaintext: string): Decryptors => ({ senderKeys: () => plaintext });

describe('the render binding (G2, REQ-8, REQ-51)', () => {
  it('a decoded message shows its own attachments, under its own sender', async () => {
    const store = new AttachmentStore();
    const a = await render(store, ALICE, 'AAAA', sk(ENV_A));
    const entry = attachmentEntryFor(a, ORIGIN, store);
    expect(entry?.attachments).toHaveLength(1);
    expect(entry?.senderId).toBe(ALICE);
    expect(a._attachmentRef).toBe(entry?.ref);
  });

  it('decoding the same message again keeps the entry and its ref, so both renders show it', async () => {
    const store = new AttachmentStore();
    const first = await render(store, ALICE, 'AAAA', sk(ENV_A));
    let events = 0;
    store.subscribe(() => events++);
    const again = await render(store, ALICE, 'AAAA', sk(ENV_A));
    expect(again._attachmentRef).toBe(first._attachmentRef);
    expect(events).toBe(0);
    expect(attachmentEntryFor(first, ORIGIN, store)).not.toBeNull();
    expect(attachmentEntryFor(again, ORIGIN, store)).not.toBeNull();
  });

  it('a later item under the same id with another sender, or unencrypted, shows nothing; the entry stays', async () => {
    const store = new AttachmentStore();
    await render(store, ALICE, 'AAAA', sk(ENV_A));
    for (const [sender, decryptors] of [[CAROL, {}], [ALICE, {}]] as const) {
      const replay = await render(store, sender, btoa(ENV_A), decryptors);
      expect(replay._attachmentCount).toBeUndefined();
      expect(attachmentEntryFor(replay, ORIGIN, store)).toBeNull();
    }
    expect(store.size).toBe(1);
  });

  it("another verified message re-labelled with this id replaces the entry: neither message shows the other's attachments", async () => {
    const store = new AttachmentStore();
    const a = await render(store, ALICE, 'AAAA', sk(ENV_A));
    // The relay withheld B and delivers it under A's id; A stays on screen (App drops the duplicate id).
    const b = await render(store, ALICE, 'BBBB', sk(ENV_B));
    expect(b._attachmentRef).not.toBe(a._attachmentRef);
    expect(attachmentEntryFor(a, ORIGIN, store)).toBeNull();
    const shown = attachmentEntryFor(b, ORIGIN, store);
    expect(shown?.attachments[0]).toMatchObject({ usable: true, descriptor: { name: 'b.pdf' } });
  });

  it('a count without a ref, a ref under another sender, a placeholder or a pending send shows nothing', async () => {
    const store = new AttachmentStore();
    const a = await render(store, ALICE, 'AAAA', sk(ENV_A));
    for (const msg of [
      { ...a, _attachmentRef: undefined },
      { ...a, sender_id: CAROL },
      { ...a, _attachmentCount: 2 },
      { ...a, _placeholder: 'wrong_conversation' as const },
      { ...a, _pendingId: 'temp_1' },
      { ...a, channel_id: '0b6e5a1c-3d2f-4e8a-9c7b-1a2b3c4d5e6f' },
    ]) {
      expect(attachmentEntryFor(msg, ORIGIN, store)).toBeNull();
    }
    expect(attachmentEntryFor(a, 'https://other.example', store)).toBeNull();
  });

  it('the Files panel lists only what the loaded messages show', async () => {
    const store = new AttachmentStore();
    const a = await render(store, ALICE, 'AAAA', sk(ENV_A));
    expect(shownChannelAttachments([a], ORIGIN, X, store)).toHaveLength(1);
    // After the channel re-renders with a forged item under the same id, the panel is empty.
    const replay = await render(store, CAROL, btoa(ENV_A), {});
    expect(shownChannelAttachments([replay], ORIGIN, X, store)).toEqual([]);
    // Nothing loaded: nothing listed, although the store still holds the entry.
    expect(shownChannelAttachments([], ORIGIN, X, store)).toEqual([]);
    expect(store.size).toBe(1);
  });
});
