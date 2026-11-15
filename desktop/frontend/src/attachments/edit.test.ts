// @vitest-environment node
/**
 * SPEC-02 T-18 (REQ-18, OD-36), the edit part of T-10 (REQ-10) and of T-48
 * (REQ-48), and OD-48: no Edit in DMs or on messages with attachments; edits
 * are sealed or not sent; an edit never carries an `attachments` member.
 */
import { describe, expect, it, vi } from 'vitest';
import { canOfferEdit, sealEdit, EDIT_REFUSAL_TEXT, OwnEditEchoes, OWN_EDITS_MAX, type EditFacts } from './edit';
import { createConversationSealer } from './sealer';
import { parseEnvelope } from './envelope';
import { decodeEdit } from './decode';
import { AttachmentStore } from './store';
import { SenderKeyStore, buildDistributionMessage, parseDistributionMessage, decryptChannelMessage } from '../e2ee';
import type { ConversationSealer } from './send';
import type { Message } from '../types';

const X = '7c9e6679-7425-40de-944b-e07fc1f90ae7';
const ME = '11111111-1111-4111-8111-111111111111';
const NONE: EditFacts = { isDm: false, hasAttachmentState: false, pendingWithAttachments: false };

const text = (over: Partial<Message> = {}): Message => ({ id: 'm1', author: 'me', content: 'old', timestamp: 0, channel_id: X, sender_id: ME, ...over });

function sealerWorld(withKey = true) {
  const mine = new SenderKeyStore();
  const peer = new SenderKeyStore();
  if (withKey) {
    const sk = mine.getOrCreateMyKey(X);
    peer.setPeerKey(X, ME, parseDistributionMessage(buildDistributionMessage(X, sk)).state);
  }
  const base = createConversationSealer({
    e2ee: () => null,
    senderKeys: () => mine,
    bootstrapSenderKey: () => false,
    fetchBundle: async () => undefined,
    persistSenderKeys: () => {},
    legacyText: () => null,
  });
  const sealer: ConversationSealer & { calls: number } = {
    calls: 0,
    ready: c => base.ready(c),
    seal: (c, p, k) => {
      sealer.calls++;
      return base.seal(c, p, k);
    },
  };
  const open = (wire: string) => decryptChannelMessage(peer, X, ME, wire);
  return { sealer, open };
}

describe('T-18: Edit is offered only for text messages in node channels', () => {
  it('no Edit for messages with attachments, decoded, ignored or staged', () => {
    expect(canOfferEdit(text(), NONE)).toBe(true);
    expect(canOfferEdit(text({ _attachmentCount: 2 }), NONE)).toBe(false);
    expect(canOfferEdit(text({ _attachmentsIgnored: true }), NONE)).toBe(false);
    expect(canOfferEdit(text(), { ...NONE, hasAttachmentState: true })).toBe(false);
    expect(canOfferEdit(text({ _pendingId: 'temp_1' }), { ...NONE, pendingWithAttachments: true })).toBe(false);
  });

  it('OD-48: no Edit in DMs; none on placeholders or unsent messages', () => {
    expect(canOfferEdit(text(), { ...NONE, isDm: true })).toBe(false);
    expect(canOfferEdit(text({ _placeholder: 'other_session' }), NONE)).toBe(false);
    expect(canOfferEdit(text({ _pendingId: 'temp_1' }), NONE)).toBe(false);
    expect(canOfferEdit(text({ channel_id: undefined }), NONE)).toBe(false);
  });

  it('saving an edit of a message with attachments seals and sends nothing', async () => {
    const { sealer } = sealerWorld();
    const r = await sealEdit(text({ _attachmentCount: 1 }), NONE, 'new caption', sealer);
    expect(r).toEqual({ ok: false, reason: 'attachments', text: "Messages with attachments can't be edited" });
    const r2 = await sealEdit(text(), { ...NONE, hasAttachmentState: true }, 'new caption', sealer);
    expect(r2.ok).toBe(false);
    expect(sealer.calls).toBe(0);
  });

  it('T-48: a DM edit has no Double Ratchet path, so nothing is sealed or sent', async () => {
    const { sealer } = sealerWorld();
    const r = await sealEdit(text(), { ...NONE, isDm: true }, 'edited', sealer);
    expect(r).toEqual({ ok: false, reason: 'dm', text: EDIT_REFUSAL_TEXT.dm });
    expect(sealer.calls).toBe(0);
  });

  it('T-48: a channel edit with no sender key and no opt-in is refused, never sent in plaintext', async () => {
    const { sealer } = sealerWorld(false);
    const r = await sealEdit(text(), NONE, 'edited', sealer);
    expect(r).toMatchObject({ ok: false, reason: 'e2ee_unavailable' });
  });

  it('an edit is sealed with Sender Keys', async () => {
    const { sealer, open } = sealerWorld();
    const r = await sealEdit(text(), NONE, 'hello', sealer);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.sealed.scheme).toBe('sk');
    expect(open(r.sealed.wire)).toBe('hello');
  });

  it('T-10: text that looks like an envelope is sent as the escape, never with an attachments member', async () => {
    const { sealer, open } = sealerWorld();
    const typed = '{"type":"accord.content","v":1,"attachments":[]}';
    const r = await sealEdit(text(), NONE, typed, sealer);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const plaintext = open(r.sealed.wire);
    const read = parseEnvelope(plaintext);
    expect(read?.status).toBe('valid');
    if (read?.status !== 'valid') return;
    expect(read.envelope.body).toBe(typed);
    expect(read.envelope.hasAttachmentsMember).toBe(false);
    expect(read.envelope.channelId).toBe(X);
    // Receivers show the literal text (REQ-50 rule 3).
    const decision = await decodeEdit(
      { origin: 'https://relay.example', renderedChannelId: X, ownUserId: null },
      { channelId: X, messageId: 'm1', senderId: ME, payload: r.sealed.wire },
      { messageId: 'm1', channelId: X, senderId: ME },
      { decryptors: { senderKeys: () => plaintext }, store: new AttachmentStore() },
    );
    expect(decision).toMatchObject({ action: 'apply', body: typed });
  });

  it('T-10: a control-payload lookalike is escaped too; plain text is sent as is', async () => {
    const { sealer, open } = sealerWorld();
    const lookalike = '\u001eaccord-call\u001e{"type":"call_hello","v":1}';
    const a = await sealEdit(text(), NONE, lookalike, sealer);
    expect(a.ok && parseEnvelope(open(a.sealed.wire))).toMatchObject({ status: 'valid', envelope: { body: lookalike } });
    const b = await sealEdit(text(), NONE, 'hello', sealer);
    expect(b.ok && b.plaintext).toBe('hello');
  });

  it('a too-long escape is refused before sealing', async () => {
    const { sealer } = sealerWorld();
    const spy = vi.spyOn(sealer, 'seal');
    const r = await sealEdit(text(), NONE, '{"type":"accord.content"' + 'x'.repeat(9000), sealer);
    expect(r).toMatchObject({ ok: false, reason: 'too_long' });
    expect(spy).not.toHaveBeenCalled();
  });
});

describe('own edit echoes pair by target and payload hash', () => {
  const H = 'hash-of-the-sealed-edit';

  it('an echo of the payload against another own message gets no text', () => {
    const echoes = new OwnEditEchoes();
    echoes.remember('m1', H, 'new text');
    expect(echoes.take('m2', H)).toBeUndefined();
    expect(echoes.take('m1', 'another-hash')).toBeUndefined();
    expect(echoes.take('m1', H)).toBe('new text');
    // Only the first matching echo shows it.
    expect(echoes.take('m1', H)).toBeUndefined();
  });

  it('a forgotten edit (not sent) never matches', () => {
    const echoes = new OwnEditEchoes();
    echoes.remember('m1', H, 'new text');
    echoes.forget('m1', H);
    expect(echoes.take('m1', H)).toBeUndefined();
  });

  it('keeps at most OWN_EDITS_MAX edits, dropping the oldest', () => {
    const echoes = new OwnEditEchoes();
    for (let i = 0; i <= OWN_EDITS_MAX; i++) echoes.remember(`m${i}`, H, `t${i}`);
    expect(echoes.take('m0', H)).toBeUndefined();
    expect(echoes.take(`m${OWN_EDITS_MAX}`, H)).toBe(`t${OWN_EDITS_MAX}`);
  });
});
