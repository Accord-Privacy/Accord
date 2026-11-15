/**
 * @module attachments/edit
 * The sender side of edits under SPEC-02 (REQ-18, REQ-48, OD-36, OD-48).
 *
 * - Edit is offered only for own, sent, node-channel messages without
 *   attachments: never in DMs until Double Ratchet edits exist (OD-48), never
 *   for a message that carries attachments (REQ-18, OD-36), and never for a
 *   placeholder.
 * - An edit is sealed with Sender Keys, or with the legacy opt-in for text,
 *   and never sent in plaintext (REQ-48). Text that could be taken for a typed
 *   payload goes in the REQ-10 escape envelope, which has no `attachments`
 *   member, so no edit can carry descriptors.
 */

import type { Message } from '../types';
import type { SealedPayload } from '../e2ee/sealed';
import { textPlaintextFor } from './envelope';
import type { ConversationSealer } from './send';

/** What the edit guard needs to know beyond the message itself. */
export interface EditFacts {
  /** The message's channel is a DM channel. */
  readonly isDm: boolean;
  /** The attachment store has an entry for the message. */
  readonly hasAttachmentState: boolean;
  /** The message is an own pending send with staged attachments. */
  readonly pendingWithAttachments: boolean;
}

type EditableMessage = Pick<Message, 'channel_id' | '_pendingId' | '_placeholder' | '_attachmentCount' | '_attachmentsIgnored'>;

/** Whether the message carries attachments, decoded, ignored or staged (REQ-18). */
export function carriesAttachments(msg: EditableMessage, facts: EditFacts): boolean {
  return (msg._attachmentCount ?? 0) > 0 || !!msg._attachmentsIgnored || facts.hasAttachmentState || facts.pendingWithAttachments;
}

/** Whether the Edit action is offered for an own message. */
export function canOfferEdit(msg: EditableMessage, facts: EditFacts): boolean {
  if (!msg.channel_id || msg._pendingId || msg._placeholder) return false;
  if (facts.isDm) return false;
  return !carriesAttachments(msg, facts);
}

export type EditRefusal = 'dm' | 'attachments' | 'not_editable' | 'too_long' | 'malformed' | 'e2ee_unavailable';

export const EDIT_REFUSAL_TEXT: Readonly<Record<EditRefusal, string>> = Object.freeze({
  dm: "Direct messages can't be edited yet",
  attachments: "Messages with attachments can't be edited",
  not_editable: "This message can't be edited",
  too_long: 'Message too long: shorten the text',
  malformed: 'Message contains invalid characters',
  e2ee_unavailable: 'Edit not saved: end-to-end encryption is unavailable for this channel',
});

export type SealedEdit =
  | { readonly ok: true; readonly sealed: SealedPayload; readonly plaintext: string }
  | { readonly ok: false; readonly reason: EditRefusal; readonly text: string };

function refuse(reason: EditRefusal): SealedEdit {
  return { ok: false, reason, text: EDIT_REFUSAL_TEXT[reason] };
}

/**
 * Build and seal the payload of an edit, or refuse it. Refusals send
 * nothing: the caller has no payload to send (REQ-18, REQ-48).
 */
export async function sealEdit(
  msg: EditableMessage,
  facts: EditFacts,
  newText: string,
  sealer: ConversationSealer,
): Promise<SealedEdit> {
  if (facts.isDm) return refuse('dm');
  if (carriesAttachments(msg, facts)) return refuse('attachments');
  if (!canOfferEdit(msg, facts) || !msg.channel_id) return refuse('not_editable');
  const channelId = msg.channel_id.toLowerCase();
  const text = textPlaintextFor(channelId, newText);
  if (!text.ok) return refuse(text.reason === 'too_long' ? 'too_long' : 'malformed');
  const conversation = { kind: 'channel' as const, channelId: msg.channel_id };
  try {
    // Sender Keys, bootstrapped if needed; else the legacy opt-in for text.
    await sealer.ready(conversation).catch(() => false);
    const sealed = await sealer.seal(conversation, text.plaintext, 'text');
    return { ok: true, sealed, plaintext: text.plaintext };
  } catch {
    return refuse('e2ee_unavailable');
  }
}

/** How many own edits wait for their echoes at most; the oldest go first. */
export const OWN_EDITS_MAX = 64;

/**
 * Own edits awaiting their echoes. Our own Sender Keys envelopes do not
 * decrypt for us, so an own `message_edit` echo shows the text we sealed only
 * when it names the message we edited and carries exactly the payload we
 * sealed for it (as REQ-49 pairs sends). A relay that replays the payload
 * against another own message matches nothing.
 */
export class OwnEditEchoes {
  private readonly pending = new Map<string, string>();

  private static key(messageId: string, wireSha256: string): string {
    return `${messageId}\n${wireSha256}`;
  }

  /** Remember the text sealed into `wireSha256` as an edit of `messageId`. */
  remember(messageId: string, wireSha256: string, text: string): void {
    const k = OwnEditEchoes.key(messageId, wireSha256);
    this.pending.delete(k);
    this.pending.set(k, text);
    while (this.pending.size > OWN_EDITS_MAX) {
      const oldest = this.pending.keys().next().value;
      if (oldest === undefined) break;
      this.pending.delete(oldest);
    }
  }

  /** The edit did not go out: no echo may show its text. */
  forget(messageId: string, wireSha256: string): void {
    this.pending.delete(OwnEditEchoes.key(messageId, wireSha256));
  }

  /** The text of the own edit of `messageId` with exactly this payload hash, once. */
  take(messageId: string, wireSha256: string): string | undefined {
    const k = OwnEditEchoes.key(messageId, wireSha256);
    const text = this.pending.get(k);
    if (text !== undefined) this.pending.delete(k);
    return text;
  }

  clear(): void {
    this.pending.clear();
  }
}
