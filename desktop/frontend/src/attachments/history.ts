/**
 * @module attachments/history
 * How one relay history item becomes the decoded fields of a `Message`
 * (SPEC-02 REQ-8, REQ-50, REQ-51, REQ-53). App.tsx's history loader and the
 * two-client tests both call `decodeHistoryItem`, so the tests exercise the
 * decryptor choice App really makes: when roadmap P0 item 7 adds a Double
 * Ratchet branch or a peer cache here, RG-C164 (d)'s expected failures flip.
 */

import { relayMessageFields, type RelayMessageFields } from '../relayMessage';
import type { Message } from '../types';
import type { DecodedMessage, WireMessage } from './decode';
import { decodedFields } from './messageFields';

/**
 * The decryptors history uses. There is no Double Ratchet branch: DR message
 * keys are single-use, and DR plaintext comes from the plaintext cache
 * (C022; roadmap P0 item 7 changes this). Sender Keys are tried, but a
 * message key is consumed by its first decryption, so another member's
 * channel message decrypts in history only if it was not shown live (C023).
 */
export const HISTORY_DECRYPTION: Readonly<{ doubleRatchet: boolean }> = Object.freeze({ doubleRatchet: false });

/** A history item's decode input, read from relay JSON with checked types. */
export interface HistoryWireItem extends WireMessage {
  /** `created_at` in seconds, 0 when absent. */
  readonly createdAt: number;
}

type Obj = Record<string, unknown>;

/** Read the decode input of a history item; members of the wrong type become empty. */
export function historyWireItem(raw: unknown): HistoryWireItem {
  const m: Obj = typeof raw === 'object' && raw !== null && !Array.isArray(raw) ? (raw as Obj) : {};
  const id = typeof m.id === 'string' ? m.id : typeof m.id === 'number' ? String(m.id) : '';
  return {
    messageId: id,
    // An item whose own channel_id differs from the requested channel gets no
    // attachment state (REQ-8); the decode function compares the two.
    channelId: typeof m.channel_id === 'string' ? m.channel_id : '',
    senderId: typeof m.sender_id === 'string' ? m.sender_id : '',
    payload: typeof m.encrypted_payload === 'string' ? m.encrypted_payload : '',
    editedAt: typeof m.edited_at === 'number' ? m.edited_at : null,
    createdAt: typeof m.created_at === 'number' ? m.created_at : 0,
  };
}

/** Decodes one item for the conversation `renderedChannelId` with the given decryptor choice. */
export type HistoryDecode = (item: WireMessage, renderedChannelId: string, opts: { doubleRatchet: boolean }) => Promise<DecodedMessage>;

/** The `Message` fields a history item decides: relay fields copied explicitly, and the decoded ones. */
export type HistoryMessageFields = RelayMessageFields & ReturnType<typeof decodedFields> & Pick<Message, 'channel_id' | 'sender_id'>;

/**
 * Decode one item of `channelId`'s history. Returns null when the display
 * path does not accept its plaintext (REQ-53). The relay object is copied
 * through an explicit field list and never spread (REQ-51); `channel_id` is
 * the requested channel.
 */
export async function decodeHistoryItem(raw: unknown, channelId: string, isDm: boolean, decode: HistoryDecode): Promise<HistoryMessageFields | null> {
  const item = historyWireItem(raw);
  const decoded = await decode(
    { channelId: item.channelId, messageId: item.messageId, senderId: item.senderId, payload: item.payload, editedAt: item.editedAt },
    channelId,
    HISTORY_DECRYPTION,
  );
  if (decoded.display === 'hidden') return null;
  return {
    ...relayMessageFields(raw),
    ...decodedFields(decoded, isDm),
    channel_id: channelId,
    sender_id: item.senderId || undefined,
  };
}
