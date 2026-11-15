/**
 * @module attachments/render
 * Which attachments a rendered `Message` may show (SPEC-02 G2, REQ-8, REQ-51).
 *
 * The attachment store is keyed by relay origin, channel and message id, and
 * an entry outlives the `Message` whose decode produced it: it stays until the
 * message is deleted, purged or expires, or the user logs out. A relay can
 * later serve another item under the same id (another sender, an unencrypted
 * or undecryptable payload, a re-labelled ciphertext), and that decode leaves
 * the old entry in place or replaces it. So a view never shows "whatever the
 * store holds under this id": it shows an entry only for the `Message` whose
 * own decode produced exactly that entry, which means all of:
 *
 * - the message is neither a placeholder nor an own pending send;
 * - its decode stored attachments (`_attachmentCount` > 0) and handed it the
 *   entry's opaque `ref` (`_attachmentRef`);
 * - the entry under the message's key still has that `ref`, the same number
 *   of attachments, and the sender the message is attributed to.
 *
 * Every attachment view (the message's attachments and image grid, the Files
 * panel, the search filters `has:file` and `has:image`) goes through
 * `shownAttachmentEntry`. Pins, threads and search results are never decoded
 * (stage 1), carry no `_attachmentRef`, and so show no attachment UI.
 */

import type { Message } from '../types';
import { previewElementFor } from './sanitize';
import { attachmentStore, type AttachmentEntry, type AttachmentKey, type AttachmentStore } from './store';

/** The `Message` fields that decide whether it shows attachments. */
export type AttachmentBearer = Pick<
  Message,
  'id' | 'channel_id' | 'sender_id' | '_attachmentCount' | '_attachmentRef' | '_placeholder' | '_pendingId'
>;

/** The attachment-store key of a message, or null when it has no channel or id. */
export function attachmentKeyOf(msg: Pick<Message, 'id' | 'channel_id'>, origin: string): AttachmentKey | null {
  if (!msg.id || !msg.channel_id) return null;
  return { origin, channelId: msg.channel_id.toLowerCase(), messageId: msg.id };
}

/** `entry` if `msg`'s own decode produced it (see the module comment), else null. */
export function shownAttachmentEntry(msg: AttachmentBearer, entry: AttachmentEntry | undefined): AttachmentEntry | null {
  if (!entry) return null;
  if (msg._placeholder || msg._pendingId) return null;
  const count = msg._attachmentCount ?? 0;
  if (count <= 0 || msg._attachmentRef === undefined) return null;
  if (entry.ref !== msg._attachmentRef) return null;
  if (entry.attachments.length !== count) return null;
  if (!msg.sender_id || entry.senderId !== msg.sender_id.toLowerCase()) return null;
  if (!msg.channel_id || entry.key.channelId !== msg.channel_id.toLowerCase() || entry.key.messageId !== msg.id) return null;
  return entry;
}

/** The attachments `msg` may show, read from `store`. */
export function attachmentEntryFor(msg: AttachmentBearer, origin: string, store: AttachmentStore = attachmentStore): AttachmentEntry | null {
  const key = attachmentKeyOf(msg, origin);
  return key ? shownAttachmentEntry(msg, store.get(key)) : null;
}

/**
 * The attachments the loaded messages of one channel may show, in message
 * order (the Files panel, REQ-26). Other channels' messages are skipped.
 */
export function shownChannelAttachments(
  messages: readonly AttachmentBearer[],
  origin: string,
  channelId: string,
  store: AttachmentStore = attachmentStore,
): AttachmentEntry[] {
  const channel = channelId.toLowerCase();
  const out: AttachmentEntry[] = [];
  const seen = new Set<number>();
  for (const msg of messages) {
    if (!msg.channel_id || msg.channel_id.toLowerCase() !== channel) continue;
    const entry = attachmentEntryFor(msg, origin, store);
    if (entry && !seen.has(entry.ref)) {
      seen.add(entry.ref);
      out.push(entry);
    }
  }
  return out;
}

/** Counts of the attachments `msg` may show (search filters `has:file`, `has:image`). */
export function shownAttachmentSummary(
  msg: AttachmentBearer,
  origin: string,
  store: AttachmentStore = attachmentStore,
): { total: number; usable: number; images: number } {
  const entry = attachmentEntryFor(msg, origin, store);
  if (!entry) return { total: 0, usable: 0, images: 0 };
  let usable = 0;
  let images = 0;
  for (const a of entry.attachments) {
    if (!a.usable) continue;
    usable++;
    if (previewElementFor(a.descriptor.mime) === 'img') images++;
  }
  return { total: entry.attachments.length, usable, images };
}
