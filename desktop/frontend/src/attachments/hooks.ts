/**
 * React bindings for the attachment store and the attachment views. Views
 * read attachment state only through these; they never write the store
 * (only the decode function does, REQ-51), and they see an entry only for the
 * `Message` whose own decode produced it (`attachments/render.ts`).
 */

import { useEffect, useState, useSyncExternalStore } from 'react';
import { attachmentStore, type AttachmentEntry, type AttachmentKey, type AttachmentStore } from './store';
import { attachmentEntryFor, shownChannelAttachments, type AttachmentBearer } from './render';
import { attachmentViews, type AttachmentLoadState, type AttachmentViews } from './view';

/** Re-render whenever the store changes. */
function useStoreTick(store: AttachmentStore): void {
  const [, setTick] = useState(0);
  useEffect(() => store.subscribe(() => setTick(t => t + 1)), [store]);
}

/** The attachments one rendered message may show, if any. */
export function useShownAttachments(msg: AttachmentBearer, origin: string, store: AttachmentStore = attachmentStore): AttachmentEntry | null {
  useStoreTick(store);
  return attachmentEntryFor(msg, origin, store);
}

/** The attachments the loaded messages of a channel may show (Files panel, REQ-26). */
export function useShownChannelAttachments(
  messages: readonly AttachmentBearer[],
  origin: string,
  channelId: string | null,
  store: AttachmentStore = attachmentStore,
): AttachmentEntry[] {
  useStoreTick(store);
  return channelId ? shownChannelAttachments(messages, origin, channelId, store) : [];
}

/** The download state of one attachment. */
export function useAttachmentState(key: AttachmentKey, blobId: string, views: AttachmentViews = attachmentViews): AttachmentLoadState {
  return useSyncExternalStore(
    l => views.subscribe(l),
    () => views.get(key, blobId),
    () => views.get(key, blobId),
  );
}
