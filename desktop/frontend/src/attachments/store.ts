/**
 * @module attachments/store
 * The attachment store of SPEC-02 REQ-51: validated descriptors, keyed by
 * relay origin, channel id and message id.
 *
 * Only the decode function writes it: `put` accepts only a
 * `VerifiedAttachmentSet`, whose constructor `attachments/decode.ts` keeps
 * private, and checks that brand again at run time. Views read from it;
 * `Message` objects never carry descriptors. Removal (REQ-24) is open to the
 * deletion, purge and expiry handlers.
 *
 * The store lives in memory only. It never persists or logs descriptors
 * (REQ-11); the encrypted plaintext cache is what survives a reload.
 */

import { isVerifiedAttachmentSet, type VerifiedAttachment, type VerifiedAttachmentSet } from './decode';

export interface AttachmentKey {
  readonly origin: string;
  readonly channelId: string;
  readonly messageId: string;
}

export interface AttachmentEntry {
  readonly key: AttachmentKey;
  /**
   * Opaque identity of this entry. The decode that stored it hands it to its
   * `Message` (`_attachmentRef`), and views show the entry only for that
   * `Message` (`attachments/render.ts`): an entry a later decode stored under
   * the same key never appears under an earlier message's body or sender.
   */
  readonly ref: number;
  /** The sender the authenticated plaintext was attributed to. */
  readonly senderId: string;
  /** One element per descriptor, in envelope order; unusable ones included (REQ-9). */
  readonly attachments: readonly VerifiedAttachment[];
}

export type StoreEvent =
  | { readonly type: 'put'; readonly entry: AttachmentEntry }
  | { readonly type: 'removed'; readonly entry: AttachmentEntry }
  | { readonly type: 'cleared' };

export type StoreListener = (event: StoreEvent) => void;

function keyString(k: AttachmentKey): string {
  return JSON.stringify([k.origin, k.channelId, k.messageId]);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function sameAttachment(a: VerifiedAttachment, b: VerifiedAttachment): boolean {
  if (!a.usable || !b.usable) return a.usable === b.usable;
  const x = a.descriptor;
  const y = b.descriptor;
  return x.blobId === y.blobId && x.scheme === y.scheme && x.size === y.size && x.paddedSize === y.paddedSize
    && x.name === y.name && x.mime === y.mime
    && sameBytes(x.key, y.key) && sameBytes(x.noncePrefix, y.noncePrefix) && sameBytes(x.sha256, y.sha256);
}

/** Same sender and the same descriptors in the same order. */
function sameContent(e: AttachmentEntry, senderId: string, attachments: readonly VerifiedAttachment[]): boolean {
  return e.senderId === senderId && e.attachments.length === attachments.length
    && e.attachments.every((a, i) => sameAttachment(a, attachments[i]));
}

/**
 * Entry refs are unique for the life of the page. The counter starts at a
 * random point so that a ref copied out of this page (a bookmark, a test
 * fixture) does not name an entry of a later page by coincidence.
 */
let nextRef = (globalThis.crypto?.getRandomValues?.(new Uint32Array(1))[0] ?? 0) * 1024 + 1;

export class AttachmentStore {
  private readonly entries = new Map<string, AttachmentEntry>();
  private readonly listeners = new Set<StoreListener>();

  /**
   * Store the attachments of one message and return the stored entry. Only
   * the decode function holds a `VerifiedAttachmentSet`; anything else is
   * refused.
   *
   * Decoding the same message again (a history reload, a repeated frame)
   * yields the same sender and descriptors and keeps the existing entry, with
   * its `ref` and download state. Different content under the same key
   * replaces the entry: the old one is removed first (its URLs are revoked)
   * and the new one gets a new `ref`, so no `Message` decoded earlier shows it.
   */
  put(set: VerifiedAttachmentSet): AttachmentEntry {
    if (!isVerifiedAttachmentSet(set)) throw new TypeError('attachment store accepts only decoded attachment sets');
    const k = keyString(set.key);
    const existing = this.entries.get(k);
    if (existing && sameContent(existing, set.senderId, set.attachments)) return existing;
    if (existing) {
      this.entries.delete(k);
      this.emit({ type: 'removed', entry: existing });
    }
    const entry: AttachmentEntry = Object.freeze({ key: set.key, ref: nextRef++, senderId: set.senderId, attachments: set.attachments });
    this.entries.set(k, entry);
    this.emit({ type: 'put', entry });
    return entry;
  }

  get(key: AttachmentKey): AttachmentEntry | undefined {
    return this.entries.get(keyString(key));
  }

  has(key: AttachmentKey): boolean {
    return this.entries.has(keyString(key));
  }

  /** Drop one message's entry (REQ-24). Returns it so views can revoke URLs. */
  remove(key: AttachmentKey): AttachmentEntry | undefined {
    const k = keyString(key);
    const entry = this.entries.get(k);
    if (!entry) return undefined;
    this.entries.delete(k);
    this.emit({ type: 'removed', entry });
    return entry;
  }

  /** Drop a message's entry whatever channel it was stored under (REQ-24). */
  removeMessage(origin: string, messageId: string): AttachmentEntry[] {
    const removed: AttachmentEntry[] = [];
    for (const [k, entry] of this.entries) {
      if (entry.key.origin === origin && entry.key.messageId === messageId) {
        this.entries.delete(k);
        removed.push(entry);
      }
    }
    for (const entry of removed) this.emit({ type: 'removed', entry });
    return removed;
  }

  /** Drop every entry of a channel (purge, channel deletion). */
  removeChannel(origin: string, channelId: string): AttachmentEntry[] {
    const removed: AttachmentEntry[] = [];
    for (const [k, entry] of this.entries) {
      if (entry.key.origin === origin && entry.key.channelId === channelId) {
        this.entries.delete(k);
        removed.push(entry);
      }
    }
    for (const entry of removed) this.emit({ type: 'removed', entry });
    return removed;
  }

  /** Every entry of a channel, for the Files panel (REQ-26). */
  listChannel(origin: string, channelId: string): AttachmentEntry[] {
    return [...this.entries.values()].filter(e => e.key.origin === origin && e.key.channelId === channelId);
  }

  get size(): number {
    return this.entries.size;
  }

  /** Drop everything (logout, wipe). */
  clear(): void {
    this.entries.clear();
    this.emit({ type: 'cleared' });
  }

  subscribe(listener: StoreListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(event: StoreEvent): void {
    for (const l of [...this.listeners]) {
      try {
        l(event);
      } catch {
        // A failing view must not break the store or other listeners.
      }
    }
  }
}

/** The application's attachment store. */
export const attachmentStore = new AttachmentStore();
