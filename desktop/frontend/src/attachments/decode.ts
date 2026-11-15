/**
 * @module attachments/decode
 * The decode function of SPEC-02 (REQ-8, REQ-50, REQ-51, REQ-53): the single
 * client function that turns a live frame, a history item or a cache record
 * into displayable content, and the only code that creates attachment state.
 *
 * Attachment state (attachment-store entries and `dr` cache records) comes
 * only from a content envelope that names the rendered channel, found in
 *   (a) plaintext from a successful Double Ratchet decryption with the
 *       sender's session, or a Sender Keys decryption with the sender key held
 *       for that sender in that channel; or
 *   (b) a cache record whose origin, channel, sender, message id and wire
 *       hash equal those of the frame or item.
 * Legacy channel-key plaintext, raw relay payloads, plain-string or
 * mismatched cache entries, edits and edited history items never create it.
 *
 * The decode function takes no `keyPair` or `encryptionEnabled` argument: the
 * Double Ratchet, Sender Keys and the cache work without them (REQ-8, D26).
 * Every plaintext is classified (`e2ee/plaintext.ts`) before anything else
 * happens to it, and the display path discards what it does not accept
 * (REQ-53). It never logs a plaintext, a descriptor or an error derived from
 * either.
 *
 * Validated descriptors have the branded type `VerifiedDescriptor`. The only
 * code that creates one, `mintAttachmentSet`, is private to this module
 * (REQ-51).
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { acceptsOn, classifyPlaintext } from '../e2ee/plaintext';
import { decodeWireBase64, encodeBase64 } from './base64';
import {
  makeCacheRecord,
  readCacheValue,
  readEnvelope,
  type CacheRecordSource,
  type DescriptorFields,
  type DescriptorSlot,
  type PlaintextCacheRecord,
} from './envelope';
import type { AttachmentEntry, AttachmentKey, AttachmentStore } from './store';

// ---------------------------------------------------------------------------
// Branded descriptors (constructor private to this module)
// ---------------------------------------------------------------------------

declare const verifiedBrand: unique symbol;

/** A descriptor that passed §6.2.2 and came from plaintext REQ-8 trusts. */
export type VerifiedDescriptor = DescriptorFields & { readonly [verifiedBrand]: true };

/** One attachment of a decoded message, in envelope order. */
export type VerifiedAttachment =
  | { readonly usable: true; readonly descriptor: VerifiedDescriptor }
  /** Shown as "Unsupported attachment — update Accord", never downloaded (REQ-9). */
  | { readonly usable: false };

/** The attachments of one message, as only the decode function can build them. */
export interface VerifiedAttachmentSet {
  readonly [verifiedBrand]: true;
  readonly key: AttachmentKey;
  readonly senderId: string;
  readonly attachments: readonly VerifiedAttachment[];
}

const minted = new WeakSet<object>();

function mintAttachmentSet(key: AttachmentKey, senderId: string, slots: readonly DescriptorSlot[]): VerifiedAttachmentSet {
  const attachments = slots.map((slot): VerifiedAttachment => {
    if (!slot.usable) return Object.freeze({ usable: false as const });
    const d = slot.descriptor;
    const descriptor = Object.freeze({
      blobId: d.blobId,
      scheme: d.scheme,
      key: d.key.slice(),
      noncePrefix: d.noncePrefix.slice(),
      sha256: d.sha256.slice(),
      size: d.size,
      paddedSize: d.paddedSize,
      name: d.name,
      mime: d.mime,
    }) as unknown as VerifiedDescriptor;
    minted.add(descriptor);
    return Object.freeze({ usable: true as const, descriptor });
  });
  const set = Object.freeze({
    key: Object.freeze({ origin: key.origin, channelId: key.channelId, messageId: key.messageId }),
    senderId,
    attachments: Object.freeze(attachments),
  }) as unknown as VerifiedAttachmentSet;
  minted.add(set);
  return set;
}

/** True only for attachment sets built by the decode function. */
export function isVerifiedAttachmentSet(x: unknown): x is VerifiedAttachmentSet {
  return typeof x === 'object' && x !== null && minted.has(x);
}

/** True only for descriptors built by the decode function. */
export function isVerifiedDescriptor(x: unknown): x is VerifiedDescriptor {
  return typeof x === 'object' && x !== null && minted.has(x);
}

// ---------------------------------------------------------------------------
// Inputs and outputs
// ---------------------------------------------------------------------------

export interface DecodeContext {
  /** Relay origin (`relayOrigin(apiBaseUrl)`). */
  readonly origin: string;
  /** The conversation being rendered: the frame's channel, or the channel whose history was requested. */
  readonly renderedChannelId: string;
  /** The user's own id, or null when unknown. */
  readonly ownUserId: string | null;
}

/** A live `channel_message` frame or a history item, as the relay sent it. */
export interface WireMessage {
  /** The channel id the frame or item itself carries. */
  readonly channelId: string;
  readonly messageId: string;
  /** For live frames `from`, for history items `sender_id`. */
  readonly senderId: string;
  /** `encrypted_data` (live) or `encrypted_payload` (history), base64. */
  readonly payload: string;
  /** History items: `edited_at`; null or absent when never edited. */
  readonly editedAt?: number | null;
}

type MaybePromise<T> = T | Promise<T>;

/**
 * Decryption steps supplied by the caller. Each returns the plaintext, or
 * null when it does not apply or fails; a throw counts as null. None of them
 * may be gated on the legacy `keyPair` or `encryptionEnabled` (REQ-8).
 */
export interface Decryptors {
  /** Double Ratchet with the sender's session. */
  readonly doubleRatchet?: (senderId: string, payload: string) => MaybePromise<string | null>;
  /** Sender Keys with the key held for `senderId` in `channelId`. */
  readonly senderKeys?: (channelId: string, senderId: string, payload: string) => MaybePromise<string | null>;
  /** The legacy channel-key opt-in (text only, never trusted). */
  readonly legacyChannelKey?: (channelId: string, payload: string) => MaybePromise<string | null>;
}

/** The own-message cache (`ownMessagesRef`), seen as raw values. */
export interface PlaintextCacheAccess {
  get(messageId: string): unknown;
  put(record: PlaintextCacheRecord): void;
}

export interface DecodeDeps {
  readonly decryptors: Decryptors;
  readonly cache: PlaintextCacheAccess;
  readonly store: AttachmentStore;
}

export type Placeholder =
  | 'invalid_format'
  | 'newer_version'
  | 'wrong_conversation'
  | 'edited_unverified'
  | 'other_session';

/** User-visible placeholder texts (SPEC-02 §8.2). */
export const PLACEHOLDER_TEXT: Readonly<Record<Placeholder, string>> = Object.freeze({
  invalid_format: 'Invalid message format',
  newer_version: 'This message requires a newer version of Accord',
  wrong_conversation: 'Message not verified for this conversation',
  edited_unverified: 'Edited message could not be verified',
  other_session: 'Sent from another session; content unavailable',
});

/** Warning shown with the body of an untrusted envelope that carried descriptors (§8.2). */
export const ATTACHMENTS_IGNORED_TEXT = 'Attachments ignored: message not end-to-end verified';

/** Where the displayed plaintext came from. */
export type PlaintextSource =
  | 'dr' // Double Ratchet decryption
  | 'sk' // Sender Keys decryption
  | 'cache' // matching cache record (REQ-8 (b))
  | 'legacy_cache' // plain-string, mismatched or malformed cache entry
  | 'legacy_key' // legacy channel key
  | 'raw' // undecryptable relay payload
  | 'none';

export interface DecodedMessage {
  /**
   * `content`: show `body`. `placeholder`: show only `PLACEHOLDER_TEXT[placeholder]`.
   * `hidden`: render nothing at all; the plaintext was not for a display path (REQ-53).
   */
  readonly display: 'content' | 'placeholder' | 'hidden';
  /** Text for `Message.content`. Never holds a descriptor (REQ-11). */
  readonly body: string;
  readonly placeholder: Placeholder | null;
  /** True only for plaintext from REQ-8 (a) or (b). */
  readonly verified: boolean;
  readonly source: PlaintextSource;
  /** For `cache`: how the cached plaintext was obtained. */
  readonly cacheSource: CacheRecordSource | null;
  /** Attachments put in the store for this message (usable and unusable). */
  readonly attachmentCount: number;
  /**
   * The `ref` of the store entry this decode produced, or null. A view shows
   * attachments only for the `Message` that carries this ref (REQ-8, REQ-51;
   * `attachments/render.ts`).
   */
  readonly attachmentRef: number | null;
  /** An untrusted envelope carried descriptors that were ignored (`ATTACHMENTS_IGNORED_TEXT`). */
  readonly attachmentsIgnored: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Base64 of SHA-256 over the base64-decoded wire payload; null if not base64. */
export function wireSha256(payload: string): string | null {
  const bytes = decodeWireBase64(payload);
  return bytes === null ? null : encodeBase64(sha256(bytes));
}

function lower(s: string): string {
  return s.toLowerCase();
}

async function attempt<A extends unknown[]>(fn: ((...args: A) => MaybePromise<string | null>) | undefined, ...args: A): Promise<string | null> {
  if (!fn) return null;
  try {
    const out = await fn(...args);
    return typeof out === 'string' ? out : null;
  } catch {
    return null;
  }
}

function cacheGet(cache: PlaintextCacheAccess, id: string): unknown {
  try {
    return cache.get(id);
  } catch {
    return undefined;
  }
}

/**
 * What an undecryptable payload displays as. Its base64 decoding is used only
 * when that is UTF-8 text a typed-plaintext rule applies to (an envelope, so
 * REQ-8 can refuse its attachments, or a control payload, which is hidden);
 * otherwise the payload is shown as the relay sent it, as today.
 */
function rawText(payload: string): string {
  const bytes = decodeWireBase64(payload);
  if (bytes === null) return payload;
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return payload;
  }
  return classifyPlaintext(text).class === 'legacy_text' ? payload : text;
}

const HIDDEN: DecodedMessage = Object.freeze({
  display: 'hidden', body: '', placeholder: null, verified: false, source: 'none',
  cacheSource: null, attachmentCount: 0, attachmentRef: null, attachmentsIgnored: false,
});

interface Provenance {
  readonly verified: boolean;
  readonly source: PlaintextSource;
  readonly cacheSource: CacheRecordSource | null;
  /** Write a `dr` cache record (REQ-19) when the plaintext is displayable and bound. */
  readonly writeDrRecord: boolean;
}

const untrusted = (source: PlaintextSource): Provenance => ({ verified: false, source, cacheSource: null, writeDrRecord: false });

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/**
 * Decode a live frame or a history item for the conversation `ctx` renders.
 *
 * Order: a cache record that matches the item exactly (REQ-8 (b)); Double
 * Ratchet; Sender Keys (REQ-8 (a)); then, untrusted and never creating
 * attachment state, any other cache entry (text display stays as today,
 * OD-46), the legacy channel key, and finally the other-session placeholder
 * for own messages or the raw payload for others.
 */
export async function decodeMessage(ctx: DecodeContext, item: WireMessage, deps: DecodeDeps): Promise<DecodedMessage> {
  const rendered = lower(ctx.renderedChannelId);
  const wireHash = wireSha256(item.payload);

  const cached = readCacheValue(cacheGet(deps.cache, item.messageId), item.messageId);
  if (cached.kind === 'record') {
    const r = cached.record;
    if (wireHash !== null
      && r.origin === ctx.origin
      && r.channel_id === rendered
      && r.channel_id === lower(item.channelId)
      && r.sender_id === lower(item.senderId)
      && r.message_id === item.messageId
      && r.wire_sha256 === wireHash) {
      return present(ctx, item, r.plaintext, { verified: true, source: 'cache', cacheSource: r.source, writeDrRecord: false }, wireHash, deps);
    }
  }

  const dr = await attempt(deps.decryptors.doubleRatchet, item.senderId, item.payload);
  if (dr !== null) {
    return present(ctx, item, dr, { verified: true, source: 'dr', cacheSource: null, writeDrRecord: true }, wireHash, deps);
  }
  const sk = await attempt(deps.decryptors.senderKeys, rendered, item.senderId, item.payload);
  if (sk !== null) {
    // Peer channel plaintext is not cached before roadmap P0 item 7 (OD-45).
    return present(ctx, item, sk, { verified: true, source: 'sk', cacheSource: null, writeDrRecord: false }, wireHash, deps);
  }

  if (cached.kind === 'record') return present(ctx, item, cached.record.plaintext, untrusted('legacy_cache'), wireHash, deps);
  if (cached.kind === 'legacy' && cached.text !== null) return present(ctx, item, cached.text, untrusted('legacy_cache'), wireHash, deps);

  const legacy = await attempt(deps.decryptors.legacyChannelKey, rendered, item.payload);
  if (legacy !== null) return present(ctx, item, legacy, untrusted('legacy_key'), wireHash, deps);

  if (ctx.ownUserId !== null && lower(item.senderId) === lower(ctx.ownUserId)) {
    return placeholder('other_session', untrusted('none'));
  }
  return present(ctx, item, rawText(item.payload), untrusted('raw'), wireHash, deps);
}

function placeholder(p: Placeholder, prov: Provenance): DecodedMessage {
  return {
    display: 'placeholder', body: '', placeholder: p, verified: prov.verified, source: prov.source,
    cacheSource: prov.cacheSource, attachmentCount: 0, attachmentRef: null, attachmentsIgnored: false,
  };
}

function content(body: string, prov: Provenance, attachmentsIgnored: boolean, stored: AttachmentEntry | null = null): DecodedMessage {
  return {
    display: 'content', body, placeholder: null, verified: prov.verified, source: prov.source,
    cacheSource: prov.cacheSource, attachmentCount: stored ? stored.attachments.length : 0,
    attachmentRef: stored ? stored.ref : null, attachmentsIgnored,
  };
}

function writeDrRecord(ctx: DecodeContext, item: WireMessage, plaintext: string, wireHash: string | null, cache: PlaintextCacheAccess): void {
  if (wireHash === null) return;
  let record: PlaintextCacheRecord;
  try {
    record = makeCacheRecord({
      origin: ctx.origin,
      channel_id: lower(ctx.renderedChannelId),
      sender_id: lower(item.senderId),
      message_id: item.messageId,
      wire_sha256: wireHash,
      source: 'dr',
      plaintext,
    });
  } catch {
    return; // ids that are not canonical UUIDs, or no usable origin: no record
  }
  try {
    cache.put(record);
  } catch {
    // Persisting is the cache's concern; never surface plaintext in errors.
  }
}

function present(
  ctx: DecodeContext,
  item: WireMessage,
  plaintext: string,
  prov: Provenance,
  wireHash: string | null,
  deps: DecodeDeps,
): DecodedMessage {
  const rendered = lower(ctx.renderedChannelId);
  const bound = lower(item.channelId) === rendered;
  const edited = item.editedAt !== undefined && item.editedAt !== null;

  // REQ-53: classify first. Control payloads, legacy key JSON and anything
  // else the display path does not accept are discarded silently.
  const c = classifyPlaintext(plaintext);
  if (!acceptsOn('display', c)) return HIDDEN;

  if (c.class === 'legacy_text') {
    if (prov.writeDrRecord && bound && !edited) writeDrRecord(ctx, item, plaintext, wireHash, deps.cache);
    return content(c.text, prov, false);
  }
  if (c.class !== 'envelope') return HIDDEN;

  const read = readEnvelope(c);
  if (read.status === 'invalid') return placeholder('invalid_format', prov);
  if (read.status === 'newer_version') return placeholder('newer_version', prov);
  const env = read.envelope;

  // REQ-8: an envelope that names another conversation shows nothing.
  if (env.channelId !== rendered) return placeholder('wrong_conversation', prov);
  // REQ-50 rule 5.
  if (edited && env.hasAttachmentsMember) return placeholder('edited_unverified', prov);

  const descriptors = env.attachments.length;
  if (prov.verified && bound && !edited) {
    if (prov.writeDrRecord) writeDrRecord(ctx, item, plaintext, wireHash, deps.cache);
    const stored = descriptors > 0
      ? deps.store.put(mintAttachmentSet(
        { origin: ctx.origin, channelId: rendered, messageId: item.messageId },
        lower(item.senderId),
        env.attachments,
      ))
      : null;
    return content(env.body, prov, false, stored);
  }
  return content(env.body, prov, descriptors > 0);
}

// ---------------------------------------------------------------------------
// Edits (REQ-50)
// ---------------------------------------------------------------------------

/** The locally known message an edit targets. */
export interface EditTarget {
  readonly messageId: string;
  readonly channelId: string;
  /** The sender the target message is attributed to. */
  readonly senderId: string;
}

/** A `message_edit` frame. `senderId` MUST come from the event's `sender_id` (rule 4). */
export interface WireEdit {
  readonly channelId: string;
  readonly messageId: string;
  readonly senderId: string;
  readonly payload: string;
}

export type EditDecision =
  | { readonly action: 'drop' }
  | { readonly action: 'apply'; readonly body: string; readonly verified: boolean; readonly source: PlaintextSource };

const DROP: EditDecision = Object.freeze({ action: 'drop' });

/**
 * Decide what a `message_edit` frame may change (REQ-50). An edit never
 * creates, replaces or removes attachment state. It is dropped when its
 * target has attachment state (rule 1), when its sender differs from the
 * target's (rule 4), when the display path does not accept its plaintext
 * (REQ-53), and when its plaintext is a content envelope that is anything but
 * a valid `v` 1 envelope without an `attachments` member for the target's
 * channel (rule 2). The REQ-10 escape shows its body (rule 3); legacy text
 * replaces the body as today.
 */
export async function decodeEdit(
  ctx: DecodeContext,
  edit: WireEdit,
  target: EditTarget,
  deps: { readonly decryptors: Decryptors; readonly store: AttachmentStore },
): Promise<EditDecision> {
  const channel = lower(target.channelId);
  if (edit.messageId !== target.messageId) return DROP;
  if (lower(edit.channelId) !== channel) return DROP;
  if (lower(edit.senderId) !== lower(target.senderId)) return DROP; // rule 4
  if (deps.store.has({ origin: ctx.origin, channelId: channel, messageId: target.messageId })) return DROP; // rule 1

  let plaintext: string | null;
  let source: PlaintextSource;
  let verified = false;
  if ((plaintext = await attempt(deps.decryptors.doubleRatchet, edit.senderId, edit.payload)) !== null) {
    source = 'dr';
    verified = true;
  } else if ((plaintext = await attempt(deps.decryptors.senderKeys, channel, edit.senderId, edit.payload)) !== null) {
    source = 'sk';
    verified = true;
  } else if ((plaintext = await attempt(deps.decryptors.legacyChannelKey, channel, edit.payload)) !== null) {
    source = 'legacy_key';
  } else {
    plaintext = rawText(edit.payload);
    source = 'raw';
  }

  const c = classifyPlaintext(plaintext);
  if (!acceptsOn('display', c)) return DROP;
  if (c.class === 'legacy_text') return { action: 'apply', body: c.text, verified, source };
  if (c.class !== 'envelope') return DROP;
  const read = readEnvelope(c);
  // Invalid and newer envelopes may carry attachments that cannot be seen: drop (rule 2).
  if (read.status !== 'valid') return DROP;
  if (read.envelope.hasAttachmentsMember) return DROP; // rule 2
  if (read.envelope.channelId !== channel) return DROP; // REQ-8 binding
  return { action: 'apply', body: read.envelope.body, verified, source }; // rule 3
}
