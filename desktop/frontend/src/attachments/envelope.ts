/**
 * @module attachments/envelope
 * Content envelope v1 and attachment descriptor v1 (SPEC-02 §6.2.1, §6.2.2),
 * their serialization, the REQ-10 escape, and the plaintext cache record v1
 * (§6.2.4).
 *
 * Classification and §6.2 rules 1 to 4 live in `e2ee/plaintext.ts`; this
 * module applies rules 5 and 6 to a classified `v` 1 envelope and copies the
 * known members into fresh objects. It never logs.
 */

import {
  classifyPlaintext,
  isWellFormedUtf16,
  needsEnvelopeEscape,
  StrictObject,
  utf8ByteLength,
  MAX_ENVELOPE_BYTES,
  type EnvelopeClassification,
  type EnvelopeFailure,
  type StrictValue,
} from '../e2ee/plaintext';
import { decodeCanonicalBase64, encodeBase64 } from './base64';
import {
  blobLength,
  CLIENT_MAX_BLOB_BYTES,
  KEY_SIZE,
  NONCE_PREFIX_SIZE,
  SCHEME,
  SHA256_SIZE,
} from './format';

export { MAX_ENVELOPE_BYTES } from '../e2ee/plaintext';
export const MAX_BODY_BYTES = 8_192;
export const MAX_NOTICE_BYTES = 256;
export const MAX_ATTACHMENTS_PER_MESSAGE = 10;
export const MAX_NAME_BYTES = 255;
export const MAX_MIME_BYTES = 255;
export const ENVELOPE_TYPE = 'accord.content';

/** The `notice` that clients older than C1 show instead of the JSON (§7.4). */
export const ATTACHMENT_NOTICE = 'This message has end-to-end encrypted attachments. Update Accord to view them.';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// RFC 6838 §4.2 restricted-name, lower case only, no parameters.
const MIME_PART = '[a-z0-9][a-z0-9!#$&\\-^_.+]{0,126}';
const MIME_RE = new RegExp(`^${MIME_PART}/${MIME_PART}$`);

/** A lowercase canonical UUID (8-4-4-4-12 hex digits, RFC 9562). */
export function isCanonicalUuid(s: unknown): s is string {
  return typeof s === 'string' && UUID_RE.test(s);
}

export function isValidMime(s: unknown): s is string {
  return typeof s === 'string' && s.length <= MAX_MIME_BYTES && MIME_RE.test(s);
}

// ---------------------------------------------------------------------------
// Reading (rules 5 and 6)
// ---------------------------------------------------------------------------

/** The members of a descriptor that passed §6.2.2, copied into a fresh object. */
export interface DescriptorFields {
  readonly blobId: string;
  readonly scheme: typeof SCHEME;
  readonly key: Uint8Array;
  readonly noncePrefix: Uint8Array;
  readonly sha256: Uint8Array;
  readonly size: number;
  readonly paddedSize: number;
  /** As sent; display code sanitizes it again (REQ-23). */
  readonly name: string;
  readonly mime: string;
}

/** One entry of `attachments`: usable, or shown as unusable and never downloaded (REQ-9). */
export type DescriptorSlot =
  | { readonly usable: true; readonly descriptor: DescriptorFields }
  | { readonly usable: false };

export interface EnvelopeV1 {
  readonly channelId: string;
  /** Absent `body` reads as the empty string. */
  readonly body: string;
  /** Whether the object has an `attachments` member at all (REQ-50 rules 2 and 5). */
  readonly hasAttachmentsMember: boolean;
  readonly attachments: readonly DescriptorSlot[];
}

export type EnvelopeRead =
  | { readonly status: 'valid'; readonly envelope: EnvelopeV1 }
  | { readonly status: 'invalid'; readonly reason: EnvelopeFailure | 'shape' }
  | { readonly status: 'newer_version' };

function isNonNegInt(v: StrictValue | undefined): v is number {
  return typeof v === 'number';
}

/** Apply §6.2.2 to one descriptor object. Null means "unusable attachment". */
export function readDescriptor(o: StrictObject): DescriptorFields | null {
  if (o.get('v') !== 1) return null;
  if (o.get('scheme') !== SCHEME) return null;
  const blobId = o.get('blob_id');
  if (!isCanonicalUuid(blobId)) return null;
  const keyB64 = o.get('key');
  const npB64 = o.get('nonce_prefix');
  const shaB64 = o.get('sha256');
  if (typeof keyB64 !== 'string' || typeof npB64 !== 'string' || typeof shaB64 !== 'string') return null;
  const key = decodeCanonicalBase64(keyB64, KEY_SIZE);
  const noncePrefix = decodeCanonicalBase64(npB64, NONCE_PREFIX_SIZE);
  const sha256 = decodeCanonicalBase64(shaB64, SHA256_SIZE);
  if (!key || !noncePrefix || !sha256) return null;
  const size = o.get('size');
  const paddedSize = o.get('padded_size');
  if (!isNonNegInt(size) || !isNonNegInt(paddedSize)) return null;
  if (size > paddedSize || blobLength(paddedSize) > CLIENT_MAX_BLOB_BYTES) return null; // REQ-3
  const name = o.get('name');
  if (typeof name !== 'string') return null;
  const nameBytes = utf8ByteLength(name);
  if (nameBytes < 1 || nameBytes > MAX_NAME_BYTES) return null;
  const mime = o.get('mime');
  if (!isValidMime(mime)) return null;
  return Object.freeze({ blobId, scheme: SCHEME, key, noncePrefix, sha256, size, paddedSize, name, mime });
}

/** Apply rules 5 and 6 and §6.2.1 to an envelope object whose `v` is 1. */
export function readEnvelopeV1(o: StrictObject): EnvelopeRead {
  const invalid: EnvelopeRead = { status: 'invalid', reason: 'shape' };
  if (o.get('type') !== ENVELOPE_TYPE || o.get('v') !== 1) return invalid;
  const channelId = o.get('channel_id');
  if (!isCanonicalUuid(channelId)) return invalid;
  if (o.has('notice')) {
    const notice = o.get('notice');
    if (typeof notice !== 'string' || utf8ByteLength(notice) > MAX_NOTICE_BYTES) return invalid;
  }
  let body = '';
  if (o.has('body')) {
    const b = o.get('body');
    if (typeof b !== 'string' || utf8ByteLength(b) > MAX_BODY_BYTES) return invalid;
    body = b;
  }
  const hasAttachmentsMember = o.has('attachments');
  const slots: DescriptorSlot[] = [];
  if (hasAttachmentsMember) {
    const list = o.get('attachments');
    if (!Array.isArray(list) || list.length > MAX_ATTACHMENTS_PER_MESSAGE) return invalid;
    const seen = new Set<string>();
    for (const item of list) {
      if (!(item instanceof StrictObject)) return invalid;
      const id = item.get('blob_id');
      if (typeof id === 'string') {
        if (seen.has(id)) return invalid;
        seen.add(id);
      }
    }
    for (const item of list as StrictObject[]) {
      const d = readDescriptor(item);
      slots.push(d ? Object.freeze({ usable: true as const, descriptor: d }) : Object.freeze({ usable: false as const }));
    }
  }
  return {
    status: 'valid',
    envelope: Object.freeze({ channelId, body, hasAttachmentsMember, attachments: Object.freeze(slots) }),
  };
}

/** Read a classified envelope (SPEC-02 §6.1 detection rules 2 and 3). */
export function readEnvelope(c: EnvelopeClassification): EnvelopeRead {
  if (c.status === 'invalid') return { status: 'invalid', reason: c.reason };
  if (c.status === 'newer_version') return { status: 'newer_version' };
  return readEnvelopeV1(c.object);
}

/** Classify a plaintext and, when it is a content envelope, read it. */
export function parseEnvelope(plaintext: string | Uint8Array): EnvelopeRead | null {
  const c = classifyPlaintext(plaintext);
  return c.class === 'envelope' ? readEnvelope(c) : null;
}

// ---------------------------------------------------------------------------
// Serialization (senders)
// ---------------------------------------------------------------------------

/** What a sender knows about one sealed and uploaded attachment. */
export interface DescriptorInput {
  readonly blobId: string;
  readonly key: Uint8Array;
  readonly noncePrefix: Uint8Array;
  readonly sha256: Uint8Array;
  readonly size: number;
  readonly paddedSize: number;
  /** Already sanitized under REQ-23. */
  readonly name: string;
  readonly mime: string;
}

function jsonString(s: string): string {
  if (!isWellFormedUtf16(s)) throw new RangeError('string contains a lone surrogate');
  return JSON.stringify(s);
}

/** Serialize one descriptor in the member order of §6.2.3, without whitespace. */
export function serializeDescriptor(d: DescriptorInput): string {
  if (!isCanonicalUuid(d.blobId)) throw new RangeError('blob_id must be a lowercase canonical UUID');
  if (d.key.length !== KEY_SIZE || d.noncePrefix.length !== NONCE_PREFIX_SIZE || d.sha256.length !== SHA256_SIZE) {
    throw new RangeError('bad key, nonce prefix or hash length');
  }
  if (!Number.isSafeInteger(d.size) || !Number.isSafeInteger(d.paddedSize) || d.size < 0 || d.size > d.paddedSize) {
    throw new RangeError('bad size');
  }
  if (!isValidMime(d.mime)) throw new RangeError('bad MIME type');
  const nameBytes = utf8ByteLength(d.name);
  if (nameBytes < 1 || nameBytes > MAX_NAME_BYTES) throw new RangeError('bad name length');
  return '{"v":1'
    + ',"blob_id":' + jsonString(d.blobId)
    + ',"scheme":' + jsonString(SCHEME)
    + ',"key":' + jsonString(encodeBase64(d.key))
    + ',"nonce_prefix":' + jsonString(encodeBase64(d.noncePrefix))
    + ',"sha256":' + jsonString(encodeBase64(d.sha256))
    + ',"size":' + String(d.size)
    + ',"padded_size":' + String(d.paddedSize)
    + ',"name":' + jsonString(d.name)
    + ',"mime":' + jsonString(d.mime)
    + '}';
}

export interface EnvelopeInput {
  readonly channelId: string;
  readonly body?: string;
  readonly attachments?: readonly DescriptorInput[];
}

/**
 * Serialize a content envelope: `type` first and no insignificant whitespace,
 * so the plaintext begins with the envelope prefix (REQ-10); `notice` right
 * after `v` when attachments are present (§6.2.1).
 */
export function serializeEnvelope(e: EnvelopeInput): string {
  if (!isCanonicalUuid(e.channelId)) throw new RangeError('channel_id must be a lowercase canonical UUID');
  const attachments = e.attachments ?? [];
  if (attachments.length > MAX_ATTACHMENTS_PER_MESSAGE) throw new RangeError('too many attachments');
  if (new Set(attachments.map(a => a.blobId)).size !== attachments.length) throw new RangeError('duplicate blob_id');
  let out = '{"type":"accord.content","v":1';
  if (attachments.length > 0) out += ',"notice":' + jsonString(ATTACHMENT_NOTICE);
  out += ',"channel_id":' + jsonString(e.channelId);
  if (e.body !== undefined && e.body !== '') out += ',"body":' + jsonString(e.body);
  if (attachments.length > 0) out += ',"attachments":[' + attachments.map(serializeDescriptor).join(',') + ']';
  return out + '}';
}

/** The REQ-10 escape envelope for user text. */
export function buildEscapeEnvelope(channelId: string, text: string): string {
  if (!isCanonicalUuid(channelId)) throw new RangeError('channel_id must be a lowercase canonical UUID');
  return '{"type":"accord.content","v":1,"channel_id":' + jsonString(channelId) + ',"body":' + jsonString(text) + '}';
}

export type TextPlaintext =
  | { readonly ok: true; readonly plaintext: string; readonly escaped: boolean }
  | { readonly ok: false; readonly reason: 'too_long' | 'malformed' };

/**
 * The plaintext to encrypt for a text-only message or edit (REQ-10, REQ-52).
 * Text is sent unchanged unless it could be taken for a typed payload; then it
 * goes in an escape envelope, which must respect `MAX_BODY_BYTES` and
 * `MAX_ENVELOPE_BYTES`.
 */
export function textPlaintextFor(channelId: string, text: string): TextPlaintext {
  if (!needsEnvelopeEscape(text)) return { ok: true, plaintext: text, escaped: false };
  if (!isWellFormedUtf16(text)) return { ok: false, reason: 'malformed' };
  if (utf8ByteLength(text) > MAX_BODY_BYTES) return { ok: false, reason: 'too_long' };
  const plaintext = buildEscapeEnvelope(channelId, text);
  if (utf8ByteLength(plaintext) > MAX_ENVELOPE_BYTES) return { ok: false, reason: 'too_long' };
  return { ok: true, plaintext, escaped: true };
}

// ---------------------------------------------------------------------------
// Plaintext cache record v1 (§6.2.4)
// ---------------------------------------------------------------------------

export type CacheRecordSource = 'dr' | 'sk' | 'own';

export interface PlaintextCacheRecord {
  readonly v: 1;
  /** `scheme://host[:port]`, lower case, from the API base URL. */
  readonly origin: string;
  readonly channel_id: string;
  readonly sender_id: string;
  /** The relay-assigned message id; equals the map key. */
  readonly message_id: string;
  /** Base64 of SHA-256 over the base64-decoded wire payload. */
  readonly wire_sha256: string;
  readonly source: CacheRecordSource;
  /** Exactly the UTF-8 string that was encrypted (`own`) or decrypted. */
  readonly plaintext: string;
}

const SOURCES: ReadonlySet<string> = new Set(['dr', 'sk', 'own']);

/**
 * The relay origin as cache records and the attachment store key it:
 * `scheme://host[:port]` in lower case. Null for a URL that cannot be parsed.
 */
export function relayOrigin(apiBaseUrl: string): string | null {
  try {
    const u = new URL(apiBaseUrl);
    if (u.origin === 'null') return null;
    return u.origin.toLowerCase();
  } catch {
    return null;
  }
}

function isOrigin(s: unknown): s is string {
  return typeof s === 'string' && s.length > 0 && relayOrigin(s) === s;
}

/** Build a record, checking every member. Throws on a malformed field. */
export function makeCacheRecord(fields: Omit<PlaintextCacheRecord, 'v'>): PlaintextCacheRecord {
  const r: PlaintextCacheRecord = {
    v: 1,
    origin: fields.origin,
    channel_id: fields.channel_id,
    sender_id: fields.sender_id,
    message_id: fields.message_id,
    wire_sha256: fields.wire_sha256,
    source: fields.source,
    plaintext: fields.plaintext,
  };
  if (!isValidRecord({ ...r }, r.message_id)) throw new RangeError('malformed cache record');
  return Object.freeze(r);
}

function isValidRecord(o: Record<string, unknown>, key: string): boolean {
  return o.v === 1
    && isOrigin(o.origin)
    && isCanonicalUuid(o.channel_id)
    && isCanonicalUuid(o.sender_id)
    && typeof o.message_id === 'string' && o.message_id.length > 0 && o.message_id === key
    && typeof o.wire_sha256 === 'string' && decodeCanonicalBase64(o.wire_sha256, SHA256_SIZE) !== null
    && typeof o.source === 'string' && SOURCES.has(o.source)
    && typeof o.plaintext === 'string';
}

export type CacheValue =
  | { readonly kind: 'record'; readonly record: PlaintextCacheRecord }
  /** A plain string, or a record with an unknown `v` or a missing or bad member: text at most. */
  | { readonly kind: 'legacy'; readonly text: string | null }
  | { readonly kind: 'absent' };

/**
 * Read a value of the own-message cache stored under `key` (§6.2.4). Only a
 * complete v1 record whose `message_id` equals the key is a record; anything
 * else is a legacy entry that never creates attachment state (REQ-19).
 */
export function readCacheValue(value: unknown, key: string): CacheValue {
  if (value === undefined || value === null) return { kind: 'absent' };
  if (typeof value === 'string') return { kind: 'legacy', text: value };
  if (typeof value !== 'object' || Array.isArray(value)) return { kind: 'legacy', text: null };
  const o = value as Record<string, unknown>;
  if (isValidRecord(o, key)) {
    return {
      kind: 'record',
      record: Object.freeze({
        v: 1,
        origin: o.origin as string,
        channel_id: o.channel_id as string,
        sender_id: o.sender_id as string,
        message_id: o.message_id as string,
        wire_sha256: o.wire_sha256 as string,
        source: o.source as CacheRecordSource,
        plaintext: o.plaintext as string,
      }),
    };
  }
  return { kind: 'legacy', text: typeof o.plaintext === 'string' ? o.plaintext : null };
}
