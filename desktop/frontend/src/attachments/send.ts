/**
 * @module attachments/send
 * Sending messages (SPEC-02 §5.3, §6.5.4): the preflight, sequential sealing
 * and upload of attachments, pending-send records, pairing with the relay's
 * echo, resolution of unconfirmed sends, resends and cleanup.
 *
 * Every message, text or attachments, goes through `PendingSendManager`:
 *
 * - **Preflight** (`prepare`), before any file is read: at most 10 files, each
 *   within min(relay limit, CLIENT_MAX_BLOB_BYTES) (REQ-16); the body and the
 *   exact serialized envelope within MAX_BODY_BYTES and MAX_ENVELOPE_BYTES,
 *   computed with placeholder values of the final lengths (REQ-52); attachment
 *   sending only on relays that advertise `attachments/2` (REQ-17); and the
 *   conversation ready for the encryption REQ-7 requires (REQ-12).
 * - **Start** (`start`): each file is sealed with a fresh key and nonce prefix
 *   and uploaded as an octet-stream blob, one at a time (REQ-13, REQ-14). The
 *   relay's size and hash are checked. The envelope is built, checked again
 *   (REQ-52) and sealed with the Double Ratchet or Sender Keys only (REQ-7).
 *   Any read or encryption failure aborts the whole message and deletes its
 *   pending blobs; staged files stay with the caller (REQ-13).
 * - **Pairing** (REQ-49): an own `channel_message` frame or history item pairs
 *   with the first open record of the same channel whose `wire_sha256` equals
 *   the payload's hash (and, for a live echo, whose `attachment_ids` set is
 *   the frame's). Never by position. Pairing writes the §6.2.4 cache record
 *   (REQ-19). Nothing paired within 30 s: "unconfirmed".
 * - **Resolution** (§6.5.4) on Retry, on reconnect and 10 minutes after the
 *   send: the newest history page, then probe deletes of the blobs.
 * - **Resends** (REQ-47) repeat the sealed bytes, or encrypt again from the
 *   record. No resend ever carries plaintext: send functions accept only a
 *   `SealedPayload` (REQ-48).
 *
 * The record keeps the plaintext and the staged files (needed by REQ-47 (ii))
 * in memory only, and nothing here logs a plaintext, a key or a file name.
 */

import { decodeWireBase64 } from './base64';
import { wireSha256, type PlaintextCacheAccess } from './decode';
import {
  isCanonicalUuid,
  isValidMime,
  makeCacheRecord,
  MAX_ATTACHMENTS_PER_MESSAGE,
  MAX_BODY_BYTES,
  MAX_ENVELOPE_BYTES,
  serializeEnvelope,
  textPlaintextFor,
  type DescriptorInput,
} from './envelope';
import { blobLength, CLIENT_MAX_BLOB_BYTES, padme, sealAttachment, sealedBlob, type SealedAttachment } from './format';
import { sanitizeFileName } from './sanitize';
import { isWellFormedUtf16, utf8ByteLength } from '../e2ee/plaintext';
import type { SealedPayload } from '../e2ee/sealed';
import type { ChannelSendOptions, SendResult } from '../ws';
import type { UploadAttachmentResponse } from '../types';

// ---------------------------------------------------------------------------
// Constants (SPEC-02 §6.8, §8.1)
// ---------------------------------------------------------------------------

/** No pairing within this time: "unconfirmed" (§6.8). */
export const PAIRING_TIMEOUT_MS = 30_000;
/** Resolution runs at the latest this long after the send (§6.8). */
export const RESOLUTION_DEADLINE_MS = 10 * 60_000;
/** A pending blob this close to `pending_expires_at` may no longer be pending (REQ-47). */
export const PENDING_EXPIRY_MARGIN_S = 60;
/** Network retries per upload, with backoff (§8.1). */
export const UPLOAD_NETWORK_RETRIES = 3;
const BACKOFF_BASE_MS = 1_000;
/** Used when a `slow_mode` failure carries no usable `retry_after`. */
const DEFAULT_SLOW_MODE_WAIT_S = 5;

/** The feature token of version-2 attachments (§6.4.6). */
export const ATTACHMENTS_FEATURE = 'attachments/2';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Conversation =
  | { readonly kind: 'dm'; readonly channelId: string; readonly peerId: string }
  | { readonly kind: 'channel'; readonly channelId: string };

export interface ReadGate {
  readonly users?: readonly string[];
  readonly roles?: readonly string[];
  readonly ttlSecs: number;
}

export interface SendOptions {
  readonly replyTo?: string;
  /** Unix seconds. */
  readonly expiresAt?: number;
  readonly gate?: ReadGate;
}

/** The encryption of one conversation (REQ-7, REQ-12). Never reads files. */
export interface ConversationSealer {
  /**
   * REQ-12: whether a message can be encrypted as REQ-7 requires. A DM needs
   * an initialized E2EE manager and a session or a fetched prekey bundle; a
   * node channel needs an own sender key that exists or has been bootstrapped.
   */
  ready(conversation: Conversation): Promise<boolean>;
  /**
   * Encrypt with the Double Ratchet (DM) or Sender Keys (node channel). For
   * `text` the legacy opt-in may be used when neither is available; for
   * `attachments` never (REQ-7). Throws when no sealing succeeds.
   */
  seal(conversation: Conversation, plaintext: string, kind: 'text' | 'attachments'): Promise<SealedPayload>;
}

/** An own message as the relay returned it in history. */
export interface HistoryItemRef {
  readonly messageId: string;
  readonly channelId: string;
  readonly senderId: string;
  /** `encrypted_payload`, base64. */
  readonly payload: string;
  /** Unix seconds. */
  readonly createdAt: number;
}

export interface HistoryPage {
  readonly items: readonly HistoryItemRef[];
  readonly nextCursor?: string;
  readonly hasMore: boolean;
}

/** The relay operations a send needs. */
export interface SendTransport {
  upload(channelId: string, blob: Blob, onProgress?: (loaded: number, total: number) => void): Promise<UploadAttachmentResponse>;
  /** 204 deleted, 404 gone or not ours, 409 claimed. Throws on a network error. */
  deleteAttachment(attachmentId: string): Promise<204 | 404 | 409>;
  sendFrame(channelId: string, sealed: SealedPayload, options: ChannelSendOptions): SendResult;
  /** One history page of a channel, newest first; `before` is the cursor of an older page. */
  history(channelId: string, before?: string): Promise<HistoryPage>;
}

export interface RelayAttachmentLimits {
  /** The relay advertises `attachments/2` (REQ-17). */
  readonly available: boolean;
  /** `attachment_limits.max_blob_bytes`, when known. Never raises the client limit (REQ-16). */
  readonly maxBlobBytes: number | null;
}

export interface SendDeps {
  readonly transport: SendTransport;
  readonly sealer: ConversationSealer;
  /** The own-message cache; pairing writes `own` records (REQ-19). */
  readonly cache: Pick<PlaintextCacheAccess, 'put'>;
  readonly ownUserId: () => string | null;
  /** Relay origin for cache records (`relayOrigin(apiBaseUrl)`). */
  readonly origin: () => string | null;
  readonly limits: () => RelayAttachmentLimits;
  /** Milliseconds; defaults to `Date.now`. */
  readonly now?: () => number;
  /** Waits between upload attempts (backoff, `Retry-After`); defaults to a timer. */
  readonly sleep?: (ms: number) => Promise<void>;
}

/** Why a send was refused or aborted; the message was not sent (§8.1). */
export type SendErrorCode =
  | 'empty'
  | 'relay_unsupported'
  | 'too_many_files'
  | 'file_too_large'
  | 'too_long'
  | 'malformed'
  | 'invalid_channel'
  | 'e2ee_unavailable'
  | 'encrypt_failed'
  | 'upload_forbidden'
  | 'upload_blocked'
  | 'upload_too_large'
  | 'storage_full'
  | 'rate_limited'
  | 'upload_corrupted'
  | 'upload_rejected';

export interface SendError {
  readonly code: SendErrorCode;
  /** User-visible text (§8.1). Never contains a file name. */
  readonly text: string;
  /** For `file_too_large`: the indexes of the staged files over the limit. */
  readonly fileIndexes?: readonly number[];
}

const SEND_ERROR_TEXT: Readonly<Record<SendErrorCode, string>> = Object.freeze({
  empty: 'Nothing to send',
  relay_unsupported: 'This relay must be updated to send end-to-end encrypted attachments',
  too_many_files: `Up to ${MAX_ATTACHMENTS_PER_MESSAGE} files per message`,
  file_too_large: 'File too large',
  too_long: 'Message too long: shorten the text or attach fewer files',
  malformed: 'Message contains invalid characters',
  invalid_channel: 'Not sent: this conversation cannot be used',
  e2ee_unavailable: 'Not sent: end-to-end encryption is unavailable for this conversation',
  encrypt_failed: 'Not sent: a file could not be encrypted',
  upload_forbidden: "You can't attach files here",
  upload_blocked: 'This user has blocked you',
  upload_too_large: 'File too large for this relay',
  storage_full: 'Storage limit reached',
  rate_limited: 'Upload limit reached',
  upload_corrupted: 'Upload was corrupted in transit',
  upload_rejected: 'Upload failed',
});

function sendError(code: SendErrorCode, extra: Partial<SendError> = {}): SendError {
  return { code, text: SEND_ERROR_TEXT[code], ...extra };
}

/** Why an own message failed after it was created (§8.1). */
export type FailureReason =
  | 'unavailable'
  | 'slow_mode'
  | 'internal'
  | 'forbidden'
  | 'blocked'
  | 'allowlist'
  | 'invalid'
  | 'network'
  | 'not_stored'
  | 'connection'
  | 'expired'
  | 'encryption'
  | 'upload';

const RETRYABLE: ReadonlySet<FailureReason> = new Set<FailureReason>([
  'unavailable', 'slow_mode', 'internal', 'network', 'not_stored', 'connection', 'encryption',
]);

const CLAIM_REASONS: ReadonlySet<string> = new Set([
  'invalid', 'forbidden', 'blocked', 'allowlist', 'slow_mode', 'unavailable', 'internal',
]);

const FAILURE_TEXT: Readonly<Record<FailureReason, string>> = Object.freeze({
  unavailable: 'Attachment expired before sending; Retry',
  slow_mode: 'Slow mode: sending soon',
  internal: 'The relay could not store the message; Retry',
  forbidden: "You can't attach files here",
  blocked: 'This user has blocked you',
  allowlist: 'This node only accepts approved app builds',
  invalid: 'Attachment error',
  network: 'Upload failed; Retry',
  not_stored: 'Not sent; Retry',
  connection: 'Not sent; Retry',
  expired: 'Expired before it could be sent',
  encryption: 'Not sent: end-to-end encryption is unavailable for this conversation',
  upload: 'Upload failed',
});

export interface Failure {
  readonly reason: FailureReason;
  readonly text: string;
  readonly retryable: boolean;
}

function failure(reason: FailureReason, text?: string): Failure {
  return { reason, text: text ?? FAILURE_TEXT[reason], retryable: RETRYABLE.has(reason) };
}

/** What the interface shows for one pending send. */
export type PendingStatus = 'sending' | 'unconfirmed' | 'failed' | 'sent';

export interface PendingView {
  readonly id: string;
  readonly channelId: string;
  readonly status: PendingStatus;
  /** Extra status text, e.g. "Waiting for connection". */
  readonly statusText: string | null;
  readonly failure: { readonly text: string; readonly retryable: boolean } | null;
  /** The message text, for the local temporary message only. */
  readonly body: string;
  readonly attachmentCount: number;
  readonly replyTo?: string;
  readonly expiresAt?: number;
  readonly readGated: boolean;
  /** Milliseconds. */
  readonly createdAt: number;
  /** Set once paired. */
  readonly messageId: string | null;
}

export interface UploadProgress {
  readonly id: string;
  readonly fileIndex: number;
  readonly fileCount: number;
  readonly loaded: number;
  readonly total: number;
}

export type PendingEvent =
  | { readonly type: 'updated'; readonly view: PendingView }
  /** Paired with a relay message: replace the temporary message by `messageId`. */
  | { readonly type: 'paired'; readonly view: PendingView; readonly messageId: string; readonly payload: string; readonly senderId: string }
  | { readonly type: 'removed'; readonly id: string; readonly channelId: string }
  | { readonly type: 'progress'; readonly progress: UploadProgress | null };

export type PendingListener = (event: PendingEvent) => void;

/** One staged file as the sender chose it; the name and type are sanitized before use. */
export interface StagedSource {
  readonly file: Blob;
  readonly name: string;
  /** The browser's MIME type guess (`File.type`); may be empty. */
  readonly type?: string;
}

export interface SendInput {
  readonly conversation: Conversation;
  readonly body: string;
  readonly files: readonly StagedSource[];
  readonly options?: SendOptions;
}

/** A send that passed the preflight; hand it to `start`. */
export interface PreparedSend {
  readonly conversation: Conversation;
  readonly envelopeChannelId: string;
  readonly body: string;
  readonly files: readonly PreparedFile[];
  readonly options: SendOptions;
  /** For text-only sends: the exact plaintext (REQ-10 escape applied). */
  readonly textPlaintext: string | null;
  /** The serialized size the preflight computed (REQ-52). */
  readonly estimatedEnvelopeBytes: number;
}

interface PreparedFile {
  readonly file: Blob;
  readonly name: string;
  readonly mime: string;
}

export type PrepareResult = { readonly ok: true; readonly send: PreparedSend } | { readonly ok: false; readonly error: SendError };

export type StartResult =
  /** The message exists (sending, waiting, or failed with Retry); the record owns the files. */
  | { readonly kind: 'started'; readonly id: string }
  /** Nothing was sent; pending blobs were deleted; the caller keeps the staged files (REQ-13). */
  | { readonly kind: 'aborted'; readonly error: SendError };

interface UploadedBlob {
  readonly descriptor: DescriptorInput;
  /** Unix seconds. */
  readonly pendingExpiresAt: number;
}

interface PendingRecord {
  readonly id: string;
  readonly conversation: Conversation;
  readonly envelopeChannelId: string;
  state: 'sending' | 'unconfirmed' | 'failed' | 'sent';
  /** The sealed payload exactly as sent (REQ-48). */
  wire: SealedPayload | null;
  /** The exact UTF-8 plaintext that was encrypted (REQ-19). */
  plaintext: string | null;
  readonly body: string;
  readonly files: readonly PreparedFile[];
  /** One slot per file; null until uploaded, or after the blob is gone. */
  blobs: (UploadedBlob | null)[];
  /** The `attachment_ids` of the frame sent (the descriptor blob ids). */
  attachmentIds: string[];
  readonly options: SendOptions;
  readonly createdAt: number;
  handedOff: boolean;
  failure: Failure | null;
  /** Ids the relay listed in `unavailable_ids`. */
  unavailableIds: Set<string>;
  /** Resolution found a claimed blob: shown as sent, open for pairing. */
  stored: boolean;
  messageId: string | null;
  slowModeResent: boolean;
  /** Transient upload status (§8.1): "retrying", "Upload limit reached, retrying in N s". */
  note: string | null;
  resolving: boolean;
  busy: boolean;
  timers: Set<ReturnType<typeof setTimeout>>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const HEX = '0123456789abcdef';
function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += HEX[b >> 4] + HEX[b & 15];
  return s;
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  if (s.size !== a.length) return false;
  return b.every(x => s.has(x));
}

function lower(s: string): string {
  return s.toLowerCase();
}

/** A sender-side MIME type: lower case, valid under §6.2.2, else octet-stream. */
export function descriptorMime(type: string | undefined): string {
  const t = (type ?? '').trim().toLowerCase();
  return isValidMime(t) ? t : 'application/octet-stream';
}

/** The client's per-file blob limit under REQ-16. */
export function effectiveMaxBlobBytes(relayMax: number | null): number {
  return relayMax !== null && Number.isFinite(relayMax) && relayMax > 0 ? Math.min(relayMax, CLIENT_MAX_BLOB_BYTES) : CLIENT_MAX_BLOB_BYTES;
}

/** Whether a file of `size` bytes fits the limit once padded and sealed (REQ-16). */
export function fitsBlobLimit(size: number, relayMax: number | null): boolean {
  if (!Number.isSafeInteger(size) || size < 0) return false;
  return blobLength(padme(size)) <= effectiveMaxBlobBytes(relayMax);
}

/** A distinct placeholder blob id of the final length for slot `i`. */
function placeholderBlobId(i: number): string {
  return `00000000-0000-4000-8000-${i.toString(16).padStart(12, '0')}`;
}

/**
 * The exact serialized envelope size of a message with these files (REQ-52):
 * placeholder blob ids, keys, nonce prefixes and hashes have the final
 * lengths, and sizes, names and MIME types are the real ones.
 */
export function estimateEnvelopeBytes(channelId: string, body: string, files: readonly { size: number; name: string; mime: string }[]): number {
  return utf8ByteLength(serializeEnvelope({
    channelId,
    body,
    attachments: files.map((f, i) => ({
      blobId: placeholderBlobId(i),
      key: new Uint8Array(32),
      noncePrefix: new Uint8Array(7),
      sha256: new Uint8Array(32),
      size: f.size,
      paddedSize: padme(f.size),
      name: f.name,
      mime: f.mime,
    })),
  }));
}

class UploadError extends Error {
  constructor(readonly code: SendErrorCode | 'network') {
    super('upload failed');
    this.name = 'UploadError';
  }
}

class SealFileError extends Error {
  constructor() {
    super('a file could not be encrypted');
    this.name = 'SealFileError';
  }
}

function errorStatus(e: unknown): number | undefined {
  const s = (e as { status?: unknown } | null)?.status;
  return typeof s === 'number' ? s : undefined;
}

function errorReason(e: unknown): string | undefined {
  const r = (e as { reason?: unknown } | null)?.reason;
  return typeof r === 'string' ? r : undefined;
}

function errorRetryAfter(e: unknown): number | undefined {
  const r = (e as { retryAfter?: unknown } | null)?.retryAfter;
  return typeof r === 'number' && Number.isFinite(r) && r >= 0 ? r : undefined;
}

function isNetworkError(e: unknown): boolean {
  if (errorStatus(e) !== undefined) return false;
  const name = (e as { name?: unknown } | null)?.name;
  return name === 'AttachmentNetworkError' || name === 'TypeError' || name === 'NetworkError';
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// The manager
// ---------------------------------------------------------------------------

let counter = 0;
function newTempId(): string {
  counter += 1;
  return `temp_${Date.now().toString(36)}_${counter}_${Math.random().toString(36).slice(2, 8)}`;
}

export class PendingSendManager {
  private readonly records = new Map<string, PendingRecord>();
  private readonly listeners = new Set<PendingListener>();

  constructor(private readonly deps: SendDeps) {}

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  private sleep(ms: number): Promise<void> {
    return (this.deps.sleep ?? delay)(ms);
  }

  subscribe(listener: PendingListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(event: PendingEvent): void {
    for (const l of [...this.listeners]) {
      try {
        l(event);
      } catch {
        // A failing view must not break sending.
      }
    }
  }

  private view(r: PendingRecord): PendingView {
    let status: PendingStatus;
    if (r.state === 'failed') status = 'failed';
    else if (r.state === 'sent' || r.stored) status = 'sent';
    else status = r.state;
    let statusText: string | null = null;
    if (r.state === 'sending' && r.note !== null) statusText = r.note;
    else if (r.state === 'sending' && r.wire !== null && !r.handedOff) statusText = 'Waiting for connection';
    return {
      id: r.id,
      channelId: r.conversation.channelId,
      status,
      statusText,
      failure: r.failure ? { text: r.failure.text, retryable: r.failure.retryable } : null,
      body: r.body,
      attachmentCount: r.files.length,
      replyTo: r.options.replyTo,
      expiresAt: r.options.expiresAt,
      readGated: !!r.options.gate && ((r.options.gate.users?.length ?? 0) > 0 || (r.options.gate.roles?.length ?? 0) > 0),
      createdAt: r.createdAt,
      messageId: r.messageId,
    };
  }

  private update(r: PendingRecord): void {
    if (this.records.get(r.id) === r) this.emit({ type: 'updated', view: this.view(r) });
  }

  /** The views of the open records of a channel, oldest first (re-shown after a history load). */
  listChannel(channelId: string): PendingView[] {
    const ch = lower(channelId);
    return [...this.records.values()].filter(r => lower(r.conversation.channelId) === ch).map(r => this.view(r));
  }

  get(id: string): PendingView | null {
    const r = this.records.get(id);
    return r ? this.view(r) : null;
  }

  /** Whether the record has attachments (for the edit guard, REQ-18). */
  hasAttachments(id: string): boolean {
    return (this.records.get(id)?.files.length ?? 0) > 0;
  }

  // -------------------------------------------------------------------------
  // Preflight
  // -------------------------------------------------------------------------

  /**
   * Check everything that can be checked before reading any file (REQ-12,
   * REQ-16, REQ-17, REQ-52). Reads no file: only `size`, `name` and `type`.
   */
  async prepare(input: SendInput): Promise<PrepareResult> {
    const files = input.files;
    const body = input.body;
    const conversation = input.conversation;
    const options = input.options ?? {};
    const envelopeChannelId = lower(conversation.channelId);
    if (files.length === 0 && body.trim() === '') return { ok: false, error: sendError('empty') };
    if (!isCanonicalUuid(envelopeChannelId)) return { ok: false, error: sendError('invalid_channel') };
    if (!isWellFormedUtf16(body)) return { ok: false, error: sendError('malformed') };

    let textPlaintext: string | null = null;
    let estimated = 0;
    const prepared: PreparedFile[] = [];
    if (files.length > 0) {
      const limits = this.deps.limits();
      if (!limits.available) return { ok: false, error: sendError('relay_unsupported') };
      if (files.length > MAX_ATTACHMENTS_PER_MESSAGE) return { ok: false, error: sendError('too_many_files') };
      const tooLarge: number[] = [];
      files.forEach((f, i) => {
        if (!fitsBlobLimit(f.file.size, limits.maxBlobBytes)) tooLarge.push(i);
      });
      if (tooLarge.length > 0) {
        const mib = Math.floor(effectiveMaxBlobBytes(limits.maxBlobBytes) / 1_048_576);
        return { ok: false, error: sendError('file_too_large', { fileIndexes: tooLarge, text: `File too large: the limit is ${mib} MiB` }) };
      }
      for (const f of files) prepared.push({ file: f.file, name: sanitizeFileName(f.name).name, mime: descriptorMime(f.type) });
      if (utf8ByteLength(body) > MAX_BODY_BYTES) return { ok: false, error: sendError('too_long') };
      estimated = estimateEnvelopeBytes(envelopeChannelId, body, prepared.map(f => ({ size: f.file.size, name: f.name, mime: f.mime })));
      if (estimated > MAX_ENVELOPE_BYTES) return { ok: false, error: sendError('too_long') };
    } else {
      const t = textPlaintextFor(envelopeChannelId, body);
      if (!t.ok) return { ok: false, error: sendError(t.reason === 'too_long' ? 'too_long' : 'malformed') };
      textPlaintext = t.plaintext;
      estimated = utf8ByteLength(t.plaintext);
    }

    let ready = false;
    try {
      ready = await this.deps.sealer.ready(conversation);
    } catch {
      ready = false;
    }
    if (!ready) return { ok: false, error: sendError('e2ee_unavailable') };

    return {
      ok: true,
      send: {
        conversation,
        envelopeChannelId,
        body,
        files: prepared,
        options,
        textPlaintext,
        estimatedEnvelopeBytes: estimated,
      },
    };
  }

  // -------------------------------------------------------------------------
  // First send
  // -------------------------------------------------------------------------

  /**
   * Seal and upload the files, build and seal the envelope, and send the
   * frame. The temporary message appears (an `updated` event) as soon as this
   * starts. Resolves `aborted` when nothing was sent (REQ-13), or `started`
   * once the message exists, sent, waiting for the connection, or failed with
   * Retry after repeated network errors.
   */
  async start(prepared: PreparedSend): Promise<StartResult> {
    const r: PendingRecord = {
      id: newTempId(),
      conversation: prepared.conversation,
      envelopeChannelId: prepared.envelopeChannelId,
      state: 'sending',
      wire: null,
      plaintext: prepared.textPlaintext,
      body: prepared.body,
      files: prepared.files,
      blobs: prepared.files.map(() => null),
      attachmentIds: [],
      options: prepared.options,
      createdAt: this.now(),
      handedOff: false,
      failure: null,
      unavailableIds: new Set(),
      stored: false,
      messageId: null,
      slowModeResent: false,
      note: null,
      resolving: false,
      busy: true,
      timers: new Set(),
    };
    this.records.set(r.id, r);
    this.update(r);
    try {
      if (r.files.length > 0) {
        try {
          await this.uploadMissing(r);
        } catch (e) {
          if (e instanceof UploadError && e.code === 'network') {
            this.fail(r, failure('network'));
            return { kind: 'started', id: r.id };
          }
          return await this.abort(r, e instanceof UploadError ? sendError(e.code as SendErrorCode) : sendError('encrypt_failed'));
        }
        const plaintext = this.buildEnvelope(r);
        if (plaintext === null) return await this.abort(r, sendError('too_long'));
        r.plaintext = plaintext;
      }
      let sealed: SealedPayload;
      try {
        sealed = await this.deps.sealer.seal(r.conversation, r.plaintext!, r.files.length > 0 ? 'attachments' : 'text');
      } catch {
        return await this.abort(r, sendError('e2ee_unavailable'));
      }
      r.wire = sealed;
      r.attachmentIds = r.blobs.map(b => b!.descriptor.blobId);
      this.transmit(r);
      return { kind: 'started', id: r.id };
    } finally {
      r.busy = false;
      this.emit({ type: 'progress', progress: null });
    }
  }

  /** REQ-13: delete the message's pending blobs, drop the record, and report. */
  private async abort(r: PendingRecord, error: SendError): Promise<StartResult> {
    await this.deletePending(r);
    this.close(r);
    return { kind: 'aborted', error };
  }

  /** Seal and upload every file slot that has no usable blob, one at a time. */
  private async uploadMissing(r: PendingRecord): Promise<void> {
    const nowS = this.now() / 1000;
    for (let i = 0; i < r.files.length; i++) {
      const b = r.blobs[i];
      const usable = b !== null
        && !r.unavailableIds.has(b.descriptor.blobId)
        && b.pendingExpiresAt - nowS > PENDING_EXPIRY_MARGIN_S;
      if (usable) continue;
      r.blobs[i] = null;
      r.blobs[i] = await this.sealAndUpload(r, i);
    }
    r.unavailableIds.clear();
  }

  private async sealAndUpload(r: PendingRecord, index: number): Promise<UploadedBlob> {
    const f = r.files[index];
    let sealed: SealedAttachment;
    try {
      sealed = await sealAttachment(f.file);
    } catch {
      throw new SealFileError();
    }
    const receipt = await this.uploadWithRetries(r, index, sealed);
    return {
      descriptor: {
        blobId: receipt.attachment_id,
        key: sealed.key,
        noncePrefix: sealed.noncePrefix,
        sha256: sealed.sha256,
        size: sealed.size,
        paddedSize: sealed.paddedSize,
        name: f.name,
        mime: f.mime,
      },
      pendingExpiresAt: receipt.pending_expires_at,
    };
  }

  /**
   * Upload one sealed blob (§8.1): up to 3 network retries with backoff; on a
   * size or hash mismatch, delete the pending upload and retry once (REQ-14);
   * on 429 wait `Retry-After` and retry once; anything else fails at once.
   */
  private async uploadWithRetries(r: PendingRecord, index: number, sealed: SealedAttachment): Promise<UploadAttachmentResponse> {
    const expectedHash = toHex(sealed.sha256);
    let networkFailures = 0;
    let mismatches = 0;
    let rateLimited = 0;
    for (;;) {
      let receipt: UploadAttachmentResponse;
      try {
        receipt = await this.deps.transport.upload(r.conversation.channelId, sealedBlob(sealed), (loaded, total) => {
          this.emit({ type: 'progress', progress: { id: r.id, fileIndex: index, fileCount: r.files.length, loaded, total } });
        });
      } catch (e) {
        if (isNetworkError(e)) {
          if (networkFailures >= UPLOAD_NETWORK_RETRIES) {
            this.setNote(r, null);
            throw new UploadError('network');
          }
          this.setNote(r, 'Upload failed, retrying');
          await this.sleep(BACKOFF_BASE_MS * 2 ** networkFailures);
          networkFailures++;
          continue;
        }
        const status = errorStatus(e);
        const reason = errorReason(e);
        if (status === 429 && rateLimited === 0) {
          rateLimited++;
          const wait = Math.max(1, Math.ceil(errorRetryAfter(e) ?? 1));
          this.setNote(r, `Upload limit reached, retrying in ${wait} s`);
          await this.sleep(1000 * wait);
          continue;
        }
        this.setNote(r, null);
        if (status === 429) throw new UploadError('rate_limited');
        if (status === 403) throw new UploadError(reason === 'blocked' ? 'upload_blocked' : 'upload_forbidden');
        if (status === 413) throw new UploadError('upload_too_large');
        if (status === 507) throw new UploadError('storage_full');
        if (status === 404 || status === 405) throw new UploadError('upload_rejected');
        throw new UploadError('upload_rejected');
      }
      const ok = isCanonicalUuid(receipt.attachment_id)
        && receipt.blob_size === sealed.blobLength
        && typeof receipt.blob_sha256 === 'string'
        && receipt.blob_sha256.toLowerCase() === expectedHash
        && Number.isFinite(receipt.pending_expires_at);
      if (ok) {
        this.setNote(r, null);
        return receipt;
      }
      // REQ-14: a mismatch means the upload is not ours as sealed: delete it.
      if (typeof receipt.attachment_id === 'string' && receipt.attachment_id !== '') {
        try {
          await this.deps.transport.deleteAttachment(receipt.attachment_id);
        } catch {
          // It expires on its own.
        }
      }
      if (mismatches >= 1) throw new UploadError('upload_corrupted');
      mismatches++;
    }
  }

  /** Build the envelope from the uploaded blobs; null when it is too large (REQ-52). */
  private buildEnvelope(r: PendingRecord): string | null {
    const plaintext = serializeEnvelope({
      channelId: r.envelopeChannelId,
      body: r.body,
      attachments: r.blobs.map(b => b!.descriptor),
    });
    return utf8ByteLength(plaintext) > MAX_ENVELOPE_BYTES ? null : plaintext;
  }

  /**
   * Send the record's sealed frame, keeping `reply_to`, `expires_at` and the
   * gate. Every frame that leaves the socket, first send or resend, gets the
   * 30 s pairing timeout and the resolution deadline (REQ-49, §6.5.4).
   */
  private transmit(r: PendingRecord): void {
    if (r.wire === null) return;
    // Timers of an earlier frame of this record no longer apply.
    this.clearTimers(r);
    if (r.options.expiresAt !== undefined && r.options.expiresAt * 1000 <= this.now()) {
      this.fail(r, failure('expired'));
      return;
    }
    const result = this.deps.transport.sendFrame(r.conversation.channelId, r.wire, {
      replyTo: r.options.replyTo,
      expiresAt: r.options.expiresAt,
      gate: r.options.gate,
      attachmentIds: r.attachmentIds,
    });
    r.state = 'sending';
    r.failure = null;
    r.handedOff = result.handedOff;
    if (result.handedOff) {
      this.schedule(r, PAIRING_TIMEOUT_MS, () => {
        if (r.state === 'sending' && r.handedOff) {
          r.state = 'unconfirmed';
          this.update(r);
        }
      });
      this.schedule(r, RESOLUTION_DEADLINE_MS, () => {
        // Only a frame that left the socket can have been stored unseen.
        if (r.handedOff && (r.state === 'sending' || r.state === 'unconfirmed') && !r.stored) void this.resolve(r);
      });
    }
    this.update(r);
  }

  private setNote(r: PendingRecord, note: string | null): void {
    if (r.note === note) return;
    r.note = note;
    this.update(r);
  }

  private schedule(r: PendingRecord, ms: number, fn: () => void): void {
    const t = setTimeout(() => {
      r.timers.delete(t);
      if (this.records.get(r.id) === r) fn();
    }, ms);
    r.timers.add(t);
  }

  private clearTimers(r: PendingRecord): void {
    for (const t of r.timers) clearTimeout(t);
    r.timers.clear();
  }

  private fail(r: PendingRecord, f: Failure): void {
    r.state = 'failed';
    r.failure = f;
    this.clearTimers(r);
    this.update(r);
  }

  private close(r: PendingRecord): void {
    this.clearTimers(r);
    if (this.records.get(r.id) === r) {
      this.records.delete(r.id);
      this.emit({ type: 'removed', id: r.id, channelId: r.conversation.channelId });
    }
  }

  /** DELETE every blob of the record that may still be pending; errors are ignored. */
  private async deletePending(r: PendingRecord): Promise<void> {
    for (const b of r.blobs) {
      if (!b) continue;
      try {
        await this.deps.transport.deleteAttachment(b.descriptor.blobId);
      } catch {
        // A pending blob expires on its own.
      }
    }
  }

  // -------------------------------------------------------------------------
  // Pairing (REQ-49)
  // -------------------------------------------------------------------------

  private pair(r: PendingRecord, messageId: string, payload: string, senderId: string): void {
    r.state = 'sent';
    r.messageId = messageId;
    this.clearTimers(r);
    const origin = this.deps.origin();
    if (origin !== null && r.plaintext !== null && r.wire !== null) {
      try {
        this.deps.cache.put(makeCacheRecord({
          origin,
          channel_id: r.envelopeChannelId,
          sender_id: lower(senderId),
          message_id: messageId,
          wire_sha256: r.wire.wireSha256,
          source: 'own',
          plaintext: r.plaintext,
        }));
      } catch {
        // Ids that are not canonical UUIDs: no record.
      }
    }
    const view = this.view(r);
    this.records.delete(r.id);
    this.emit({ type: 'paired', view, messageId, payload, senderId });
  }

  private findMatch(channelId: string, senderId: string, payload: string, attachmentIds: readonly string[] | null): PendingRecord | null {
    const own = this.deps.ownUserId();
    if (own === null || lower(senderId) !== lower(own)) return null;
    if (decodeWireBase64(payload) === null) return null;
    const hash = wireSha256(payload);
    if (hash === null) return null;
    const ch = lower(channelId);
    for (const r of this.records.values()) {
      if (r.state !== 'sending' && r.state !== 'unconfirmed') continue;
      if (r.wire === null || lower(r.conversation.channelId) !== ch) continue;
      if (r.wire.wireSha256 !== hash) continue;
      if (attachmentIds !== null && !sameSet(r.attachmentIds, attachmentIds)) continue;
      return r;
    }
    return null;
  }

  /**
   * Pair a live `channel_message` frame whose `from` is the user's own id, in
   * any channel. `rawFrame` is the relay's frame, whose `attachment_ids` is
   * read here and used only for pairing, never for attachment state (§6.5.2).
   * Returns the paired view (whose `id` is the temporary message id), or null
   * when nothing pairs: then the frame is an own message from another session
   * (§6.5.4).
   */
  pairLiveEcho(frame: { channelId: string; messageId: string; senderId: string; payload: string }, rawFrame: unknown = null): PendingView | null {
    const raw = (rawFrame && typeof rawFrame === 'object' ? (rawFrame as { attachment_ids?: unknown }).attachment_ids : undefined);
    const ids = Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : [];
    const r = this.findMatch(frame.channelId, frame.senderId, frame.payload, ids);
    if (!r) return null;
    this.pair(r, frame.messageId, frame.payload, frame.senderId);
    return { ...this.view(r) };
  }

  /** Pair an own history item (no `attachment_ids` on history items). */
  pairHistoryItem(item: HistoryItemRef): PendingView | null {
    const r = this.findMatch(item.channelId, item.senderId, item.payload, null);
    if (!r) return null;
    this.pair(r, item.messageId, item.payload, item.senderId);
    return { ...this.view(r) };
  }

  private pairPage(items: readonly HistoryItemRef[]): void {
    for (const item of items) this.pairHistoryItem(item);
  }

  // -------------------------------------------------------------------------
  // Claim failures (REQ-15, §6.5.3)
  // -------------------------------------------------------------------------

  /**
   * Handle an `attachment_claim_failed` frame. Only the open record whose
   * `attachment_ids` set equals the frame's is affected; a frame for another
   * message changes nothing. Returns true when a record was marked failed.
   */
  onClaimFailed(frame: { reason?: unknown; attachment_ids?: unknown; unavailable_ids?: unknown; retry_after?: unknown }): boolean {
    if (!Array.isArray(frame.attachment_ids)) return false;
    const ids = frame.attachment_ids.filter((x): x is string => typeof x === 'string');
    if (ids.length === 0 || ids.length !== frame.attachment_ids.length) return false;
    let r: PendingRecord | null = null;
    for (const rec of this.records.values()) {
      if ((rec.state === 'sending' || rec.state === 'unconfirmed') && rec.attachmentIds.length > 0 && sameSet(rec.attachmentIds, ids)) {
        r = rec;
        break;
      }
    }
    if (!r) return false;
    const reason = (typeof frame.reason === 'string' && CLAIM_REASONS.has(frame.reason) ? frame.reason : 'internal') as FailureReason;
    if (reason === 'unavailable') {
      const listed = Array.isArray(frame.unavailable_ids)
        ? frame.unavailable_ids.filter((x): x is string => typeof x === 'string' && ids.includes(x))
        : [];
      r.unavailableIds = new Set(listed.length > 0 ? listed : ids);
    }
    if (reason === 'slow_mode') {
      const wait = typeof frame.retry_after === 'number' && Number.isFinite(frame.retry_after) && frame.retry_after >= 0
        ? Math.ceil(frame.retry_after)
        : DEFAULT_SLOW_MODE_WAIT_S;
      this.fail(r, failure('slow_mode', `Slow mode: sending in ${wait} s`));
      if (!r.slowModeResent) {
        r.slowModeResent = true;
        const rec = r;
        this.schedule(rec, wait * 1000, () => {
          if (rec.state === 'failed' && rec.failure?.reason === 'slow_mode') void this.retry(rec.id);
        });
      }
      return true;
    }
    this.fail(r, failure(reason));
    return true;
  }

  // -------------------------------------------------------------------------
  // Resolution (§6.5.4)
  // -------------------------------------------------------------------------

  /** Still open, not rebuilding, and waiting for confirmation. */
  private awaitingConfirmation(r: PendingRecord): boolean {
    return this.records.get(r.id) === r && !r.busy && r.handedOff && (r.state === 'sending' || r.state === 'unconfirmed');
  }

  private async resolve(r: PendingRecord): Promise<void> {
    if (r.resolving || !this.awaitingConfirmation(r)) return;
    r.resolving = true;
    try {
      let page: HistoryPage;
      try {
        page = await this.deps.transport.history(r.conversation.channelId);
      } catch {
        return; // Try again on the next trigger.
      }
      this.pairPage(page.items);
      if (!this.awaitingConfirmation(r)) return; // paired, or changed meanwhile
      if (r.attachmentIds.length === 0) return; // text stays unconfirmed (§6.5.4 step 3)

      const statuses: number[] = [];
      for (const id of [...r.attachmentIds]) {
        try {
          statuses.push(await this.deps.transport.deleteAttachment(id));
        } catch {
          return; // Network error: resolve later.
        }
      }
      if (!this.awaitingConfirmation(r)) return;
      if (statuses.includes(409)) {
        // Claims are all-or-nothing: the message was stored.
        r.stored = true;
        r.state = 'unconfirmed';
        this.clearTimers(r);
        this.update(r);
        await this.fetchBackTo(r, page);
        return;
      }
      // 204 or 404 for every id: not stored, or the blobs are gone.
      r.blobs = r.blobs.map(() => null);
      this.fail(r, failure('not_stored'));
    } finally {
      r.resolving = false;
    }
  }

  /** Fetch older history pages back to the record's `created_at`, once (§6.5.4). */
  private async fetchBackTo(r: PendingRecord, first: HistoryPage): Promise<void> {
    let page = first;
    const createdS = Math.floor(r.createdAt / 1000) - 1;
    for (let i = 0; i < 50 && page.hasMore && page.nextCursor !== undefined; i++) {
      const oldest = page.items.reduce((m, it) => Math.min(m, it.createdAt), Number.POSITIVE_INFINITY);
      if (oldest < createdS) return;
      try {
        page = await this.deps.transport.history(r.conversation.channelId, page.nextCursor);
      } catch {
        return;
      }
      this.pairPage(page.items);
      if (this.records.get(r.id) !== r) return;
    }
  }

  // -------------------------------------------------------------------------
  // Reconnect, Retry, Delete (REQ-47, §6.5.4)
  // -------------------------------------------------------------------------

  /**
   * The socket reconnected: resend byte for byte every frame that was not
   * handed off while all its blobs have more than 60 s left (REQ-47 (i)),
   * otherwise mark it failed; resolve every unconfirmed send.
   */
  onReconnect(): void {
    const nowS = this.now() / 1000;
    for (const r of [...this.records.values()]) {
      if (r.busy) continue;
      if (r.state === 'sending' && r.wire !== null && !r.handedOff) {
        const fresh = r.blobs.every(b => b !== null && b.pendingExpiresAt - nowS > PENDING_EXPIRY_MARGIN_S);
        if (fresh) this.transmit(r);
        else this.fail(r, failure('connection'));
      } else if (r.state === 'unconfirmed' && !r.stored) {
        void this.resolve(r);
      }
    }
  }

  /**
   * Retry a failed or unconfirmed send (REQ-47). An unconfirmed send is
   * resolved first and resent only if resolution finds it was not stored. A
   * frame the relay refused with `slow_mode` or `internal` is resent byte for
   * byte while its blobs stay pending; every other retry encrypts again,
   * re-uploading only the blobs that may no longer be pending.
   */
  async retry(id: string): Promise<void> {
    const r = this.records.get(id);
    if (!r || r.busy || r.resolving) return;
    if (r.state === 'unconfirmed') {
      if (r.stored) return;
      await this.resolve(r);
      // `resolve` may have paired, stored or failed the record.
      if (this.records.get(id) !== r || (r.state as PendingRecord['state']) !== 'failed') return;
    }
    if (r.state !== 'failed' || !r.failure?.retryable) return;
    if (r.options.expiresAt !== undefined && r.options.expiresAt * 1000 <= this.now()) {
      this.fail(r, failure('expired'));
      return;
    }
    this.clearTimers(r);
    const reason = r.failure.reason;
    const nowS = this.now() / 1000;
    const blobsFresh = r.blobs.every(b => b !== null && b.pendingExpiresAt - nowS > PENDING_EXPIRY_MARGIN_S);
    if ((reason === 'slow_mode' || reason === 'internal') && r.attachmentIds.length > 0 && r.wire !== null && blobsFresh) {
      // REQ-47 (i): the relay refused this exact frame for a reason other
      // than `unavailable`, so it was not stored.
      this.transmit(r);
      return;
    }
    await this.rebuild(r);
  }

  /** REQ-47 (ii): re-run REQ-12 to REQ-15, REQ-52 and REQ-7 from the record. */
  private async rebuild(r: PendingRecord): Promise<void> {
    r.busy = true;
    r.state = 'sending';
    r.failure = null;
    r.wire = null;
    r.handedOff = false;
    this.update(r);
    try {
      let ready = false;
      try {
        ready = await this.deps.sealer.ready(r.conversation);
      } catch {
        ready = false;
      }
      if (!ready) {
        this.fail(r, failure('encryption'));
        return;
      }
      if (r.files.length > 0) {
        try {
          await this.uploadMissing(r);
        } catch (e) {
          if (e instanceof UploadError) {
            this.fail(r, e.code === 'network' ? failure('network') : failure('upload', SEND_ERROR_TEXT[e.code]));
          } else {
            this.fail(r, failure('encryption', SEND_ERROR_TEXT.encrypt_failed));
          }
          return;
        }
        const plaintext = this.buildEnvelope(r);
        if (plaintext === null) {
          this.fail(r, failure('upload', SEND_ERROR_TEXT.too_long));
          return;
        }
        r.plaintext = plaintext;
      }
      if (r.plaintext === null) {
        this.fail(r, failure('encryption'));
        return;
      }
      let sealed: SealedPayload;
      try {
        sealed = await this.deps.sealer.seal(r.conversation, r.plaintext, r.files.length > 0 ? 'attachments' : 'text');
      } catch {
        this.fail(r, failure('encryption'));
        return;
      }
      r.wire = sealed;
      r.attachmentIds = r.blobs.map(b => b!.descriptor.blobId);
      r.slowModeResent = false;
      this.transmit(r);
    } finally {
      r.busy = false;
      this.emit({ type: 'progress', progress: null });
    }
  }

  /**
   * Abandon a failed send: delete its pending blobs and close the record
   * (§6.5.4). Records in other states are left alone.
   */
  async abandon(id: string): Promise<boolean> {
    const r = this.records.get(id);
    if (!r || r.busy || r.state !== 'failed') return false;
    this.close(r);
    await this.deletePending(r);
    return true;
  }

  /**
   * Tests only: mark a send failed with a retryable reason, as the scenarios
   * of T-47 (e) and RG-C193 require ("a text-only message forced to failed").
   * Throws outside the test build, like the fixed-key sealing of format.ts.
   */
  failForTests(id: string, reason: FailureReason = 'internal'): void {
    if (import.meta.env.MODE !== 'test') throw new Error('available only in tests');
    const r = this.records.get(id);
    if (r) this.fail(r, failure(reason));
  }

  /** Drop every record (logout). Pending blobs expire on the relay. */
  clear(): void {
    for (const r of [...this.records.values()]) this.close(r);
  }
}

/** Describe a send error for the composer (§8.1). */
export function sendErrorText(error: SendError): string {
  return error.text;
}
