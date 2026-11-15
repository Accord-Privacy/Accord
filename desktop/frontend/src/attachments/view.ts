/**
 * @module attachments/view
 * Downloading, verifying, previewing and saving attachments (SPEC-02 §5.4).
 *
 * - Blobs are fetched only with `GET /attachments/{id}`, with the length cap
 *   of REQ-20, and released only after `openAttachment` has checked the
 *   length, hash, every record and the padding (REQ-5). On any failure no
 *   received or partly decrypted byte is rendered, previewed, saved or cached;
 *   there is no fallback to raw bytes (REQ-21).
 * - Inline previews only for the allowlist of §6.8, from `blob:` URLs whose
 *   Blob carries the allowlisted type; every other type is a download whose
 *   Blob is `application/octet-stream` (REQ-22). Automatic fetches only for
 *   allowlisted media up to 10 MiB of blob (REQ-25, OD-39).
 * - Saving in the Tauri shell goes through the `save_attachment` command with
 *   the sanitized name and the verified bytes; in the relay-served web client
 *   through an anchor with `download` on an octet-stream `blob:` URL. No
 *   fallback, no navigation, no `window.open`, no frame (REQ-22).
 * - When a message is deleted, purged or expires, its URLs are revoked, its
 *   downloads aborted and its bytes dropped (REQ-24): the attachment store's
 *   `removed` events drive this.
 *
 * Nothing here logs a name, a key or bytes.
 */

import { api, AttachmentLengthError } from '../api';
import { AttachmentIntegrityError, blobLength, openAttachment } from './format';
import type { VerifiedDescriptor } from './decode';
import { attachmentStore, type AttachmentKey, type AttachmentStore, type StoreEvent } from './store';
import { shownAttachmentSummary, type AttachmentBearer } from './render';
import { blobTypeFor, previewElementFor, sanitizeFileName, type PreviewElement } from './sanitize';

/** Largest blob fetched automatically for an inline preview (§6.8, REQ-25). */
export const AUTO_PREVIEW_MAX_BLOB_BYTES = 10_485_760;

export type AttachmentLoadError = 'unavailable' | 'network' | 'integrity';

export type AttachmentLoadState =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  /** Verified. `url` is set only for allowlisted previews (REQ-22). */
  | { readonly status: 'ready'; readonly blob: Blob; readonly url: string | null }
  | { readonly status: 'error'; readonly error: AttachmentLoadError };

/** User-visible failure texts (SPEC-02 §8.2). */
export const LOAD_ERROR_TEXT: Readonly<Record<AttachmentLoadError, string>> = Object.freeze({
  unavailable: 'Attachment unavailable (deleted, expired or no access)',
  network: "Couldn't download — Retry",
  integrity: 'Attachment failed its integrity check and may have been tampered with',
});
export const UNSUPPORTED_ATTACHMENT_TEXT = 'Unsupported attachment — update Accord';
export const SAVE_FAILED_TEXT = "Couldn't save the file";

/** Whether a descriptor is previewed inline, and in which element. */
export function previewFor(d: Pick<VerifiedDescriptor, 'mime'>): PreviewElement | null {
  return previewElementFor(d.mime);
}

/** REQ-25: fetch automatically only allowlisted media whose blob is at most 10 MiB. */
export function shouldAutoFetch(d: Pick<VerifiedDescriptor, 'mime' | 'paddedSize'>): boolean {
  return previewElementFor(d.mime) !== null && blobLength(d.paddedSize) <= AUTO_PREVIEW_MAX_BLOB_BYTES;
}

/**
 * Counts of the attachments a message shows (search filters, badges): only
 * the store entry its own decode produced (`attachments/render.ts`).
 */
export function attachmentSummary(msg: AttachmentBearer, origin: string, store: AttachmentStore = attachmentStore): { total: number; usable: number; images: number } {
  return shownAttachmentSummary(msg, origin, store);
}

export interface ViewDeps {
  download(attachmentId: string, expectedLength: number, signal: AbortSignal): Promise<Uint8Array>;
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
}

interface Entry {
  state: AttachmentLoadState;
  controller: AbortController | null;
}

function messageKey(k: AttachmentKey): string {
  return JSON.stringify([k.origin, k.channelId, k.messageId]);
}

function entryKey(k: AttachmentKey, blobId: string): string {
  return JSON.stringify([k.origin, k.channelId, k.messageId, blobId]);
}

const IDLE: AttachmentLoadState = Object.freeze({ status: 'idle' });

function classify(e: unknown): AttachmentLoadError {
  if (e instanceof AttachmentIntegrityError || e instanceof AttachmentLengthError) return 'integrity';
  const status = (e as { status?: unknown } | null)?.status;
  if (typeof status === 'number') return status === 404 || status === 403 || status === 401 || status === 410 ? 'unavailable' : 'network';
  return 'network';
}

/**
 * Per-attachment download state, keyed like the attachment store plus the
 * blob id. Views subscribe to it; it subscribes to the store to drop state.
 */
export class AttachmentViews {
  private readonly entries = new Map<string, Entry>();
  /** message key → entry keys */
  private readonly byMessage = new Map<string, Set<string>>();
  private readonly listeners = new Set<() => void>();
  private readonly unsubscribeStore: () => void;

  constructor(private readonly deps: ViewDeps, store: AttachmentStore) {
    this.unsubscribeStore = store.subscribe((e: StoreEvent) => {
      if (e.type === 'removed') this.dropMessage(e.entry.key);
      else if (e.type === 'cleared') this.clear();
    });
  }

  get(key: AttachmentKey, blobId: string): AttachmentLoadState {
    return this.entries.get(entryKey(key, blobId))?.state ?? IDLE;
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(): void {
    for (const l of [...this.listeners]) {
      try {
        l();
      } catch {
        // ignore
      }
    }
  }

  private set(k: string, mk: string, entry: Entry): void {
    this.entries.set(k, entry);
    let set = this.byMessage.get(mk);
    if (!set) this.byMessage.set(mk, (set = new Set()));
    set.add(k);
    this.emit();
  }

  /**
   * Download and verify one attachment. Resolves when it is ready or failed;
   * a second call while loading or ready does nothing, and a call after a
   * failure tries again.
   */
  async load(key: AttachmentKey, d: VerifiedDescriptor): Promise<AttachmentLoadState> {
    const k = entryKey(key, d.blobId);
    const mk = messageKey(key);
    const existing = this.entries.get(k);
    if (existing && (existing.state.status === 'loading' || existing.state.status === 'ready')) return existing.state;
    const controller = new AbortController();
    const entry: Entry = { state: { status: 'loading' }, controller };
    this.set(k, mk, entry);

    let plain: Uint8Array | null = null;
    try {
      const received = await this.deps.download(d.blobId, blobLength(d.paddedSize), controller.signal);
      plain = await openAttachment(received, d);
      received.fill(0);
    } catch (e) {
      if (this.entries.get(k) !== entry) return IDLE; // dropped meanwhile (REQ-24)
      entry.controller = null;
      entry.state = { status: 'error', error: controller.signal.aborted ? 'network' : classify(e) };
      this.emit();
      return entry.state;
    }
    if (this.entries.get(k) !== entry || controller.signal.aborted) {
      plain.fill(0);
      return IDLE;
    }
    // Verified: only now do the bytes become a Blob (REQ-5, REQ-22).
    const blob = new Blob([plain as Uint8Array<ArrayBuffer>], { type: blobTypeFor(d.mime) });
    plain.fill(0);
    const url = previewElementFor(d.mime) !== null ? this.deps.createObjectURL(blob) : null;
    entry.controller = null;
    entry.state = { status: 'ready', blob, url };
    this.emit();
    return entry.state;
  }

  /** REQ-24: abort a message's downloads, revoke its URLs and drop its bytes. */
  dropMessage(key: AttachmentKey): void {
    const mk = messageKey(key);
    const keys = this.byMessage.get(mk);
    if (!keys) return;
    this.byMessage.delete(mk);
    for (const k of keys) this.dropEntry(k);
    this.emit();
  }

  private dropEntry(k: string): void {
    const entry = this.entries.get(k);
    if (!entry) return;
    this.entries.delete(k);
    entry.controller?.abort();
    if (entry.state.status === 'ready' && entry.state.url !== null) this.deps.revokeObjectURL(entry.state.url);
  }

  /** Drop everything (logout, wipe). */
  clear(): void {
    for (const k of [...this.entries.keys()]) this.dropEntry(k);
    this.byMessage.clear();
    this.emit();
  }

  dispose(): void {
    this.clear();
    this.unsubscribeStore();
  }
}

/** The application's attachment views, bound to the application's store. */
export const attachmentViews = new AttachmentViews(
  {
    download: (id, expected, signal) => api.downloadAttachment(id, expected, signal),
    createObjectURL: blob => URL.createObjectURL(blob),
    revokeObjectURL: url => URL.revokeObjectURL(url),
  },
  attachmentStore,
);

// ---------------------------------------------------------------------------
// Saving (REQ-22, OD-47)
// ---------------------------------------------------------------------------

/** Saving is unavailable or failed; carries no name, path or bytes. */
export class AttachmentSaveError extends Error {
  constructor() {
    super(SAVE_FAILED_TEXT);
    this.name = 'AttachmentSaveError';
  }
}

/** The IPC header of the shell's `save_attachment` command (`desktop/src/save_attachment.rs`). */
export const SAVE_NAME_HEADER = 'x-accord-file-name';

type TauriInvoke = (cmd: string, args?: unknown, options?: { headers: Record<string, string> }) => Promise<unknown>;

/** True inside the Tauri shell (the webview has the shell's IPC internals). */
export function isTauriShell(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

function tauriInvoke(): TauriInvoke | null {
  const invoke = (window as unknown as { __TAURI__?: { core?: { invoke?: unknown } } }).__TAURI__?.core?.invoke;
  return typeof invoke === 'function' ? (invoke as TauriInvoke) : null;
}

/**
 * Save verified attachment bytes under a sender-chosen name, sanitized again
 * here (REQ-23). Resolves `saved`, or `cancelled` when the user dismissed the
 * shell's dialog. Rejects with `AttachmentSaveError` when saving is
 * unavailable or fails; there is no other mechanism to fall back to.
 */
export async function saveAttachment(name: string, blob: Blob): Promise<'saved' | 'cancelled'> {
  const safeName = sanitizeFileName(name).name;
  if (isTauriShell()) {
    const invoke = tauriInvoke();
    if (!invoke) throw new AttachmentSaveError();
    let result: unknown;
    try {
      const bytes = new Uint8Array(await blob.arrayBuffer());
      result = await invoke('save_attachment', bytes, { headers: { [SAVE_NAME_HEADER]: encodeURIComponent(safeName) } });
    } catch {
      throw new AttachmentSaveError();
    }
    if (result === true) return 'saved';
    if (result === false) return 'cancelled';
    throw new AttachmentSaveError();
  }
  // Relay-served web client: an anchor with `download` on an octet-stream URL.
  let url: string | null = null;
  try {
    url = URL.createObjectURL(new Blob([blob], { type: 'application/octet-stream' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = safeName;
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    a.remove();
  } catch {
    if (url !== null) URL.revokeObjectURL(url);
    throw new AttachmentSaveError();
  }
  const done = url;
  setTimeout(() => URL.revokeObjectURL(done), 30_000);
  return 'saved';
}
