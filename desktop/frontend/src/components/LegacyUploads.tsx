/**
 * The "Legacy uploads" section of the Files panel (SPEC-02 REQ-27 to REQ-29,
 * §8.3). Hidden until the user turns it on for this session. Every item is
 * badged: the relay operator could have read or replaced it. Downloads ask
 * for confirmation first, decrypt with the decrypt-only legacy reader, and
 * release nothing when decryption fails. Items are never previewed, shown in
 * a message, staged in the composer or turned into version-2 attachments
 * (OD-40). The uploader is shown only as reported by the relay. After
 * `LEGACY_READ_UNTIL`, or once a legacy route answers 410, the section is
 * gone and no legacy route is called.
 *
 * This is the only module that imports `attachments/legacy.ts`.
 */

import { useCallback, useEffect, useState } from 'react';
import { api, LegacyRetiredError } from '../api';
import type { LegacyFileRow } from '../types';
import {
  decryptLegacyFile,
  decryptLegacyName,
  LEGACY_NAME_UNAVAILABLE,
  legacyReadAllowed,
  markLegacyRetired,
} from '../attachments/legacy';
import { SAVE_FAILED_TEXT, saveAttachment } from '../attachments/view';
import { AttachmentName } from './AttachmentName';
import { formatFileSize } from './MessageAttachments';

export const LEGACY_TOGGLE_TEXT = 'Show legacy uploads (not end-to-end encrypted)';
export const LEGACY_BADGE_TEXT = 'Legacy upload: the relay operator could have read or changed this file';
export const LEGACY_RETIRED_TEXT = 'Legacy uploads are no longer available';
export const LEGACY_DECRYPT_FAILED_TEXT = "Couldn't decrypt this legacy file";
const PAGE_SIZE = 50;

/** Session-scoped opt-in (REQ-27: hidden until turned on for the current session). */
let shownThisSession = false;

/** Tests only. */
export function resetLegacyToggleForTests(): void {
  shownThisSession = false;
}

interface LegacyItem {
  row: LegacyFileRow;
  /** Sanitized name, or null when unavailable. */
  name: string | null;
}

interface LegacyUploadsProps {
  channelId: string;
  keyPair: CryptoKeyPair | null;
  memberNames?: ReadonlyMap<string, string>;
  save?: typeof saveAttachment;
}

export function LegacyUploads({ channelId, keyPair, memberNames, save = saveAttachment }: LegacyUploadsProps) {
  const [shown, setShown] = useState(shownThisSession);
  const [items, setItems] = useState<LegacyItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(false);
  const [retired, setRetired] = useState(!legacyReadAllowed());
  const [confirming, setConfirming] = useState<LegacyItem | null>(null);
  const [itemError, setItemError] = useState<{ id: string; text: string } | null>(null);
  const [listError, setListError] = useState<string | null>(null);

  const privateKey = keyPair?.privateKey ?? null;

  const handleRetired = useCallback(() => {
    markLegacyRetired();
    setRetired(true);
    setItems([]);
  }, []);

  const loadPage = useCallback(async (before?: string) => {
    if (!legacyReadAllowed()) {
      setRetired(true);
      return;
    }
    setLoading(true);
    setListError(null);
    try {
      const rows = await api.listLegacyFiles(channelId, { limit: PAGE_SIZE, before });
      const named = await Promise.all(rows.map(async (row): Promise<LegacyItem> => ({
        row,
        name: await decryptLegacyName(privateKey, channelId, row.encrypted_filename),
      })));
      setItems(prev => (before ? [...prev, ...named] : named));
      setHasMore(rows.length === PAGE_SIZE);
    } catch (e) {
      if (e instanceof LegacyRetiredError) handleRetired();
      else setListError("Couldn't load legacy uploads");
    } finally {
      setLoading(false);
    }
  }, [channelId, privateKey, handleRetired]);

  useEffect(() => {
    setItems([]);
    if (shown && !retired) void loadPage();
    // Reload when the channel changes or the section is turned on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [channelId, shown]);

  const download = useCallback(async (item: LegacyItem) => {
    setConfirming(null);
    setItemError(null);
    if (!legacyReadAllowed()) {
      setRetired(true);
      return;
    }
    let plain: Uint8Array;
    try {
      const blob = await api.downloadLegacyFile(item.row.id);
      plain = await decryptLegacyFile(privateKey, channelId, blob);
    } catch (e) {
      if (e instanceof LegacyRetiredError) handleRetired();
      else setItemError({ id: item.row.id, text: LEGACY_DECRYPT_FAILED_TEXT });
      return;
    }
    try {
      await save(item.name ?? 'attachment', new Blob([plain as Uint8Array<ArrayBuffer>], { type: 'application/octet-stream' }));
    } catch {
      setItemError({ id: item.row.id, text: SAVE_FAILED_TEXT });
    } finally {
      plain.fill(0);
    }
  }, [privateKey, channelId, save, handleRetired]);

  if (retired) {
    return <div className="legacy-uploads legacy-uploads-retired" data-testid="legacy-uploads">{LEGACY_RETIRED_TEXT}</div>;
  }

  if (!shown) {
    return (
      <div className="legacy-uploads" data-testid="legacy-uploads">
        <button
          type="button"
          className="legacy-uploads-toggle"
          onClick={() => {
            shownThisSession = true;
            setShown(true);
          }}
        >
          {LEGACY_TOGGLE_TEXT}
        </button>
      </div>
    );
  }

  const last = items.length > 0 ? items[items.length - 1].row : null;
  return (
    <div className="legacy-uploads" data-testid="legacy-uploads">
      <div className="legacy-uploads-header">
        <span className="legacy-uploads-title">Legacy uploads</span>
        <button
          type="button"
          className="legacy-uploads-toggle"
          onClick={() => {
            shownThisSession = false;
            setShown(false);
          }}
        >
          Hide
        </button>
      </div>
      {loading && items.length === 0 && <div className="file-list-empty">Loading…</div>}
      {listError && <div className="file-list-empty" role="alert">{listError}</div>}
      {!loading && !listError && items.length === 0 && <div className="file-list-empty">No legacy uploads</div>}
      {items.map(item => {
        const uploader = memberNames?.get(item.row.uploader_id) ?? item.row.uploader_id;
        return (
          <div key={item.row.id} className="legacy-upload-item" data-testid="legacy-upload-item">
            <div className="legacy-upload-badge" role="note">{LEGACY_BADGE_TEXT}</div>
            <div className="legacy-upload-name">
              {item.name === null ? LEGACY_NAME_UNAVAILABLE : <AttachmentName name={item.name} />}
            </div>
            <div className="legacy-upload-meta">
              {formatFileSize(item.row.file_size_bytes)}
              {uploader && <> · Uploaded by {uploader}, according to the relay</>}
            </div>
            {itemError?.id === item.row.id && <div className="legacy-upload-error" role="alert">{itemError.text}</div>}
            <button type="button" className="legacy-upload-download" onClick={() => setConfirming(item)}>
              Download
            </button>
          </div>
        );
      })}
      {hasMore && last && (
        <button
          type="button"
          className="legacy-uploads-more"
          disabled={loading}
          onClick={() => void loadPage(`${last.created_at}:${last.id}`)}
        >
          Load more
        </button>
      )}
      {confirming && (
        <div className="legacy-confirm" role="dialog" aria-modal="true" aria-label="Download legacy upload">
          <p>{LEGACY_BADGE_TEXT}. Download it anyway?</p>
          <div className="legacy-confirm-actions">
            <button type="button" onClick={() => void download(confirming)}>Download</button>
            <button type="button" onClick={() => setConfirming(null)}>Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}
