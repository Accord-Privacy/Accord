/**
 * Attachment UI of one message (SPEC-02 §5.4, §8.2), built only from the
 * attachment store (REQ-51), and only from the entry this message's own
 * decode produced (`attachments/render.ts`): a grid for two or more
 * allowlisted images, and a card for every other attachment. Previews come only from verified bytes
 * (REQ-5, REQ-21), only for the allowlist of §6.8 and only in `<img>`,
 * `<audio>` or `<video>` (REQ-22). Saving goes through `saveAttachment`.
 */

import { useCallback, useEffect, useState } from 'react';
import type { VerifiedAttachment, VerifiedDescriptor } from '../attachments/decode';
import type { AttachmentKey } from '../attachments/store';
import { useAttachmentState, useShownAttachments } from '../attachments/hooks';
import type { AttachmentBearer } from '../attachments/render';
import {
  attachmentViews,
  LOAD_ERROR_TEXT,
  previewFor,
  SAVE_FAILED_TEXT,
  saveAttachment,
  shouldAutoFetch,
  UNSUPPORTED_ATTACHMENT_TEXT,
  type AttachmentViews,
} from '../attachments/view';
import { AttachmentName } from './AttachmentName';
import { GRID_MAX_IMAGES, ImageGrid } from './ImageGrid';
import { Icon } from './Icon';

export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export interface AttachmentCardProps {
  entryKey: AttachmentKey;
  descriptor: VerifiedDescriptor;
  onImageClick?: (url: string) => void;
  /** Hide the inline preview (Files panel). */
  compact?: boolean;
  views?: AttachmentViews;
  save?: typeof saveAttachment;
}

/** One usable attachment: preview when allowed, name, size, Download. */
export function AttachmentCard({ entryKey, descriptor: d, onImageClick, compact = false, views = attachmentViews, save = saveAttachment }: AttachmentCardProps) {
  const state = useAttachmentState(entryKey, d.blobId, views);
  const kind = previewFor(d);
  const [saving, setSaving] = useState(false);
  const [saveFailed, setSaveFailed] = useState(false);

  useEffect(() => {
    if (!compact && state.status === 'idle' && shouldAutoFetch(d)) void views.load(entryKey, d);
  }, [compact, state.status, views, entryKey, d]);

  const onDownload = useCallback(async () => {
    setSaveFailed(false);
    setSaving(true);
    try {
      let s = views.get(entryKey, d.blobId);
      if (s.status !== 'ready') s = await views.load(entryKey, d);
      if (s.status !== 'ready') return; // the error state renders
      try {
        await save(d.name, s.blob);
      } catch {
        setSaveFailed(true);
      }
    } finally {
      setSaving(false);
    }
  }, [views, entryKey, d, save]);

  const failed = state.status === 'error' ? state.error : null;
  const url = state.status === 'ready' ? state.url : null;
  const busy = saving || state.status === 'loading';

  return (
    <div className={`file-attachment${failed ? ' file-attachment-error' : ''}`} data-testid="attachment-card">
      {!compact && url && kind === 'img' && (
        <div className="file-attachment-image-preview">
          <img src={url} alt="" onClick={onImageClick ? (e) => { e.stopPropagation(); onImageClick(url); } : undefined} />
        </div>
      )}
      {!compact && url && kind === 'audio' && (
        <div className="file-attachment-audio-preview">
          <audio controls preload="metadata" src={url} />
        </div>
      )}
      {!compact && url && kind === 'video' && (
        <div className="file-attachment-video-preview">
          <video controls preload="metadata" src={url} />
        </div>
      )}
      <div className="file-attachment-info">
        <span className="file-attachment-icon"><Icon name="clipboard" size={18} /></span>
        <div className="file-attachment-details">
          <span className="file-attachment-name"><AttachmentName name={d.name} /></span>
          <span className="file-attachment-size">{formatFileSize(d.size)}</span>
          {failed && (
            <span className="file-attachment-status" role="alert">
              {LOAD_ERROR_TEXT[failed]}
              {failed === 'network' && (
                <button type="button" className="file-attachment-retry" onClick={() => void views.load(entryKey, d)}>Retry</button>
              )}
            </span>
          )}
          {saveFailed && <span className="file-attachment-status" role="alert">{SAVE_FAILED_TEXT}</span>}
        </div>
        {failed !== 'integrity' && failed !== 'unavailable' && (
          <button
            type="button"
            className="file-attachment-download"
            onClick={() => void onDownload()}
            disabled={busy}
            title="Download"
            aria-label="Download attachment"
          >
            <Icon name={busy ? 'clock' : 'download'} size={16} />
          </button>
        )}
      </div>
    </div>
  );
}

/** An attachment whose descriptor failed validation or names an unknown version (REQ-9). */
export function UnsupportedAttachment() {
  return (
    <div className="file-attachment file-attachment-unsupported" data-testid="attachment-unsupported">
      <span className="file-attachment-icon"><Icon name="clipboard" size={18} /></span>
      <span className="file-attachment-status">{UNSUPPORTED_ATTACHMENT_TEXT}</span>
    </div>
  );
}

export interface MessageAttachmentsProps {
  /** The rendered message; its own decode decides what it shows. */
  message: AttachmentBearer;
  /** Relay origin of the attachment store keys. */
  origin: string;
  onImageClick?: (url: string) => void;
  views?: AttachmentViews;
  save?: typeof saveAttachment;
}

function isGridImage(a: VerifiedAttachment): a is { usable: true; descriptor: VerifiedDescriptor } {
  return a.usable && previewFor(a.descriptor) === 'img';
}

/** The attachments of one message, read from the attachment store. */
export function MessageAttachments({ message, origin, onImageClick, views = attachmentViews, save = saveAttachment }: MessageAttachmentsProps) {
  const entry = useShownAttachments(message, origin);
  if (!entry || entry.attachments.length === 0) return null;
  const entryKey = entry.key;
  const images = entry.attachments.filter(isGridImage).slice(0, GRID_MAX_IMAGES);
  const grid = images.length >= 2 ? new Set(images.map(a => a.descriptor.blobId)) : null;
  return (
    <>
      {grid && (
        <ImageGrid
          entryKey={entryKey}
          images={images.map(a => a.descriptor)}
          onImageClick={onImageClick}
          views={views}
        />
      )}
      <div className="message-attachments">
        {entry.attachments.map((a, i) =>
          a.usable ? (
            <AttachmentCard
              key={a.descriptor.blobId}
              entryKey={entryKey}
              descriptor={a.descriptor}
              onImageClick={onImageClick}
              compact={grid !== null && grid.has(a.descriptor.blobId)}
              views={views}
              save={save}
            />
          ) : (
            <UnsupportedAttachment key={`unsupported-${i}`} />
          ),
        )}
      </div>
    </>
  );
}
