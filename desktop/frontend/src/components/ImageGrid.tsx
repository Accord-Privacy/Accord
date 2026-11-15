/**
 * A grid for two or more allowlisted images of one message (SPEC-02 §6.8).
 * Works only from verified descriptors in the attachment store: each image is
 * downloaded, verified and shown from a `blob:` URL of its allowlisted type,
 * never from raw bytes (REQ-21, REQ-22). Images above the automatic preview
 * limit are not fetched until the user asks (REQ-25).
 */

import { useEffect } from 'react';
import type { VerifiedDescriptor } from '../attachments/decode';
import type { AttachmentKey } from '../attachments/store';
import { useAttachmentState } from '../attachments/hooks';
import { attachmentViews, LOAD_ERROR_TEXT, previewFor, shouldAutoFetch, type AttachmentViews } from '../attachments/view';

interface ImageGridProps {
  entryKey: AttachmentKey;
  /** Usable descriptors whose MIME type previews as `<img>`. */
  images: readonly VerifiedDescriptor[];
  onImageClick?: (src: string) => void;
  views?: AttachmentViews;
}

/** At most this many images go in the grid; the rest are shown as cards. */
export const GRID_MAX_IMAGES = 4;

function GridImage({ entryKey, d, onImageClick, views }: {
  entryKey: AttachmentKey;
  d: VerifiedDescriptor;
  onImageClick?: (src: string) => void;
  views: AttachmentViews;
}) {
  const state = useAttachmentState(entryKey, d.blobId, views);
  useEffect(() => {
    if (state.status === 'idle' && shouldAutoFetch(d)) void views.load(entryKey, d);
  }, [state.status, views, entryKey, d]);
  const url = state.status === 'ready' ? state.url : null;
  return (
    <div
      className="grid-image"
      onClick={url && onImageClick ? (e) => { e.stopPropagation(); onImageClick(url); } : undefined}
    >
      {url ? (
        <img src={url} alt="" loading="lazy" />
      ) : state.status === 'error' ? (
        <div className="grid-image-error" role="alert">{LOAD_ERROR_TEXT[state.error]}</div>
      ) : state.status === 'idle' ? (
        <button type="button" className="grid-image-load" onClick={(e) => { e.stopPropagation(); void views.load(entryKey, d); }}>
          Load image
        </button>
      ) : (
        <div className="grid-image-loading" aria-busy="true" />
      )}
    </div>
  );
}

export function ImageGrid({ entryKey, images, onImageClick, views = attachmentViews }: ImageGridProps) {
  const shown = images.filter(d => previewFor(d) === 'img').slice(0, GRID_MAX_IMAGES);
  if (shown.length < 2) return null;
  return (
    <div className={`message-image-grid grid-${shown.length}`}>
      {shown.map(d => (
        <GridImage key={d.blobId} entryKey={entryKey} d={d} onImageClick={onImageClick} views={views} />
      ))}
    </div>
  );
}
