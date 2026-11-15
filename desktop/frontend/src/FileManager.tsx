/**
 * Composer file staging and the Files panel (SPEC-02).
 *
 * Staging only: picking or dropping files stages them in the composer, where
 * the send module seals and uploads them with the message (`attachments/
 * send.ts`). Nothing here reads, encrypts or uploads a file, and nothing here
 * uses the channel-derived key (REQ-17).
 *
 * The Files panel lists version-2 attachments only from the attachment store,
 * built from decrypted descriptors, and never asks the relay for a list
 * (REQ-26, OD-42). Legacy uploads live in their own opt-in section
 * (`components/LegacyUploads.tsx`, REQ-27).
 */

import React, { useState, useRef, useCallback } from 'react';
import { Icon } from './components/Icon';
import { AttachmentCard, formatFileSize } from './components/MessageAttachments';
import { LegacyUploads } from './components/LegacyUploads';
import { AttachmentName } from './components/AttachmentName';
import { useShownChannelAttachments } from './attachments/hooks';
import type { AttachmentBearer } from './attachments/render';
import { previewElementFor } from './attachments/sanitize';
import type { VerifiedDescriptor } from './attachments/decode';
import type { AttachmentKey } from './attachments/store';
import type { AttachmentViews, saveAttachment } from './attachments/view';

export interface StagedFile {
  file: File;
  /** A `blob:` URL of the user's own local image, for the staging preview only. */
  previewUrl?: string;
  name: string;
  /** Why this file cannot be sent (REQ-16), shown on the staged item. */
  error?: string;
}

/** The tooltip of the disabled attach control (SPEC-02 §8.1, REQ-17). */
export const ATTACHMENTS_UNAVAILABLE_TEXT = 'This relay must be updated to send end-to-end encrypted attachments';

/** Stage picked or dropped files; previews only for allowlisted local images. */
export function stageFiles(files: FileList | readonly File[]): StagedFile[] {
  const staged: StagedFile[] = [];
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const previewUrl = previewElementFor((file.type || '').toLowerCase()) === 'img' ? URL.createObjectURL(file) : undefined;
    staged.push({ file, previewUrl, name: file.name });
  }
  return staged;
}

// =================== File Upload Button ===================
interface FileUploadButtonProps {
  onFilesStaged: (files: StagedFile[]) => void;
  /** Attachment sending is disabled (relay without `attachments/2`). */
  disabled?: boolean;
  disabledReason?: string;
}

export const FileUploadButton: React.FC<FileUploadButtonProps> = ({ onFilesStaged, disabled = false, disabledReason }) => {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files;
    if (!selected || selected.length === 0) return;
    onFilesStaged(stageFiles(selected));
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="file-upload-wrapper">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        onChange={handleFileChange}
        style={{ display: 'none' }}
        disabled={disabled}
      />
      <button
        type="button"
        onClick={() => fileInputRef.current?.click()}
        disabled={disabled}
        className="file-upload-btn"
        title={disabled ? (disabledReason ?? ATTACHMENTS_UNAVAILABLE_TEXT) : 'Attach file'}
        aria-label={disabled ? (disabledReason ?? ATTACHMENTS_UNAVAILABLE_TEXT) : 'Attach file'}
      >
        <Icon name="plus" size={20} />
      </button>
    </div>
  );
};

// =================== Drag & Drop Wrapper ===================
interface DropZoneProps {
  children: React.ReactNode;
  onFilesStaged: (files: StagedFile[]) => void;
  disabled?: boolean;
}

export const FileDropZone: React.FC<DropZoneProps> = ({ children, onFilesStaged, disabled = false }) => {
  const [isDragging, setIsDragging] = useState(false);
  const dragCounter = useRef(0);

  const handleDragEnter = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current++;
    if (!disabled && e.dataTransfer.items && e.dataTransfer.items.length > 0) setIsDragging(true);
  }, [disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current--;
    if (dragCounter.current === 0) setIsDragging(false);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    dragCounter.current = 0;
    if (disabled) return;
    const files = e.dataTransfer.files;
    if (!files || files.length === 0) return;
    onFilesStaged(stageFiles(files));
  }, [onFilesStaged, disabled]);

  return (
    <div
      className="file-drop-zone"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {children}
      {isDragging && (
        <div className="file-drop-overlay">
          <div className="file-drop-overlay-content">
            <span className="file-drop-icon"><Icon name="folder" size={48} /></span>
            <span>Drop files to attach</span>
          </div>
        </div>
      )}
    </div>
  );
};

// =================== Staged Files Preview ===================
interface StagedFilesPreviewProps {
  files: StagedFile[];
  onRemove: (index: number) => void;
  onClear: () => void;
}

export const StagedFilesPreview: React.FC<StagedFilesPreviewProps> = ({ files, onRemove, onClear }) => {
  if (files.length === 0) return null;
  return (
    <div className="staged-files-preview">
      <div className="staged-files-header">
        <span className="staged-files-count">{files.length} file{files.length > 1 ? 's' : ''} attached</span>
        <button className="staged-files-clear" onClick={onClear} title="Remove all">✕</button>
      </div>
      <div className="staged-files-list">
        {files.map((sf, index) => (
          <div key={index} className={`staged-file-item${sf.error ? ' staged-file-error' : ''}`}>
            {sf.previewUrl ? (
              <img src={sf.previewUrl} alt="" className="staged-file-thumb" />
            ) : (
              <span className="staged-file-icon"><Icon name="clipboard" size={16} /></span>
            )}
            <span className="staged-file-name"><AttachmentName name={sf.name} /></span>
            <span className="staged-file-size">{formatFileSize(sf.file.size)}</span>
            {sf.error && <span className="staged-file-error-text" role="alert">{sf.error}</span>}
            <button className="staged-file-remove" onClick={() => onRemove(index)} title="Remove">✕</button>
          </div>
        ))}
      </div>
    </div>
  );
};

// =================== Files panel ===================
interface FileListProps {
  /** Relay origin of the attachment store keys. */
  origin: string;
  channelId: string;
  /** The channel's loaded messages; only their own decoded attachments are listed. */
  messages: readonly AttachmentBearer[];
  /** The relay advertises `attachments/2`; the legacy section needs it (§7.3). */
  attachmentsAvailable: boolean;
  /** For the legacy reader only. */
  keyPair: CryptoKeyPair | null;
  /** Display names for the legacy uploader label, by user id. */
  memberNames?: ReadonlyMap<string, string>;
  /** Download state (tests inject their own). */
  views?: AttachmentViews;
  save?: typeof saveAttachment;
}

/**
 * The Files panel: every attachment of this channel's loaded, decrypted
 * messages (REQ-26), each shown only for the message whose own decode
 * produced it (`attachments/render.ts`), and the opt-in legacy section. A
 * recipient sees only attachments of messages it decrypted (C022, C023).
 */
export const FileList: React.FC<FileListProps> = ({ origin, channelId, messages, attachmentsAvailable, keyPair, memberNames, views, save }) => {
  const [isVisible, setIsVisible] = useState(false);
  const entries = useShownChannelAttachments(messages, origin, isVisible ? channelId : null);
  const items: { key: AttachmentKey; d: VerifiedDescriptor }[] = [];
  for (const e of entries) {
    for (const a of e.attachments) if (a.usable) items.push({ key: e.key, d: a.descriptor });
  }

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        type="button"
        onClick={() => setIsVisible(v => !v)}
        className="file-list-toggle-btn"
        title="Show files"
        aria-label="Show files"
      >
        <Icon name="folder" size={18} />
      </button>

      {isVisible && (
        <div className="file-list-panel" data-testid="files-panel">
          <div className="file-list-header">
            <div className="file-list-title">Channel Files</div>
            <button className="file-list-close" onClick={() => setIsVisible(false)}>✕</button>
          </div>
          {items.length === 0 ? (
            <div className="file-list-empty">No files in the messages loaded here</div>
          ) : (
            <div className="file-list-items">
              {items.map(({ key, d }) => (
                <AttachmentCard key={`${key.messageId}:${d.blobId}`} entryKey={key} descriptor={d} compact views={views} save={save} />
              ))}
            </div>
          )}
          {attachmentsAvailable && (
            <LegacyUploads channelId={channelId} keyPair={keyPair} memberNames={memberNames} />
          )}
        </div>
      )}
    </div>
  );
};
