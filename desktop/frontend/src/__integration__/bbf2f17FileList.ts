/**
 * The Files panel list of the client at bbf2f17, for the RG-C164 (b) replay
 * (SPEC-02 §10.3): the markup of `FileList` (FileManager.tsx:631-649 at
 * bbf2f17) and the helpers it called (FileManager.tsx:659-705), copied
 * verbatim except for JSX written as `createElement`, so that both the jsdom
 * unit tests and the Node two-client tests can render it.
 *
 * It takes the relay's `GET /channels/{id}/files` JSON as `unknown`, exactly
 * as the old client did (`api.getChannelFiles` cast the JSON to
 * `FileMetadata[]` without checking it). With the bbf2f17 relay, which sent
 * `encrypted_filename` as a JSON array of bytes, `getFileTypeIcon` called
 * `split` on an array and the panel crashed (C164).
 */

import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

// ---- verbatim from FileManager.tsx at bbf2f17 -----------------------------

function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function getFileTypeIcon(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)) return '🖼️';
  if (['mp4', 'webm', 'mov', 'avi'].includes(ext)) return '🎬';
  if (['mp3', 'wav', 'ogg', 'flac', 'aac'].includes(ext)) return '🎵';
  if (['pdf'].includes(ext)) return '📕';
  if (['zip', 'tar', 'gz', 'rar', '7z'].includes(ext)) return '📦';
  if (['doc', 'docx', 'txt', 'md', 'rtf'].includes(ext)) return '📄';
  if (['xls', 'xlsx', 'csv'].includes(ext)) return '📊';
  if (['js', 'ts', 'py', 'rs', 'go', 'c', 'cpp', 'h', 'java'].includes(ext)) return '💻';
  if (['json', 'yaml', 'yml', 'toml', 'xml'].includes(ext)) return '⚙️';
  return '📎';
}

const formatTimestamp = (timestamp: number): string => {
  const date = new Date(timestamp * 1000);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
  });
};

// ---------------------------------------------------------------------------

/** The bbf2f17 `FileMetadata`, as the old client assumed the JSON to be. */
interface FileMetadata {
  id: string;
  encrypted_filename: string;
  file_size_bytes: number;
  created_at: number;
}

/** The list the bbf2f17 Files panel rendered for `files` (unchecked relay JSON). */
function OldFileListItems({ files }: { files: unknown }) {
  return createElement(
    'div',
    { className: 'file-list-items' },
    (files as FileMetadata[]).map(file =>
      createElement(
        'div',
        { key: file.id, className: 'file-list-item' },
        createElement('div', { className: 'file-list-item-icon' }, getFileTypeIcon(file.encrypted_filename)),
        createElement(
          'div',
          { className: 'file-list-item-info' },
          createElement('div', { className: 'file-list-item-name' }, file.encrypted_filename),
          createElement('div', { className: 'file-list-item-meta' }, formatFileSize(file.file_size_bytes), ' • ', formatTimestamp(file.created_at)),
        ),
        createElement(
          'div',
          { className: 'file-list-item-actions' },
          createElement('button', { className: 'file-list-item-download', title: 'Download' }, '⬇'),
          createElement('button', { className: 'file-list-item-delete', title: 'Delete' }),
        ),
      ),
    ),
  );
}

/** Render the bbf2f17 list for relay JSON; throws where the old panel crashed. */
export function renderOldFileList(json: unknown): string {
  return renderToStaticMarkup(createElement(OldFileListItems, { files: json }));
}

/** The names the old panel showed, one per row, read back from its markup. */
export function oldFileListNames(markup: string): string[] {
  return [...markup.matchAll(/<div class="file-list-item-name">([^<]*)<\/div>/g)].map(m => m[1]);
}
