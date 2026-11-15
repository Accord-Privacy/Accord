/**
 * @module attachments/sanitize
 * File-name sanitization (SPEC-02 REQ-23), the final-extension split and the
 * inline-preview allowlist (SPEC-02 §6.8).
 *
 * The Rust shell applies the same rules again before saving
 * (`accord_core::attachment::sanitize_file_name`).
 */

import { utf8ByteLength } from '../e2ee/plaintext';
import { MAX_NAME_BYTES } from './envelope';

/** Used when sanitization leaves nothing (REQ-23 step 7). */
export const FALLBACK_NAME = 'attachment';
/** At most this many code points follow the dot of a final extension (§6.8). */
export const MAX_EXTENSION_CODE_POINTS = 16;

// Step 2: White_Space. Step 3: Cc, Cf, Cs, Co, Cn and Default_Ignorable_Code_Point.
const WHITE_SPACE_RE = /\p{White_Space}/gu;
const REMOVED_RE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Cn}\p{Default_Ignorable_Code_Point}]/gu;
// Step 4.
const RESERVED_RE = /[/\\:<>"|?*]/g;

/** Replace every lone surrogate with U+FFFD (REQ-23 step 1, first half). */
function toWellFormed(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s[i] + s[i + 1];
        i++;
      } else out += '\uFFFD';
    } else if (c >= 0xdc00 && c <= 0xdfff) out += '\uFFFD';
    else out += s[i];
  }
  return out;
}

function trimSpacesAndDots(s: string): string {
  let a = 0;
  let b = s.length;
  while (a < b && (s[a] === ' ' || s[a] === '.')) a++;
  while (b > a && (s[b - 1] === ' ' || s[b - 1] === '.')) b--;
  return s.slice(a, b);
}

/**
 * The final extension of a sanitized name (§6.8): its last `.` and everything
 * after it, when that dot is not the first character and at most 16 code
 * points follow it. Null when there is none.
 */
export function finalExtension(name: string): string | null {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return null;
  const after = Array.from(name.slice(dot + 1)).length;
  return after <= MAX_EXTENSION_CODE_POINTS ? name.slice(dot) : null;
}

/** Split a sanitized name into stem and final extension (`ext` is '' when absent). */
export function splitFinalExtension(name: string): { stem: string; ext: string } {
  const ext = finalExtension(name);
  return ext === null ? { stem: name, ext: '' } : { stem: name.slice(0, name.length - ext.length), ext };
}

/** Truncate to at most `maxBytes` UTF-8 bytes on a code-point boundary. */
function truncateUtf8(s: string, maxBytes: number): string {
  let bytes = 0;
  let out = '';
  for (const cp of s) {
    const n = utf8ByteLength(cp);
    if (bytes + n > maxBytes) break;
    bytes += n;
    out += cp;
  }
  return out;
}

export interface SanitizedName {
  readonly name: string;
  /** True when sanitization changed the name (§8.2 tooltip). */
  readonly changed: boolean;
}

/**
 * Sanitize a sender-chosen file name before it is displayed or used as a
 * download or save name (REQ-23, steps 1 to 7 in order).
 */
export function sanitizeFileName(input: string): SanitizedName {
  // 1. Lone surrogates to U+FFFD, then NFC.
  let s = toWellFormed(input).normalize('NFC');
  // 2. White_Space to U+0020.
  s = s.replace(WHITE_SPACE_RE, ' ');
  // 3. Remove Cc, Cf, Cs, Co, Cn and Default_Ignorable_Code_Point.
  s = s.replace(REMOVED_RE, '');
  // 4. Reserved path and shell characters to '_'.
  s = s.replace(RESERVED_RE, '_');
  // 5. Collapse runs of U+0020, then trim U+0020 and dots at both ends.
  s = trimSpacesAndDots(s.replace(/ {2,}/g, ' '));
  // 6. At most 255 UTF-8 bytes, keeping the final extension.
  if (utf8ByteLength(s) > MAX_NAME_BYTES) {
    const ext = finalExtension(s);
    if (ext !== null) {
      const stem = s.slice(0, s.length - ext.length);
      s = truncateUtf8(stem, MAX_NAME_BYTES - utf8ByteLength(ext)) + ext;
    } else {
      s = truncateUtf8(s, MAX_NAME_BYTES);
    }
  }
  // 7. Fallback.
  if (s === '') s = FALLBACK_NAME;
  return { name: s, changed: s !== input };
}

// ---------------------------------------------------------------------------
// Preview allowlist (§6.8, REQ-22)
// ---------------------------------------------------------------------------

export type PreviewElement = 'img' | 'audio' | 'video';

export const PREVIEW_ALLOWLIST: Readonly<Record<string, PreviewElement>> = Object.freeze({
  'image/png': 'img',
  'image/jpeg': 'img',
  'image/gif': 'img',
  'image/webp': 'img',
  'audio/mpeg': 'audio',
  'audio/ogg': 'audio',
  'audio/wav': 'audio',
  'audio/webm': 'audio',
  'audio/aac': 'audio',
  'audio/flac': 'audio',
  'video/mp4': 'video',
  'video/webm': 'video',
});

/** The element an allowlisted MIME type previews in, or null (download only). */
export function previewElementFor(mime: string): PreviewElement | null {
  return Object.prototype.hasOwnProperty.call(PREVIEW_ALLOWLIST, mime) ? PREVIEW_ALLOWLIST[mime] : null;
}

/** The Blob type for attachment bytes: the MIME type if previewable, else octet-stream. */
export function blobTypeFor(mime: string): string {
  return previewElementFor(mime) ? mime : 'application/octet-stream';
}
