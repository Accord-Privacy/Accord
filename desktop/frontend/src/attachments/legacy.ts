/**
 * @module attachments/legacy
 * The decrypt-only reader for legacy uploads (SPEC-02 §5.5, REQ-27 to REQ-29).
 *
 * Legacy files were encrypted under SHA-256("<channelId>:accord-channel-key-v1"),
 * which the relay can compute, so the relay operator could have read or
 * replaced every one of them. This module only decrypts; nothing in the client
 * encrypts under that key any more (REQ-17). Only the legacy section of the
 * Files panel (`components/LegacyUploads.tsx`) imports it, and it is the only
 * remaining file-path user of `getChannelKey`. C2 deletes it (§7.7).
 *
 * Legacy items are never previewed, shown in a message, attached to a message
 * or turned into version-2 attachments (REQ-27, OD-40). A failed decryption
 * releases no bytes (REQ-28).
 */

import { gcm } from '@noble/ciphers/aes.js';
import { getChannelKey, decryptMessage } from '../crypto';
import { sanitizeFileName } from './sanitize';

/** Shown for an empty legacy name or one that fails to decrypt (REQ-28). */
export const LEGACY_NAME_UNAVAILABLE = '(name unavailable)';

/** Legacy layout: 12-byte IV ‖ ciphertext ‖ 16-byte tag. */
const IV_SIZE = 12;
const TAG_SIZE = 16;

async function channelKey(privateKey: CryptoKey | null, channelId: string): Promise<Uint8Array> {
  // The derivation ignores the private key (SPEC-02 §4.1): the channel id
  // alone determines it, which is exactly why these files are relay-readable.
  const key = await getChannelKey(privateKey as CryptoKey, channelId);
  if (!(key instanceof Uint8Array)) throw new Error('legacy channel key unavailable');
  return key;
}

/** A legacy file that failed to decrypt. Carries no received bytes. */
export class LegacyDecryptError extends Error {
  constructor() {
    super("Couldn't decrypt this legacy file");
    this.name = 'LegacyDecryptError';
  }
}

/**
 * Decrypt a legacy name. Returns the sanitized name (REQ-23), or null when the
 * stored name is empty or does not decrypt; callers then show
 * `LEGACY_NAME_UNAVAILABLE`.
 */
export async function decryptLegacyName(privateKey: CryptoKey | null, channelId: string, encryptedName: string): Promise<string | null> {
  if (typeof encryptedName !== 'string' || encryptedName === '') return null;
  try {
    const name = await decryptMessage(await channelKey(privateKey, channelId), encryptedName);
    if (name === '') return null;
    return sanitizeFileName(name).name;
  } catch {
    return null;
  }
}

/**
 * Decrypt a legacy blob. Throws `LegacyDecryptError` on any failure, after
 * which no byte of the input or the output may be used (REQ-28).
 */
export async function decryptLegacyFile(privateKey: CryptoKey | null, channelId: string, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length < IV_SIZE + TAG_SIZE) throw new LegacyDecryptError();
  try {
    const key = await channelKey(privateKey, channelId);
    return gcm(key, blob.slice(0, IV_SIZE)).decrypt(blob.slice(IV_SIZE));
  } catch {
    throw new LegacyDecryptError();
  }
}

// ---------------------------------------------------------------------------
// Availability (REQ-29)
// ---------------------------------------------------------------------------

/**
 * The compile-time end of the legacy read window, `VITE_ACCORD_LEGACY_READ_UNTIL`
 * (an ISO date, `YYYY-MM-DD`, UTC midnight). Every release build sets it; the
 * build fails while it is unset (`vite.config.ts`). Development and test
 * builds may leave it unset, which means no compile-time cutoff; a relay's 410
 * still retires the section.
 */
export function legacyReadUntil(raw: string | undefined = import.meta.env.VITE_ACCORD_LEGACY_READ_UNTIL): number | null {
  if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(raw)) return null;
  const t = Date.parse(`${raw}T00:00:00Z`);
  return Number.isFinite(t) ? t : null;
}

let retiredThisSession = false;

/** Record a 410 from a legacy route: the section stays hidden for this session. */
export function markLegacyRetired(): void {
  retiredThisSession = true;
}

/** Whether a legacy route answered 410 in this session. */
export function legacyRetired(): boolean {
  return retiredThisSession;
}

/**
 * Whether the client may still show the legacy section and call legacy
 * routes: not after `LEGACY_READ_UNTIL`, and not after a 410 (REQ-29).
 */
export function legacyReadAllowed(now: number = Date.now(), until: number | null = legacyReadUntil()): boolean {
  if (retiredThisSession) return false;
  return until === null || now < until;
}

/** Tests only: forget a recorded 410. */
export function resetLegacyStateForTests(): void {
  retiredThisSession = false;
}
