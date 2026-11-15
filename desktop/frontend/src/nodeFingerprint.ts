/**
 * Node-scoped device fingerprint (SPEC-01 §6.9, REQ-43).
 *
 * device_fingerprint_hash = lowercase_hex(HMAC-SHA-256(
 *     key     = install_secret,
 *     message = UTF-8("accord-node-device-v1:" || node_id)))
 *
 * - `install_secret` is 32 bytes from the platform CSPRNG, generated once per
 *   installation and kept in localStorage under `accord_install_secret`
 *   (base64). It is per installation, not per account, so every account on this
 *   installation yields the same value for a node. It is never sent anywhere,
 *   and the panic wipe, duress and "Clear Local Data" remove it with the other
 *   `accord_` keys.
 * - `node_id` is the lowercase hyphenated UUID.
 * - Two nodes see unrelated values for the same installation, so node
 *   moderators cannot link a user's accounts across nodes by comparing them.
 *
 * Like every fingerprint it is supplied by the client and unauthenticated: it
 * only stops ban evasion by people who use an unmodified client on the same
 * installation. The relay treats it as opaque; a later construction would use
 * a new label.
 */

import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const INSTALL_SECRET_KEY = 'accord_install_secret';
export const NODE_FINGERPRINT_LABEL = 'accord-node-device-v1:';
const SECRET_LENGTH = 32;

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array | null {
  try {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The installation's secret, created on first use. Returns null when local
 * storage or the CSPRNG is unavailable; joins then go without a fingerprint.
 */
export function getInstallSecret(): Uint8Array | null {
  try {
    const stored = localStorage.getItem(INSTALL_SECRET_KEY);
    if (stored) {
      const bytes = fromBase64(stored);
      if (bytes && bytes.length === SECRET_LENGTH) return bytes;
    }
    const fresh = new Uint8Array(SECRET_LENGTH);
    crypto.getRandomValues(fresh);
    localStorage.setItem(INSTALL_SECRET_KEY, toBase64(fresh));
    return fresh;
  } catch {
    return null;
  }
}

/** The fingerprint of `nodeId` under `secret`: 64 lowercase hex characters. */
export function computeNodeFingerprint(secret: Uint8Array, nodeId: string): string {
  const message = new TextEncoder().encode(NODE_FINGERPRINT_LABEL + nodeId.toLowerCase());
  return toHex(hmac(sha256, secret, message));
}

/**
 * This installation's fingerprint for `nodeId`, or undefined when it cannot
 * be computed (the join then goes without one).
 */
export async function nodeDeviceFingerprint(nodeId: string): Promise<string | undefined> {
  const secret = getInstallSecret();
  if (!secret) return undefined;
  try {
    return computeNodeFingerprint(secret, nodeId);
  } catch {
    return undefined;
  }
}
