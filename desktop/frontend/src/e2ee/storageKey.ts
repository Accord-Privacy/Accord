/**
 * @module storageKey
 * Storage Master Key (SMK) — at-rest key hardening.
 *
 * Local encrypted stores (identity keys, sender keys, NMK, the own/DM message
 * plaintext cache) used to derive their AES key from SHA-256(password‖domain):
 * a single unsalted hash over a possibly-weak password (audit finding L1).
 *
 * The SMK is a per-user random 256-bit secret held in the OS keyring. We mix
 * it in as the HKDF salt when deriving every at-rest key, making at-rest
 * encryption *two-factor*:
 *   at-rest key = HKDF-SHA256(ikm = password, salt = SMK, info = domain)
 * Deriving anything now requires BOTH the password (knowledge) AND the SMK
 * (possession of this device's keyring). A locked, seized device cannot
 * recover history without the password; a leaked password is useless without
 * the device secret. Even a weak password resists offline brute force because
 * the attacker also needs the 256-bit keyring secret.
 *
 * On the web build there is no OS keyring, so the SMK is unavailable and we
 * fall back to the legacy password-only derivation (web is already documented
 * as a residual-risk surface). The desktop app is the security-critical target.
 */

// @ts-ignore - noble v2 uses .js exports
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';

let cachedSmk: Uint8Array | null = null;

function isTauri(): boolean {
  return typeof window !== 'undefined' && !!(window as any).__TAURI__;
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Fetch (creating on first use) the user's storage master key from the OS
 * keyring and cache it in memory. Must be called at login, before any store
 * load/save. No-op that leaves the SMK unavailable on the web build.
 */
export async function initStorageMasterKey(userId: string): Promise<void> {
  if (!isTauri()) {
    cachedSmk = null;
    return;
  }
  try {
    const b64: string = await (window as any).__TAURI__.core.invoke('get_or_create_smk', { userId });
    cachedSmk = fromBase64(b64);
  } catch (e) {
    console.warn('[storageKey] SMK unavailable, falling back to password-only at-rest keys:', e);
    cachedSmk = null;
  }
}

/** The cached SMK bytes, or null (web build / not yet initialised). */
export function getStorageSalt(): Uint8Array | null {
  return cachedSmk;
}

/** Whether two-factor at-rest keys are active (SMK present). */
export function hasStorageMasterKey(): boolean {
  return cachedSmk !== null;
}

/** Zeroize and drop the cached SMK (logout). Does not delete it from keyring. */
export function clearStorageMasterKey(): void {
  if (cachedSmk) cachedSmk.fill(0);
  cachedSmk = null;
}

/** Permanently delete the SMK from the keyring (account deletion / panic-wipe). */
export async function destroyStorageMasterKey(userId: string): Promise<void> {
  clearStorageMasterKey();
  if (!isTauri()) return;
  try {
    await (window as any).__TAURI__.core.invoke('delete_smk', { userId });
  } catch (e) {
    console.warn('[storageKey] failed to delete SMK from keyring:', e);
  }
}

/**
 * Derive a 32-byte at-rest key for a store `domain`.
 *  - SMK present  → HKDF-SHA256(ikm=password, salt=SMK, info=domain)  [v2]
 *  - SMK absent   → SHA-256(password‖domain)                          [legacy]
 * `forceLegacy` reproduces the old scheme regardless, for reading/ migrating
 * data written before the SMK existed.
 */
export function deriveAtRestKey(password: string, domain: string, forceLegacy = false): Uint8Array {
  const passBytes = new TextEncoder().encode(password);
  if (!forceLegacy && cachedSmk) {
    const info = new TextEncoder().encode(domain);
    return hkdf(sha256, passBytes, cachedSmk, info, 32);
  }
  const domainBytes = new TextEncoder().encode(domain);
  const material = new Uint8Array(passBytes.length + domainBytes.length);
  material.set(passBytes, 0);
  material.set(domainBytes, passBytes.length);
  return sha256(material);
}

/** Whether a stored blob uses the v2 (SMK/HKDF) scheme, by its version tag. */
export const AT_REST_V2_TAG = 0x02;
