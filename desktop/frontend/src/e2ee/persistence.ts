/**
 * @module persistence
 * Encrypted persistence for E2EE identity keys and sender key store.
 *
 * At-rest keys come from ./storageKey (deriveAtRestKey): two-factor
 * HKDF(password, salt = OS-keyring SMK) on desktop, legacy SHA-256(password‖
 * domain) on web. Blobs written with the SMK carry a 1-byte version tag so
 * legacy data still reads and is migrated to v2 on the next save.
 */

// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';

import type { IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair } from './keys';
import { SenderKeyStore } from './senderKeys';
import { deriveAtRestKey, hasStorageMasterKey, AT_REST_V2_TAG } from './storageKey';

// ─── Constants ──────────────────────────────────────────────────────────────

const IDENTITY_STORAGE_PREFIX = 'accord_e2ee_identity_';
const SENDERKEYS_STORAGE_PREFIX = 'accord_e2ee_senderkeys_';
const OWNMSGS_STORAGE_PREFIX = 'accord_e2ee_ownmsgs_';
const IDENTITY_DOMAIN = 'accord-e2ee-identity-storage';
const SENDERKEYS_DOMAIN = 'accord-e2ee-senderkeys-storage';
const OWNMSGS_DOMAIN = 'accord-e2ee-ownmsgs-storage';

// ─── Helpers ────────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function toBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encryptData(data: string, password: string, domain: string): string {
  const key = deriveAtRestKey(password, domain);
  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(data);
  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(plaintext);
  if (hasStorageMasterKey()) {
    // v2: [tag][iv(12)][ct]
    const combined = new Uint8Array(1 + 12 + ciphertext.length);
    combined[0] = AT_REST_V2_TAG;
    combined.set(iv, 1);
    combined.set(ciphertext, 13);
    return toBase64(combined);
  }
  // legacy (web, no SMK): [iv(12)][ct]
  const combined = new Uint8Array(12 + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, 12);
  return toBase64(combined);
}

function decryptData(encrypted: string, password: string, domain: string): string {
  const combined = fromBase64(encrypted);
  // v2 blobs are tag-prefixed. Try v2 first when tagged; the GCM auth tag makes
  // a misread (a legacy blob whose first byte happens to be the tag) safe — it
  // fails authentication and we fall back to the legacy layout.
  if (combined[0] === AT_REST_V2_TAG) {
    try {
      const key = deriveAtRestKey(password, domain);
      const iv = combined.slice(1, 13);
      const ciphertext = combined.slice(13);
      return new TextDecoder().decode(gcm(key, iv).decrypt(ciphertext));
    } catch {
      // fall through to legacy interpretation
    }
  }
  const key = deriveAtRestKey(password, domain, /* forceLegacy */ true);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  return new TextDecoder().decode(gcm(key, iv).decrypt(ciphertext));
}

// ─── Identity Key Persistence ───────────────────────────────────────────────

export interface StoredIdentityKeys {
  identityKeyPair: IdentityKeyPair;
  signedPreKey: SignedPreKeyPair;
  oneTimePreKeys: OneTimePreKeyPair[];
}

function identityStorageKey(userId: string): string {
  return `${IDENTITY_STORAGE_PREFIX}${userId}`;
}

function senderKeysStorageKey(userId: string): string {
  return `${SENDERKEYS_STORAGE_PREFIX}${userId}`;
}

function ownMessagesStorageKey(userId: string): string {
  return `${OWNMSGS_STORAGE_PREFIX}${userId}`;
}

/**
 * Save E2EE identity keys to localStorage, encrypted with password.
 */
export function saveIdentityKeys(
  userId: string,
  keys: StoredIdentityKeys,
  password: string,
): void {
  const serialized = JSON.stringify({
    identityKeyPair: {
      privateKey: toBase64(keys.identityKeyPair.privateKey),
      publicKey: toBase64(keys.identityKeyPair.publicKey),
    },
    signedPreKey: {
      privateKey: toBase64(keys.signedPreKey.privateKey),
      publicKey: toBase64(keys.signedPreKey.publicKey),
    },
    oneTimePreKeys: keys.oneTimePreKeys.map(k => ({
      privateKey: toBase64(k.privateKey),
      publicKey: toBase64(k.publicKey),
    })),
  });
  const encrypted = encryptData(serialized, password, IDENTITY_DOMAIN);
  localStorage.setItem(identityStorageKey(userId), encrypted);
}

/**
 * Load E2EE identity keys from localStorage.
 * Returns null if not found or decryption fails.
 */
export function loadIdentityKeys(
  userId: string,
  password: string,
): StoredIdentityKeys | null {
  try {
    const encrypted = localStorage.getItem(identityStorageKey(userId));
    if (!encrypted) return null;
    const json = decryptData(encrypted, password, IDENTITY_DOMAIN);
    const data = JSON.parse(json);
    return {
      identityKeyPair: {
        privateKey: fromBase64(data.identityKeyPair.privateKey),
        publicKey: fromBase64(data.identityKeyPair.publicKey),
      },
      signedPreKey: {
        privateKey: fromBase64(data.signedPreKey.privateKey),
        publicKey: fromBase64(data.signedPreKey.publicKey),
      },
      oneTimePreKeys: (data.oneTimePreKeys || []).map((k: any) => ({
        privateKey: fromBase64(k.privateKey),
        publicKey: fromBase64(k.publicKey),
      })),
    };
  } catch (e) {
    console.warn('Failed to load E2EE identity keys:', e);
    return null;
  }
}

// ─── SenderKeyStore Persistence ─────────────────────────────────────────────

/**
 * Save SenderKeyStore to localStorage, encrypted with password.
 */
export function saveSenderKeyStore(
  userId: string,
  store: SenderKeyStore,
  password: string,
): void {
  try {
    const serialized = JSON.stringify(store.exportStore());
    const encrypted = encryptData(serialized, password, SENDERKEYS_DOMAIN);
    localStorage.setItem(senderKeysStorageKey(userId), encrypted);
  } catch (e) {
    console.warn('Failed to save sender key store:', e);
  }
}

/**
 * Load SenderKeyStore from localStorage.
 * Returns null if not found or decryption fails.
 */
export function loadSenderKeyStore(
  userId: string,
  password: string,
): SenderKeyStore | null {
  try {
    const encrypted = localStorage.getItem(senderKeysStorageKey(userId));
    if (!encrypted) return null;
    const json = decryptData(encrypted, password, SENDERKEYS_DOMAIN);
    const data = JSON.parse(json);
    const store = new SenderKeyStore();
    store.importStore(data);
    return store;
  } catch (e) {
    console.warn('Failed to load sender key store:', e);
    return null;
  }
}

// ─── Own-message plaintext cache ──────────────────────────────────────────────
// With sender keys, the author cannot decrypt their own channel messages (their
// key lives in `myKeys`, not `peerKeys`, and the chain has ratcheted forward).
// We keep the plaintext of our own sent messages, encrypted at rest with the
// user's password, so history renders correctly after re-login.

/** Persist the own-message plaintext cache (messageId → plaintext). */
export function saveOwnMessages(
  userId: string,
  messages: Map<string, string>,
  password: string,
): void {
  try {
    const obj = Object.fromEntries(messages);
    const encrypted = encryptData(JSON.stringify(obj), password, OWNMSGS_DOMAIN);
    localStorage.setItem(ownMessagesStorageKey(userId), encrypted);
  } catch (e) {
    console.warn('Failed to save own-message cache:', e);
  }
}

/** Load the own-message plaintext cache. Returns an empty map if none/failed. */
export function loadOwnMessages(
  userId: string,
  password: string,
): Map<string, string> {
  try {
    const encrypted = localStorage.getItem(ownMessagesStorageKey(userId));
    if (!encrypted) return new Map();
    const json = decryptData(encrypted, password, OWNMSGS_DOMAIN);
    return new Map(Object.entries(JSON.parse(json)));
  } catch (e) {
    console.warn('Failed to load own-message cache:', e);
    return new Map();
  }
}
