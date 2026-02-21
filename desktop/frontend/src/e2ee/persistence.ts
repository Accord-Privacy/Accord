/**
 * @module persistence
 * Encrypted persistence for E2EE identity keys and sender key store.
 *
 * Keys are encrypted at rest using AES-256-GCM with a key derived from
 * SHA-256(password || domain-separator). This mirrors the pattern used
 * in session.ts for Double Ratchet session persistence.
 */

// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';

import type { IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair } from './keys';
import { SenderKeyStore } from './senderKeys';

// ─── Constants ──────────────────────────────────────────────────────────────

const IDENTITY_STORAGE_PREFIX = 'accord_e2ee_identity_';
const SENDERKEYS_STORAGE_PREFIX = 'accord_e2ee_senderkeys_';
const IDENTITY_DOMAIN = 'accord-e2ee-identity-storage';
const SENDERKEYS_DOMAIN = 'accord-e2ee-senderkeys-storage';

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

function deriveKey(password: string, domain: string): Uint8Array {
  const passBytes = new TextEncoder().encode(password);
  const domainBytes = new TextEncoder().encode(domain);
  const material = new Uint8Array(passBytes.length + domainBytes.length);
  material.set(passBytes, 0);
  material.set(domainBytes, passBytes.length);
  return sha256(material);
}

function encryptData(data: string, password: string, domain: string): string {
  const key = deriveKey(password, domain);
  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(data);
  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(plaintext);
  const combined = new Uint8Array(12 + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, 12);
  return toBase64(combined);
}

function decryptData(encrypted: string, password: string, domain: string): string {
  const key = deriveKey(password, domain);
  const combined = fromBase64(encrypted);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const cipher = gcm(key, iv);
  const plaintext = cipher.decrypt(ciphertext);
  return new TextDecoder().decode(plaintext);
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
