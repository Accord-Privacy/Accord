// Client-side encryption with Web Crypto API + pure-JS fallback
// Falls back to @noble libraries when crypto.subtle is unavailable
// (e.g., HTTP origins on LAN — crypto.subtle requires secure context)
//
// ⚠️  WARNING: INSECURE PLACEHOLDER ENCRYPTION ⚠️
// The current key derivation does NOT provide true end-to-end encryption.
// Channel keys are derived from channel ID + a user-specific token, meaning
// the server (or anyone with the channel UUID and token) can decrypt messages.
// TODO: Implement proper key exchange protocol for real E2EE.

// @ts-ignore - noble v2 uses .js exports
import { p256 } from '@noble/curves/nist.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';
// @ts-ignore
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';
// randomBytes: use crypto.getRandomValues (available even in insecure contexts)
function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

import { BIP39_WORDLIST } from './bip39wordlist';

// Storage keys are namespaced by identity (public key hash) to support
// multiple accounts in the same browser without overwriting each other.
// Legacy un-namespaced keys are tried as fallback during migration.
function storageKeys(pkHash?: string) {
  const suffix = pkHash ? `_${pkHash.slice(0, 16)}` : '';
  return {
    PRIVATE_KEY: `accord_private_key${suffix}`,
    PUBLIC_KEY: `accord_public_key${suffix}`,
    CHANNEL_KEYS: `accord_channel_keys${suffix}`,
  };
}

// Active identity hash — set after login/registration
let activeIdentityHash: string | undefined;

export function setActiveIdentity(pkHash: string) {
  activeIdentityHash = pkHash;
}

function STORAGE_KEYS_FOR(pkHash?: string) {
  return storageKeys(pkHash || activeIdentityHash);
}

// Legacy compat
const STORAGE_KEYS = {
  PRIVATE_KEY: 'accord_private_key',
  PUBLIC_KEY: 'accord_public_key',
  CHANNEL_KEYS: 'accord_channel_keys'
};

const ECDH_PARAMS = {
  name: 'ECDH',
  namedCurve: 'P-256'
};

const AES_PARAMS = {
  name: 'AES-GCM',
  length: 256
};

// ---------------------------------------------------------------------------
// Detect environment
// ---------------------------------------------------------------------------
const HAS_SUBTLE = typeof window !== 'undefined' &&
  typeof window.crypto !== 'undefined' &&
  typeof window.crypto.subtle !== 'undefined';

/**
 * Check if crypto is available in this environment.
 * Returns true if EITHER Web Crypto or the noble fallback is usable.
 */
export function isCryptoSupported(): boolean {
  // Noble fallback is always available (pure JS), so crypto is always supported
  return true;
}

// ---------------------------------------------------------------------------
// SHA-256 helper (used by App.tsx for public key hashing)
// ---------------------------------------------------------------------------
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  if (HAS_SUBTLE) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // Noble fallback
  const hash = sha256(data);
  return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Utility: base64 <-> ArrayBuffer
// ---------------------------------------------------------------------------
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode.apply(null, Array.from(new Uint8Array(buffer)));
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }
  return buffer;
}

function uint8ToBase64(u8: Uint8Array): string {
  return arrayBufferToBase64(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer);
}

function base64ToUint8(b64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(b64));
}

// ---------------------------------------------------------------------------
// PBKDF2 wrapping key derivation
// ---------------------------------------------------------------------------
async function deriveWrappingKeySubtle(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function deriveWrappingKeyNoble(passphrase: string, salt: Uint8Array): Uint8Array {
  const enc = new TextEncoder();
  return pbkdf2(sha256, enc.encode(passphrase), salt, { c: 100000, dkLen: 32 });
}

// ---------------------------------------------------------------------------
// Passphrase encrypt/decrypt (for key storage)
// ---------------------------------------------------------------------------
async function encryptWithPassphrase(data: ArrayBuffer, passphrase: string): Promise<string> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  if (HAS_SUBTLE) {
    const wrappingKey = await deriveWrappingKeySubtle(passphrase, salt);
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, wrappingKey, data);
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    return arrayBufferToBase64(combined.buffer);
  }
  // Noble fallback
  const key = deriveWrappingKeyNoble(passphrase, salt);
  const cipher = gcm(key, iv);
  const encrypted = cipher.encrypt(new Uint8Array(data));
  const combined = new Uint8Array(salt.length + iv.length + encrypted.length);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(encrypted, salt.length + iv.length);
  return uint8ToBase64(combined);
}

async function decryptWithPassphrase(encryptedB64: string, passphrase: string): Promise<ArrayBuffer> {
  const combined = new Uint8Array(base64ToArrayBuffer(encryptedB64));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  if (HAS_SUBTLE) {
    const wrappingKey = await deriveWrappingKeySubtle(passphrase, salt);
    return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, wrappingKey, ciphertext);
  }
  // Noble fallback
  const key = deriveWrappingKeyNoble(passphrase, salt);
  const cipher = gcm(key, iv);
  const decrypted = cipher.decrypt(ciphertext);
  return decrypted.buffer.slice(decrypted.byteOffset, decrypted.byteOffset + decrypted.byteLength) as ArrayBuffer;
}

function getKeyPassphrase(): string {
  const token = localStorage.getItem('accord_token') || '';
  return `accord-key-wrap:${token}`;
}

// ---------------------------------------------------------------------------
// Key types — we wrap both Web Crypto and noble keys behind a common interface
// ---------------------------------------------------------------------------

// We store raw bytes alongside CryptoKey so we can always fall back
interface AccordKeyPairInternal {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  // Raw bytes for noble fallback path
  _privateKeyRaw?: Uint8Array;
  _publicKeyRaw?: Uint8Array; // SPKI-encoded
}

/**
 * Generate ECDH P-256 keypair for encryption
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  if (HAS_SUBTLE) {
    const keyPair = await window.crypto.subtle.generateKey(
      ECDH_PARAMS, true, ['deriveKey', 'deriveBits']
    );
    return keyPair;
  }
  // Noble fallback: generate P-256 key, wrap in a CryptoKey-like object
  return generateKeyPairNoble();
}

function generateKeyPairNoble(): CryptoKeyPair {
  const privBytes = randomBytes(32);
  const pubPoint = p256.getPublicKey(privBytes, false); // uncompressed

  // Encode public key as SPKI DER for compatibility
  const spkiPublic = encodeP256PublicSPKI(pubPoint);
  const pkcs8Private = encodeP256PrivatePKCS8(privBytes, pubPoint);

  const pair: AccordKeyPairInternal = {
    privateKey: { _nobleRaw: privBytes, _noblePkcs8: pkcs8Private } as unknown as CryptoKey,
    publicKey: { _nobleRaw: pubPoint, _nobleSpki: spkiPublic } as unknown as CryptoKey,
    _privateKeyRaw: privBytes,
    _publicKeyRaw: spkiPublic,
  };
  return pair as unknown as CryptoKeyPair;
}

// ---------------------------------------------------------------------------
// SPKI / PKCS8 DER encoding for P-256 (to match Web Crypto export format)
// ---------------------------------------------------------------------------

// OID for id-ecPublicKey (1.2.840.10045.2.1) + P-256 (1.2.840.10045.3.1.7)
const EC_P256_ALGORITHM_ID = new Uint8Array([
  0x30, 0x13, // SEQUENCE (19 bytes)
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
]);

function encodeP256PublicSPKI(uncompressedPub: Uint8Array): Uint8Array {
  // SubjectPublicKeyInfo = SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
  const bitString = new Uint8Array(2 + 1 + uncompressedPub.length);
  bitString[0] = 0x03; // BIT STRING tag
  bitString[1] = 1 + uncompressedPub.length; // length
  bitString[2] = 0x00; // no unused bits
  bitString.set(uncompressedPub, 3);

  const innerLen = EC_P256_ALGORITHM_ID.length + bitString.length;
  const spki = new Uint8Array(2 + innerLen);
  spki[0] = 0x30; // SEQUENCE tag
  spki[1] = innerLen;
  spki.set(EC_P256_ALGORITHM_ID, 2);
  spki.set(bitString, 2 + EC_P256_ALGORITHM_ID.length);
  return spki;
}

function encodeP256PrivatePKCS8(privBytes: Uint8Array, uncompressedPub: Uint8Array): Uint8Array {
  // ECPrivateKey (SEC1) inner structure
  const ecPrivateKey = encodeECPrivateKey(privBytes, uncompressedPub);

  // PKCS#8 PrivateKeyInfo = SEQUENCE { version INTEGER(0), algorithm, privateKey OCTET STRING }
  const versionBytes = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER 0
  const octetString = new Uint8Array(2 + ecPrivateKey.length);
  octetString[0] = 0x04; // OCTET STRING
  octetString[1] = ecPrivateKey.length;
  octetString.set(ecPrivateKey, 2);

  const innerLen = versionBytes.length + EC_P256_ALGORITHM_ID.length + octetString.length;
  const pkcs8 = new Uint8Array(2 + innerLen);
  pkcs8[0] = 0x30;
  pkcs8[1] = innerLen;
  let off = 2;
  pkcs8.set(versionBytes, off); off += versionBytes.length;
  pkcs8.set(EC_P256_ALGORITHM_ID, off); off += EC_P256_ALGORITHM_ID.length;
  pkcs8.set(octetString, off);
  return pkcs8;
}

function encodeECPrivateKey(privBytes: Uint8Array, uncompressedPub: Uint8Array): Uint8Array {
  // ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING, publicKey [1] BIT STRING }
  const version = new Uint8Array([0x02, 0x01, 0x01]);
  const privOctet = new Uint8Array([0x04, 0x20, ...privBytes]); // 32 bytes

  // [1] EXPLICIT BIT STRING containing uncompressed public key
  const bitStr = new Uint8Array([0x03, 1 + uncompressedPub.length, 0x00, ...uncompressedPub]);
  const ctx1 = new Uint8Array([0xa1, bitStr.length, ...bitStr]);

  const innerLen = version.length + privOctet.length + ctx1.length;
  const seq = new Uint8Array(2 + innerLen);
  seq[0] = 0x30;
  seq[1] = innerLen;
  let off = 2;
  seq.set(version, off); off += version.length;
  seq.set(privOctet, off); off += privOctet.length;
  seq.set(ctx1, off);
  return seq;
}

function decodeP256PrivateFromPKCS8(pkcs8: Uint8Array): Uint8Array {
  // Simple parser: find the 32-byte private key inside the PKCS8 structure
  // The private key bytes are in an OCTET STRING (0x04 0x20) inside the ECPrivateKey
  for (let i = 0; i < pkcs8.length - 33; i++) {
    if (pkcs8[i] === 0x04 && pkcs8[i + 1] === 0x20) {
      const candidate = pkcs8.slice(i + 2, i + 34);
      // Verify it's a valid P-256 scalar (non-zero, less than order)
      try {
        p256.getPublicKey(candidate, false);
        return candidate;
      } catch {
        continue;
      }
    }
  }
  throw new Error('Could not extract P-256 private key from PKCS8');
}

// ---------------------------------------------------------------------------
// Export public key
// ---------------------------------------------------------------------------
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  if (HAS_SUBTLE && !(publicKey as any)._nobleSpki) {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(exported);
  }
  // Noble fallback
  const spki = (publicKey as any)._nobleSpki as Uint8Array;
  if (!spki) throw new Error('Cannot export noble public key: missing SPKI data');
  return uint8ToBase64(spki);
}

// ---------------------------------------------------------------------------
// Save/Load keypair to/from localStorage
// ---------------------------------------------------------------------------
export async function saveKeyToStorage(keyPair: CryptoKeyPair, pkHash?: string): Promise<void> {
  let privateKeyData: ArrayBuffer;
  let publicKeyData: ArrayBuffer;

  if (HAS_SUBTLE && !(keyPair.privateKey as any)._nobleRaw) {
    privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    publicKeyData = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  } else {
    const pkcs8 = (keyPair.privateKey as any)._noblePkcs8 as Uint8Array;
    const spki = (keyPair.publicKey as any)._nobleSpki as Uint8Array;
    privateKeyData = pkcs8.buffer.slice(pkcs8.byteOffset, pkcs8.byteOffset + pkcs8.byteLength) as ArrayBuffer;
    publicKeyData = spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength) as ArrayBuffer;
  }

  const passphrase = getKeyPassphrase();
  const encryptedPrivateKey = await encryptWithPassphrase(privateKeyData, passphrase);

  const keys = STORAGE_KEYS_FOR(pkHash);
  localStorage.setItem(keys.PRIVATE_KEY, encryptedPrivateKey);
  localStorage.setItem(keys.PUBLIC_KEY, arrayBufferToBase64(publicKeyData));
}

export async function loadKeyFromStorage(pkHash?: string): Promise<CryptoKeyPair | null> {
  try {
    const namespacedKeys = STORAGE_KEYS_FOR(pkHash);
    let privateKeyEncrypted = localStorage.getItem(namespacedKeys.PRIVATE_KEY);
    let publicKeyB64 = localStorage.getItem(namespacedKeys.PUBLIC_KEY);
    // Fallback to legacy
    if (!privateKeyEncrypted || !publicKeyB64) {
      privateKeyEncrypted = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
      publicKeyB64 = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
    }

    if (!privateKeyEncrypted || !publicKeyB64) return null;

    let privateKeyBuffer: ArrayBuffer;
    try {
      const passphrase = getKeyPassphrase();
      privateKeyBuffer = await decryptWithPassphrase(privateKeyEncrypted, passphrase);
    } catch {
      // Fallback: try reading as plain base64 (legacy unencrypted format)
      privateKeyBuffer = base64ToArrayBuffer(privateKeyEncrypted);
    }
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyB64);

    if (HAS_SUBTLE) {
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8', privateKeyBuffer, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
      const publicKey = await window.crypto.subtle.importKey(
        'spki', publicKeyBuffer, ECDH_PARAMS, true, []);
      return { privateKey, publicKey };
    }

    // Noble fallback: extract raw private key from PKCS8
    const privBytes = decodeP256PrivateFromPKCS8(new Uint8Array(privateKeyBuffer));
    const pubPoint = p256.getPublicKey(privBytes, false);
    const spki = encodeP256PublicSPKI(pubPoint);
    const pkcs8 = encodeP256PrivatePKCS8(privBytes, pubPoint);

    return {
      privateKey: { _nobleRaw: privBytes, _noblePkcs8: pkcs8 } as unknown as CryptoKey,
      publicKey: { _nobleRaw: pubPoint, _nobleSpki: spki } as unknown as CryptoKey,
    } as unknown as CryptoKeyPair;
  } catch (error) {
    console.warn('Failed to load keys from storage (may be password-encrypted):', error);
    // Don't clear keys — they may be loadable via loadKeyWithPassword()
    return null;
  }
}

// ---------------------------------------------------------------------------
// Channel key derivation (placeholder — NOT real E2EE)
// ---------------------------------------------------------------------------

/**
 * Create a deterministic AES-256 key from channel ID + user secrets.
 * Returns raw 32 bytes (noble path) or CryptoKey (subtle path).
 */
async function createChannelKeyFromId(channelId: string): Promise<CryptoKey | Uint8Array> {
  const enc = new TextEncoder();
  const userSecret = localStorage.getItem('accord_token') || '';
  const privateKeyB64 = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY) || '';
  const material = `${channelId}:${userSecret}:${privateKeyB64.slice(0, 32)}`;
  const data = enc.encode(material);

  if (HAS_SUBTLE) {
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return window.crypto.subtle.importKey('raw', digest, AES_PARAMS, false, ['encrypt', 'decrypt']);
  }
  return sha256(data);
}

export async function deriveChannelKey(_privateKey: CryptoKey, channelId: string): Promise<CryptoKey | Uint8Array> {
  // The original code's ECDH derivation was broken (used privateKey as publicKey).
  // Just use the channel-ID-based fallback for now.
  return createChannelKeyFromId(channelId);
}

// ---------------------------------------------------------------------------
// Channel key cache
// ---------------------------------------------------------------------------
const channelKeyCache = new Map<string, CryptoKey | Uint8Array>();

export async function getChannelKey(privateKey: CryptoKey, channelId: string): Promise<CryptoKey | Uint8Array> {
  if (channelKeyCache.has(channelId)) return channelKeyCache.get(channelId)!;
  const key = await deriveChannelKey(privateKey, channelId);
  channelKeyCache.set(channelId, key);
  return key;
}

export function clearChannelKeyCache(): void {
  channelKeyCache.clear();
}

// ---------------------------------------------------------------------------
// AES-GCM Encrypt / Decrypt (messages)
// ---------------------------------------------------------------------------
export async function encryptMessage(key: CryptoKey | Uint8Array, plaintext: string): Promise<string> {
  const data = new TextEncoder().encode(plaintext);
  const iv = randomBytes(12);

  if (HAS_SUBTLE && key instanceof CryptoKey) {
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, data);
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return arrayBufferToBase64(combined.buffer);
  }

  // Noble fallback
  const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(0);
  const cipher = gcm(keyBytes, iv);
  const encrypted = cipher.encrypt(data);
  const combined = new Uint8Array(iv.length + encrypted.length);
  combined.set(iv);
  combined.set(encrypted, iv.length);
  return uint8ToBase64(combined);
}

export async function decryptMessage(key: CryptoKey | Uint8Array, ciphertext: string): Promise<string> {
  const combined = base64ToUint8(ciphertext);
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);

  if (HAS_SUBTLE && key instanceof CryptoKey) {
    const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, encrypted);
    return new TextDecoder().decode(decrypted);
  }

  // Noble fallback
  const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(0);
  const cipher = gcm(keyBytes, iv);
  const decrypted = cipher.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

// ---------------------------------------------------------------------------
// AES-GCM Encrypt / Decrypt (files)
// ---------------------------------------------------------------------------
export async function encryptFile(key: CryptoKey | Uint8Array, fileBuffer: ArrayBuffer): Promise<ArrayBuffer> {
  const iv = randomBytes(12);

  if (HAS_SUBTLE && key instanceof CryptoKey) {
    const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, fileBuffer);
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return combined.buffer;
  }

  const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(0);
  const cipher = gcm(keyBytes, iv);
  const encrypted = cipher.encrypt(new Uint8Array(fileBuffer));
  const combined = new Uint8Array(iv.length + encrypted.length);
  combined.set(iv);
  combined.set(encrypted, iv.length);
  return combined.buffer.slice(combined.byteOffset, combined.byteOffset + combined.byteLength) as ArrayBuffer;
}

export async function decryptFile(key: CryptoKey | Uint8Array, encryptedBuffer: ArrayBuffer): Promise<ArrayBuffer> {
  const all = new Uint8Array(encryptedBuffer);
  const iv = all.slice(0, 12);
  const encrypted = all.slice(12);

  if (HAS_SUBTLE && key instanceof CryptoKey) {
    return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, encrypted);
  }

  const keyBytes = key instanceof Uint8Array ? key : new Uint8Array(0);
  const cipher = gcm(keyBytes, iv);
  const decrypted = cipher.decrypt(encrypted);
  return decrypted.buffer.slice(decrypted.byteOffset, decrypted.byteOffset + decrypted.byteLength) as ArrayBuffer;
}

export async function encryptFilename(key: CryptoKey | Uint8Array, filename: string): Promise<string> {
  return encryptMessage(key, filename);
}

export async function decryptFilename(key: CryptoKey | Uint8Array, encryptedFilename: string): Promise<string> {
  return decryptMessage(key, encryptedFilename);
}

// ---------------------------------------------------------------------------
// BIP39 Mnemonic support for identity backup & recovery
// ---------------------------------------------------------------------------

/**
 * Convert 256-bit entropy to a 24-word BIP39 mnemonic.
 * Appends an 8-bit checksum (first byte of SHA-256 of entropy).
 */
export function entropyToMnemonic(entropy: Uint8Array): string {
  if (entropy.length !== 32) throw new Error('Expected 32 bytes of entropy');
  const hash = sha256(entropy);
  const checksum = hash[0]; // 8 bits for 256-bit entropy

  // Convert entropy + checksum to 11-bit groups (264 bits = 24 words × 11 bits)
  // Build a bit string
  let bits = '';
  for (const byte of entropy) {
    bits += byte.toString(2).padStart(8, '0');
  }
  bits += checksum.toString(2).padStart(8, '0');

  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const idx = parseInt(bits.slice(i * 11, (i + 1) * 11), 2);
    words.push(BIP39_WORDLIST[idx]);
  }
  return words.join(' ');
}

/**
 * Convert a 24-word BIP39 mnemonic back to 256-bit entropy.
 * Validates the checksum.
 */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const words = mnemonic.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) throw new Error('Expected 24 words');

  let bits = '';
  for (const word of words) {
    const idx = BIP39_WORDLIST.indexOf(word);
    if (idx === -1) throw new Error(`Unknown word: "${word}"`);
    bits += idx.toString(2).padStart(11, '0');
  }

  // 264 bits = 256 entropy + 8 checksum
  const entropyBits = bits.slice(0, 256);
  const checksumBits = bits.slice(256, 264);

  const entropy = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
  }

  // Verify checksum
  const hash = sha256(entropy);
  const expectedChecksum = hash[0].toString(2).padStart(8, '0');
  if (checksumBits !== expectedChecksum) {
    throw new Error('Invalid mnemonic checksum');
  }

  return entropy;
}

/**
 * Get the raw 32-byte private key from a CryptoKeyPair.
 */
export async function getRawPrivateKey(keyPair: CryptoKeyPair): Promise<Uint8Array> {
  if ((keyPair.privateKey as any)._nobleRaw) {
    return (keyPair.privateKey as any)._nobleRaw as Uint8Array;
  }
  // Web Crypto path: export PKCS8 then extract
  const pkcs8 = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  return decodeP256PrivateFromPKCS8(new Uint8Array(pkcs8));
}

/**
 * Derive the 24-word mnemonic from an existing keypair's private key.
 */
export async function keyPairToMnemonic(keyPair: CryptoKeyPair): Promise<string> {
  const raw = await getRawPrivateKey(keyPair);
  return entropyToMnemonic(raw);
}

/**
 * Recover a P-256 keypair from a 24-word mnemonic.
 * The entropy IS the private key bytes directly.
 */
export function mnemonicToKeyPair(mnemonic: string): CryptoKeyPair {
  const privBytes = mnemonicToEntropy(mnemonic);

  // Validate it's a valid P-256 scalar
  const pubPoint = p256.getPublicKey(privBytes, false);
  const spki = encodeP256PublicSPKI(pubPoint);
  const pkcs8 = encodeP256PrivatePKCS8(privBytes, pubPoint);

  return {
    privateKey: { _nobleRaw: privBytes, _noblePkcs8: pkcs8 } as unknown as CryptoKey,
    publicKey: { _nobleRaw: pubPoint, _nobleSpki: spki } as unknown as CryptoKey,
  } as unknown as CryptoKeyPair;
}

// ---------------------------------------------------------------------------
// Password-based key storage (survives logout)
// ---------------------------------------------------------------------------

/**
 * Save keypair encrypted with user's password (not token).
 * This persists across logouts since the token is cleared but keys remain.
 */
export async function saveKeyWithPassword(keyPair: CryptoKeyPair, password: string, pkHash?: string): Promise<void> {
  let privateKeyData: ArrayBuffer;
  let publicKeyData: ArrayBuffer;

  if (HAS_SUBTLE && !(keyPair.privateKey as any)._nobleRaw) {
    privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    publicKeyData = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  } else {
    const pkcs8 = (keyPair.privateKey as any)._noblePkcs8 as Uint8Array;
    const spki = (keyPair.publicKey as any)._nobleSpki as Uint8Array;
    privateKeyData = pkcs8.buffer.slice(pkcs8.byteOffset, pkcs8.byteOffset + pkcs8.byteLength) as ArrayBuffer;
    publicKeyData = spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength) as ArrayBuffer;
  }

  const passphrase = `accord-key-wrap:${password}`;
  const encryptedPrivateKey = await encryptWithPassphrase(privateKeyData, passphrase);

  const keys = STORAGE_KEYS_FOR(pkHash);
  localStorage.setItem(keys.PRIVATE_KEY, encryptedPrivateKey);
  localStorage.setItem(keys.PUBLIC_KEY, arrayBufferToBase64(publicKeyData));
  // Also save to legacy slot for backwards compat
  localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, encryptedPrivateKey);
  localStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, arrayBufferToBase64(publicKeyData));
}

/**
 * Load keypair decrypted with user's password.
 */
export async function loadKeyWithPassword(password: string, pkHash?: string): Promise<CryptoKeyPair | null> {
  // Try namespaced keys first, then legacy
  const namespacedKeys = STORAGE_KEYS_FOR(pkHash);
  let privateKeyEncrypted = localStorage.getItem(namespacedKeys.PRIVATE_KEY);
  let publicKeyB64 = localStorage.getItem(namespacedKeys.PUBLIC_KEY);
  // Fallback to legacy
  if (!privateKeyEncrypted || !publicKeyB64) {
    privateKeyEncrypted = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
    publicKeyB64 = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
  }
  try {
    if (!privateKeyEncrypted || !publicKeyB64) return null;

    const passphrase = `accord-key-wrap:${password}`;
    const privateKeyBuffer = await decryptWithPassphrase(privateKeyEncrypted, passphrase);
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyB64);

    if (HAS_SUBTLE) {
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8', privateKeyBuffer, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
      const publicKey = await window.crypto.subtle.importKey(
        'spki', publicKeyBuffer, ECDH_PARAMS, true, []);
      return { privateKey, publicKey };
    }

    const privBytes = decodeP256PrivateFromPKCS8(new Uint8Array(privateKeyBuffer));
    const pubPoint = p256.getPublicKey(privBytes, false);
    const spki = encodeP256PublicSPKI(pubPoint);
    const pkcs8Enc = encodeP256PrivatePKCS8(privBytes, pubPoint);

    return {
      privateKey: { _nobleRaw: privBytes, _noblePkcs8: pkcs8Enc } as unknown as CryptoKey,
      publicKey: { _nobleRaw: pubPoint, _nobleSpki: spki } as unknown as CryptoKey,
    } as unknown as CryptoKeyPair;
  } catch {
    return null;
  }
}

/**
 * Check if there's a stored keypair (public key in localStorage).
 */
export function hasStoredKeyPair(pkHash?: string): boolean {
  const keys = STORAGE_KEYS_FOR(pkHash);
  return !!localStorage.getItem(keys.PUBLIC_KEY) || !!localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
}

/**
 * Get the stored public key base64 without needing to decrypt.
 */
export function getStoredPublicKey(): string | null {
  return localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
}
