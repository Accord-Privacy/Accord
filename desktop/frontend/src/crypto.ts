// Client-side encryption using Web Crypto API
// No external dependencies - uses built-in browser crypto
//
// ⚠️  WARNING: INSECURE PLACEHOLDER ENCRYPTION ⚠️
// The current key derivation does NOT provide true end-to-end encryption.
// Channel keys are derived from channel ID + a user-specific token, meaning
// the server (or anyone with the channel UUID and token) can decrypt messages.
// A proper implementation requires ECDH key exchange between participants
// (e.g., Sender Keys, MLS, or pairwise Double Ratchet).
// TODO: Implement proper key exchange protocol for real E2EE.

const STORAGE_KEYS = {
  PRIVATE_KEY: 'accord_private_key',
  PUBLIC_KEY: 'accord_public_key',
  CHANNEL_KEYS: 'accord_channel_keys'
};

// Web Crypto API uses ECDH P-256, which is equivalent to X25519 used by the CLI
const ECDH_PARAMS = {
  name: 'ECDH',
  namedCurve: 'P-256'
};

const AES_PARAMS = {
  name: 'AES-GCM',
  length: 256
};

/**
 * Generate ECDH P-256 keypair for encryption
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  try {
    const keyPair = await window.crypto.subtle.generateKey(
      ECDH_PARAMS,
      true, // extractable
      ['deriveKey', 'deriveBits']
    );
    
    return keyPair;
  } catch (error) {
    throw new Error(`Failed to generate keypair: ${error}`);
  }
}

/**
 * Derive a symmetric key for a channel using HKDF
 */
export async function deriveChannelKey(privateKey: CryptoKey, channelId: string): Promise<CryptoKey> {
  try {
    // Create a salt from the channel ID
    const encoder = new TextEncoder();
    const salt = encoder.encode(channelId);
    
    // Use the private key to derive bits, then create an AES key
    const derivedBits = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: privateKey // This is actually wrong - we need the other party's public key
        // For now, we'll use the channel ID as a seed for key derivation
      },
      privateKey,
      256
    );
    
    // Create a key from derived bits and channel ID
    const keyMaterial = new Uint8Array([...new Uint8Array(derivedBits), ...salt]);
    const keyBytes = keyMaterial.slice(0, 32); // Take first 32 bytes for AES-256
    const importedKey = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      AES_PARAMS,
      false, // not extractable
      ['encrypt', 'decrypt']
    );
    
    return importedKey;
  } catch (error) {
    // Fallback: create a deterministic key from channel ID
    return await createChannelKeyFromId(channelId);
  }
}

/**
 * Create a deterministic key from channel ID (fallback method)
 * 
 * ⚠️  WARNING: This is NOT real E2EE. The key is derived from the channel ID
 * combined with a user-local secret. Any party with the channel UUID and the
 * user's token/secret can derive the same key. This is a placeholder until
 * proper ECDH key exchange is implemented.
 * TODO: Replace with proper multi-party key agreement (MLS / Sender Keys).
 */
async function createChannelKeyFromId(channelId: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  
  // Incorporate user-specific secret to make keys less trivially derivable
  // This is still NOT real E2EE — just makes it harder than plain channel ID hashing
  const userSecret = localStorage.getItem('accord_token') || '';
  const privateKeyB64 = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY) || '';
  const material = `${channelId}:${userSecret}:${privateKeyB64.slice(0, 32)}`;
  const data = encoder.encode(material);
  
  // Hash the combined material to create key
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  
  const key = await window.crypto.subtle.importKey(
    'raw',
    digest,
    AES_PARAMS,
    false, // not extractable
    ['encrypt', 'decrypt']
  );
  
  return key;
}

/**
 * Encrypt a message using AES-256-GCM
 */
export async function encryptMessage(key: CryptoKey, plaintext: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);
    
    // Generate a random IV (96 bits for GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      data
    );
    
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    // Return as base64
    return arrayBufferToBase64(combined.buffer);
  } catch (error) {
    throw new Error(`Failed to encrypt message: ${error}`);
  }
}

/**
 * Decrypt a message using AES-256-GCM
 */
export async function decryptMessage(key: CryptoKey, ciphertext: string): Promise<string> {
  try {
    // Parse base64 and extract IV + encrypted data
    const combined = base64ToArrayBuffer(ciphertext);
    const iv = new Uint8Array(combined.slice(0, 12));
    const encrypted = combined.slice(12);
    
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encrypted
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    throw new Error(`Failed to decrypt message: ${error}`);
  }
}

/**
 * Encrypt a file buffer using AES-256-GCM
 */
export async function encryptFile(key: CryptoKey, fileBuffer: ArrayBuffer): Promise<ArrayBuffer> {
  try {
    // Generate a random IV (96 bits for GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      fileBuffer
    );
    
    // Combine IV and encrypted data
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    
    return combined.buffer;
  } catch (error) {
    throw new Error(`Failed to encrypt file: ${error}`);
  }
}

/**
 * Decrypt a file buffer using AES-256-GCM
 */
export async function decryptFile(key: CryptoKey, encryptedBuffer: ArrayBuffer): Promise<ArrayBuffer> {
  try {
    // Extract IV and encrypted data
    const iv = new Uint8Array(encryptedBuffer.slice(0, 12));
    const encrypted = encryptedBuffer.slice(12);
    
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encrypted
    );
    
    return decrypted;
  } catch (error) {
    throw new Error(`Failed to decrypt file: ${error}`);
  }
}

/**
 * Encrypt filename using the same method as messages
 */
export async function encryptFilename(key: CryptoKey, filename: string): Promise<string> {
  return encryptMessage(key, filename);
}

/**
 * Decrypt filename using the same method as messages
 */
export async function decryptFilename(key: CryptoKey, encryptedFilename: string): Promise<string> {
  return decryptMessage(key, encryptedFilename);
}

/**
 * Export public key as base64 for server registration
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  try {
    const exported = await window.crypto.subtle.exportKey('spki', publicKey);
    return arrayBufferToBase64(exported);
  } catch (error) {
    throw new Error(`Failed to export public key: ${error}`);
  }
}

/**
 * Derive a wrapping key from a passphrase using PBKDF2.
 * Used to encrypt the private key before storing in localStorage.
 */
async function deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    encoder.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt data with a passphrase-derived key (AES-GCM).
 */
async function encryptWithPassphrase(data: ArrayBuffer, passphrase: string): Promise<string> {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, data);
  // Format: base64(salt + iv + ciphertext)
  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);
  return arrayBufferToBase64(combined.buffer);
}

/**
 * Decrypt data with a passphrase-derived key (AES-GCM).
 */
async function decryptWithPassphrase(encryptedB64: string, passphrase: string): Promise<ArrayBuffer> {
  const combined = new Uint8Array(base64ToArrayBuffer(encryptedB64));
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const ciphertext = combined.slice(28);
  const wrappingKey = await deriveWrappingKey(passphrase, salt);
  return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrappingKey, ciphertext);
}

/**
 * Get a passphrase for key encryption. Uses the auth token as a derived secret
 * so the user doesn't need to enter a separate passphrase.
 * TODO: Consider prompting the user for an explicit passphrase for better security.
 */
function getKeyPassphrase(): string {
  // Use a combination of token and a fixed app secret as the passphrase
  const token = localStorage.getItem('accord_token') || '';
  return `accord-key-wrap:${token}`;
}

/**
 * Save keypair to localStorage (private key encrypted with passphrase)
 */
export async function saveKeyToStorage(keyPair: CryptoKeyPair): Promise<void> {
  try {
    const privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKeyData = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    
    // Encrypt private key before storing
    const passphrase = getKeyPassphrase();
    const encryptedPrivateKey = await encryptWithPassphrase(privateKeyData, passphrase);
    
    localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, encryptedPrivateKey);
    localStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, arrayBufferToBase64(publicKeyData));
  } catch (error) {
    throw new Error(`Failed to save keys to storage: ${error}`);
  }
}

/**
 * Load keypair from localStorage (decrypts private key with passphrase)
 */
export async function loadKeyFromStorage(): Promise<CryptoKeyPair | null> {
  try {
    const privateKeyEncrypted = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
    const publicKeyB64 = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
    
    if (!privateKeyEncrypted || !publicKeyB64) {
      return null;
    }
    
    let privateKeyBuffer: ArrayBuffer;
    try {
      // Try decrypting with passphrase (new format)
      const passphrase = getKeyPassphrase();
      privateKeyBuffer = await decryptWithPassphrase(privateKeyEncrypted, passphrase);
    } catch {
      // Fallback: try reading as plain base64 (legacy unencrypted format)
      privateKeyBuffer = base64ToArrayBuffer(privateKeyEncrypted);
    }
    const publicKeyBuffer = base64ToArrayBuffer(publicKeyB64);
    
    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      privateKeyBuffer,
      ECDH_PARAMS,
      true, // extractable
      ['deriveKey', 'deriveBits']
    );
    
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      ECDH_PARAMS,
      true, // extractable
      []
    );
    
    return { privateKey, publicKey };
  } catch (error) {
    console.error('Failed to load keys from storage:', error);
    return null;
  }
}

/**
 * Cache channel keys for performance
 */
const channelKeyCache = new Map<string, CryptoKey>();

export async function getChannelKey(privateKey: CryptoKey, channelId: string): Promise<CryptoKey> {
  if (channelKeyCache.has(channelId)) {
    return channelKeyCache.get(channelId)!;
  }
  
  const key = await deriveChannelKey(privateKey, channelId);
  channelKeyCache.set(channelId, key);
  return key;
}

/**
 * Clear cached channel keys (useful for logout)
 */
export function clearChannelKeyCache(): void {
  channelKeyCache.clear();
}

/**
 * Check if crypto is available in this environment
 */
export function isCryptoSupported(): boolean {
  return typeof window !== 'undefined' && 
         typeof window.crypto !== 'undefined' && 
         typeof window.crypto.subtle !== 'undefined';
}

// Utility functions for base64 conversion
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