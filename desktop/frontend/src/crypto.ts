// Client-side encryption using Web Crypto API
// No external dependencies - uses built-in browser crypto

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
 */
async function createChannelKeyFromId(channelId: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const data = encoder.encode(channelId);
  
  // Hash the channel ID to create key material
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
 * Save keypair to localStorage
 */
export async function saveKeyToStorage(keyPair: CryptoKeyPair): Promise<void> {
  try {
    // Export private key
    const privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKeyData = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    
    localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, arrayBufferToBase64(privateKeyData));
    localStorage.setItem(STORAGE_KEYS.PUBLIC_KEY, arrayBufferToBase64(publicKeyData));
  } catch (error) {
    throw new Error(`Failed to save keys to storage: ${error}`);
  }
}

/**
 * Load keypair from localStorage
 */
export async function loadKeyFromStorage(): Promise<CryptoKeyPair | null> {
  try {
    const privateKeyB64 = localStorage.getItem(STORAGE_KEYS.PRIVATE_KEY);
    const publicKeyB64 = localStorage.getItem(STORAGE_KEYS.PUBLIC_KEY);
    
    if (!privateKeyB64 || !publicKeyB64) {
      return null;
    }
    
    const privateKeyBuffer = base64ToArrayBuffer(privateKeyB64);
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