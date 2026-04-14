/**
 * Voice encryption for relay mode using Web Crypto AES-GCM.
 *
 * Each sender generates a random 256-bit session key, encrypts audio
 * payloads with AES-256-GCM, and shares the key with peers via
 * VoiceKeyExchange messages (key wrapped with per-peer shared secrets).
 *
 * The server only sees ciphertext — it cannot decrypt voice data.
 */

/** Generate a random voice session key. */
export async function generateVoiceKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, // extractable for key exchange
    ['encrypt', 'decrypt'],
  );
}

/** Export a CryptoKey to raw bytes. */
export async function exportKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
}

/** Import raw key bytes as an AES-GCM CryptoKey. */
export async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw.buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypt a voice frame.
 * Returns: 12-byte nonce + ciphertext+tag (concatenated).
 */
export async function encryptVoiceFrame(
  key: CryptoKey,
  plaintext: Uint8Array,
  sequence: number,
): Promise<Uint8Array> {
  // Nonce: 12 bytes. First 4 = sequence (LE), last 8 = random.
  // Random component prevents nonce reuse if sequence wraps.
  const nonce = new Uint8Array(12);
  const view = new DataView(nonce.buffer);
  view.setUint32(0, sequence, true);
  crypto.getRandomValues(nonce.subarray(4));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer, tagLength: 128 },
    key,
    plaintext.slice().buffer as ArrayBuffer,
  );

  // Prepend nonce to ciphertext
  const result = new Uint8Array(12 + ciphertext.byteLength);
  result.set(nonce, 0);
  result.set(new Uint8Array(ciphertext), 12);
  return result;
}

/**
 * Decrypt a voice frame.
 * Input: 12-byte nonce + ciphertext+tag (as produced by encryptVoiceFrame).
 * Returns plaintext, or null if decryption fails.
 */
export async function decryptVoiceFrame(
  key: CryptoKey,
  data: Uint8Array,
): Promise<Uint8Array | null> {
  if (data.length < 12 + 16) return null; // too short (nonce + min tag)

  const nonce = data.slice(0, 12);
  const ciphertext = data.slice(12);

  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce.buffer as ArrayBuffer, tagLength: 128 },
      key,
      ciphertext.buffer as ArrayBuffer,
    );
    return new Uint8Array(plaintext);
  } catch {
    return null; // authentication failed or corrupt data
  }
}
