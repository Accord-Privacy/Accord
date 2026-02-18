/**
 * @module keys
 * X25519 key generation for the Double Ratchet E2EE protocol.
 *
 * Generates:
 * - Identity keypair (long-term, used in X3DH)
 * - Signed prekey (medium-term, rotated periodically)
 * - One-time prekeys (consumed on first message)
 *
 * Uses @noble/curves for X25519 (Curve25519 ECDH), which is the same
 * primitive as the Rust backend's x25519-dalek.
 */

// @ts-ignore - noble v2 uses .js exports
import { x25519 } from '@noble/curves/ed25519.js';

/** 32-byte raw key */
export type RawKey = Uint8Array;

/** A keypair: 32-byte private scalar + 32-byte public point */
export interface X25519KeyPair {
  privateKey: RawKey; // 32 bytes
  publicKey: RawKey;  // 32 bytes
}

/** Identity keypair — long-term, identifies a user */
export interface IdentityKeyPair extends X25519KeyPair {}

/** Signed prekey — medium-term, published in prekey bundle */
export interface SignedPreKeyPair extends X25519KeyPair {}

/** One-time prekey — single use, consumed during X3DH */
export interface OneTimePreKeyPair extends X25519KeyPair {}

/** Prekey bundle published to the server for others to initiate X3DH */
export interface PreKeyBundle {
  identityKey: RawKey;       // 32 bytes
  signedPrekey: RawKey;      // 32 bytes
  oneTimePrekey?: RawKey;    // 32 bytes, optional
}

/**
 * Generate a random 32-byte private key and derive the X25519 public key.
 * Uses crypto.getRandomValues (available even in insecure contexts).
 */
function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = new Uint8Array(32);
  crypto.getRandomValues(privateKey);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

/** Generate a long-term identity keypair */
export function generateIdentityKeyPair(): IdentityKeyPair {
  return generateX25519KeyPair();
}

/** Generate a signed prekey */
export function generateSignedPreKey(): SignedPreKeyPair {
  return generateX25519KeyPair();
}

/** Generate a one-time prekey */
export function generateOneTimePreKey(): OneTimePreKeyPair {
  return generateX25519KeyPair();
}

/**
 * Generate a batch of one-time prekeys.
 * @param count Number of prekeys to generate (default 10)
 */
export function generateOneTimePreKeys(count = 10): OneTimePreKeyPair[] {
  return Array.from({ length: count }, () => generateOneTimePreKey());
}

/**
 * Build a prekey bundle from local key material.
 * This is what gets uploaded to the server so others can initiate X3DH.
 */
export function buildPreKeyBundle(
  identityKeyPair: IdentityKeyPair,
  signedPreKey: SignedPreKeyPair,
  oneTimePreKey?: OneTimePreKeyPair,
): PreKeyBundle {
  return {
    identityKey: identityKeyPair.publicKey,
    signedPrekey: signedPreKey.publicKey,
    oneTimePrekey: oneTimePreKey?.publicKey,
  };
}

/**
 * Perform an X25519 Diffie-Hellman exchange.
 * @returns 32-byte shared secret
 */
export function x25519DH(privateKey: RawKey, publicKey: RawKey): RawKey {
  return x25519.getSharedSecret(privateKey, publicKey);
}

/**
 * Encode a 32-byte key as hex string (for debugging / storage keys).
 */
export function keyToHex(key: RawKey): string {
  return Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decode a hex string back to bytes.
 */
export function hexToKey(hex: string): RawKey {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
