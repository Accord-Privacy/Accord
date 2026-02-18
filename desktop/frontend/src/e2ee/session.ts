/**
 * @module session
 * Session manager for Double Ratchet E2EE.
 *
 * Manages one Double Ratchet session per peer. Handles:
 * - Session creation from X3DH output
 * - Message encryption/decryption with automatic session lookup
 * - Session state persistence to localStorage (encrypted with identity key)
 *
 * Usage:
 *   const mgr = new SessionManager(identityKeyPair);
 *   mgr.createSessionAsAlice(peerId, sharedSecret, peerRatchetPub);
 *   const encrypted = mgr.encrypt(peerId, "hello");
 *   const decrypted = mgr.decrypt(peerId, encrypted);
 */

// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';

import type { IdentityKeyPair, RawKey } from './keys';
import { keyToHex } from './keys';
import { DoubleRatchetSession, type DoubleRatchetMessage, type RatchetSessionState } from './ratchet';

const STORAGE_PREFIX = 'accord_e2ee_session_';

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

/**
 * Encrypt session state with identity key using AES-256-GCM.
 * Key is SHA-256(identityPrivateKey || "accord-session-storage").
 */
function encryptSessionState(state: RatchetSessionState, identityKey: RawKey): string {
  const keyMaterial = new Uint8Array(identityKey.length + 23);
  keyMaterial.set(identityKey, 0);
  keyMaterial.set(new TextEncoder().encode('accord-session-storage'), identityKey.length);
  const key = sha256(keyMaterial);

  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(JSON.stringify(state));
  const cipher = gcm(key, iv);
  const ciphertext = cipher.encrypt(plaintext);

  const combined = new Uint8Array(12 + ciphertext.length);
  combined.set(iv, 0);
  combined.set(ciphertext, 12);
  return toBase64(combined);
}

/**
 * Decrypt session state encrypted with identity key.
 */
function decryptSessionState(encrypted: string, identityKey: RawKey): RatchetSessionState {
  const keyMaterial = new Uint8Array(identityKey.length + 23);
  keyMaterial.set(identityKey, 0);
  keyMaterial.set(new TextEncoder().encode('accord-session-storage'), identityKey.length);
  const key = sha256(keyMaterial);

  const combined = fromBase64(encrypted);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const cipher = gcm(key, iv);
  const plaintext = cipher.decrypt(ciphertext);

  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ─── Session Manager ─────────────────────────────────────────────────────────

export class SessionManager {
  private sessions: Map<string, DoubleRatchetSession> = new Map();
  private identityKeyPair: IdentityKeyPair;

  constructor(identityKeyPair: IdentityKeyPair) {
    this.identityKeyPair = identityKeyPair;
  }

  /**
   * Create a new session as the initiator (Alice).
   *
   * Call after completing X3DH with a peer.
   *
   * @param peerId - Unique identifier for the peer (e.g., user ID or public key hash)
   * @param sharedSecret - 32-byte X3DH shared secret
   * @param peerRatchetPub - Peer's signed prekey (their initial ratchet public key)
   */
  createSessionAsAlice(peerId: string, sharedSecret: Uint8Array, peerRatchetPub: Uint8Array): void {
    const session = DoubleRatchetSession.initAlice(sharedSecret, peerRatchetPub);
    this.sessions.set(peerId, session);
    this.persistSession(peerId);
  }

  /**
   * Create a new session as the responder (Bob).
   *
   * Call when receiving the first message from a new peer.
   *
   * @param peerId - Unique identifier for the peer
   * @param sharedSecret - 32-byte X3DH shared secret
   * @param ourSignedPreKeyPrivate - Our signed prekey private key used in X3DH
   */
  createSessionAsBob(peerId: string, sharedSecret: Uint8Array, ourSignedPreKeyPrivate: Uint8Array): void {
    const session = DoubleRatchetSession.initBob(sharedSecret, ourSignedPreKeyPrivate);
    this.sessions.set(peerId, session);
    this.persistSession(peerId);
  }

  /**
   * Check if we have an active session with a peer.
   */
  hasSession(peerId: string): boolean {
    return this.sessions.has(peerId) || this.loadSession(peerId);
  }

  /**
   * Encrypt a plaintext string for a peer.
   *
   * @returns JSON string of DoubleRatchetMessage (ready to send as encrypted_data)
   * @throws If no session exists for the peer
   */
  encrypt(peerId: string, plaintext: string): string {
    const session = this.getSession(peerId);
    const plaintextBytes = new TextEncoder().encode(plaintext);
    const msg = session.encrypt(plaintextBytes);
    this.persistSession(peerId);
    return JSON.stringify(msg);
  }

  /**
   * Decrypt a ciphertext string from a peer.
   *
   * @param ciphertext - JSON string of DoubleRatchetMessage
   * @returns Decrypted plaintext string
   * @throws If no session exists or decryption fails
   */
  decrypt(peerId: string, ciphertext: string): string {
    const session = this.getSession(peerId);
    const msg: DoubleRatchetMessage = JSON.parse(ciphertext);
    const plaintext = session.decrypt(msg);
    this.persistSession(peerId);
    return new TextDecoder().decode(plaintext);
  }

  /**
   * Remove a session (e.g., when a peer is blocked or conversation deleted).
   */
  removeSession(peerId: string): void {
    this.sessions.delete(peerId);
    const storageKey = this.storageKeyFor(peerId);
    try { localStorage.removeItem(storageKey); } catch {}
  }

  // ─── Private ─────────────────────────────────────────────────────────

  private getSession(peerId: string): DoubleRatchetSession {
    let session = this.sessions.get(peerId);
    if (!session) {
      if (!this.loadSession(peerId)) {
        throw new Error(`No E2EE session with peer: ${peerId}`);
      }
      session = this.sessions.get(peerId)!;
    }
    return session;
  }

  private storageKeyFor(peerId: string): string {
    const idHash = keyToHex(this.identityKeyPair.publicKey).slice(0, 16);
    return `${STORAGE_PREFIX}${idHash}_${peerId}`;
  }

  /** Persist session state to localStorage (encrypted) */
  private persistSession(peerId: string): void {
    const session = this.sessions.get(peerId);
    if (!session) return;
    try {
      const state = session.serialize();
      const encrypted = encryptSessionState(state, this.identityKeyPair.privateKey);
      localStorage.setItem(this.storageKeyFor(peerId), encrypted);
    } catch (e) {
      console.warn('Failed to persist E2EE session:', e);
    }
  }

  /** Load session from localStorage. Returns true if found. */
  private loadSession(peerId: string): boolean {
    try {
      const encrypted = localStorage.getItem(this.storageKeyFor(peerId));
      if (!encrypted) return false;
      const state = decryptSessionState(encrypted, this.identityKeyPair.privateKey);
      this.sessions.set(peerId, DoubleRatchetSession.deserialize(state));
      return true;
    } catch (e) {
      console.warn('Failed to load E2EE session:', e);
      return false;
    }
  }
}
