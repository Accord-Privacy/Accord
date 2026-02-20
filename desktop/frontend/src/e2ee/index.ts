/**
 * @module e2ee
 * Public API for Accord's end-to-end encryption module.
 *
 * Wraps X3DH key agreement + Double Ratchet messaging into a simple interface.
 *
 * Usage:
 *   import { E2EEManager } from './e2ee';
 *
 *   const e2ee = new E2EEManager();
 *   await e2ee.initialize();  // generates or loads identity keys
 *
 *   // Initiating a session with a peer
 *   e2ee.initiateSession(peerId, peerPreKeyBundle);
 *
 *   // Encrypt/decrypt
 *   const encrypted = e2ee.encrypt(peerId, "hello");
 *   const decrypted = e2ee.decrypt(peerId, encrypted);
 */

export {
  generateIdentityKeyPair,
  generateSignedPreKey,
  generateOneTimePreKey,
  generateOneTimePreKeys,
  buildPreKeyBundle,
  keyToHex,
  hexToKey,
} from './keys';

export type {
  IdentityKeyPair,
  SignedPreKeyPair,
  OneTimePreKeyPair,
  PreKeyBundle,
  X25519KeyPair,
  RawKey,
} from './keys';

export { x3dhInitiate, x3dhRespond } from './x3dh';
export type { X3DHInitiatorOutput } from './x3dh';

export { DoubleRatchetSession } from './ratchet';
export type { MessageHeader, DoubleRatchetMessage, RatchetSessionState } from './ratchet';

export { SessionManager } from './session';

export {
  SenderKeyStore,
  generateSenderKey,
  senderKeyFingerprint,
  senderKeyToPublic,
  createSenderKeyState,
  senderKeyEncrypt,
  senderKeyDecrypt,
  buildDistributionMessage,
  parseDistributionMessage,
  isSenderKeyEnvelope,
  parseSenderKeyEnvelope,
  encryptChannelMessage,
  decryptChannelMessage,
} from './senderKeys';

export type {
  SenderKeyPrivate,
  SenderKeyPublic,
  SenderKeyState,
  SenderKeyEnvelope,
  SenderKeyDistributionMessage,
} from './senderKeys';

import type { IdentityKeyPair, SignedPreKeyPair, OneTimePreKeyPair, PreKeyBundle } from './keys';
import { generateIdentityKeyPair, generateSignedPreKey, generateOneTimePreKeys, buildPreKeyBundle } from './keys';
import { x3dhInitiate, x3dhRespond } from './x3dh';
import { SessionManager } from './session';

/**
 * High-level E2EE manager.
 *
 * Manages identity keys, prekey generation, X3DH handshakes,
 * and Double Ratchet sessions for all peers.
 */
export class E2EEManager {
  private identityKeyPair: IdentityKeyPair | null = null;
  private signedPreKey: SignedPreKeyPair | null = null;
  private oneTimePreKeys: OneTimePreKeyPair[] = [];
  private sessionManager: SessionManager | null = null;

  /** Whether the manager has been initialized with keys */
  get isInitialized(): boolean {
    return this.identityKeyPair !== null;
  }

  /**
   * Initialize with fresh keys. Call once at registration.
   * @returns PreKeyBundle to upload to the server
   */
  initialize(): PreKeyBundle {
    this.identityKeyPair = generateIdentityKeyPair();
    this.signedPreKey = generateSignedPreKey();
    this.oneTimePreKeys = generateOneTimePreKeys(10);
    this.sessionManager = new SessionManager(this.identityKeyPair);

    return buildPreKeyBundle(
      this.identityKeyPair,
      this.signedPreKey,
      this.oneTimePreKeys[0],
    );
  }

  /**
   * Initialize with existing keys (e.g., loaded from storage).
   */
  initializeWithKeys(
    identityKeyPair: IdentityKeyPair,
    signedPreKey: SignedPreKeyPair,
    oneTimePreKeys: OneTimePreKeyPair[] = [],
  ): void {
    this.identityKeyPair = identityKeyPair;
    this.signedPreKey = signedPreKey;
    this.oneTimePreKeys = oneTimePreKeys;
    this.sessionManager = new SessionManager(identityKeyPair);
  }

  /**
   * Initiate an E2EE session with a peer using their prekey bundle.
   * Performs X3DH as the initiator (Alice).
   *
   * @param peerId - Peer's unique identifier
   * @param peerBundle - Peer's published prekey bundle
   * @returns Ephemeral public key to include in the initial message to the peer
   */
  initiateSession(peerId: string, peerBundle: PreKeyBundle): Uint8Array {
    this.ensureInitialized();
    const { sharedSecret, ephemeralPublicKey } = x3dhInitiate(this.identityKeyPair!, peerBundle);
    this.sessionManager!.createSessionAsAlice(peerId, sharedSecret, peerBundle.signedPrekey);
    // Zeroize shared secret
    sharedSecret.fill(0);
    return ephemeralPublicKey;
  }

  /**
   * Accept an incoming E2EE session from a peer.
   * Performs X3DH as the responder (Bob).
   *
   * @param peerId - Peer's unique identifier
   * @param peerIdentityKey - Peer's identity public key
   * @param peerEphemeralKey - Peer's ephemeral public key (from initial message)
   * @param oneTimePreKeyIndex - Index of the one-time prekey used (if any)
   */
  acceptSession(
    peerId: string,
    peerIdentityKey: Uint8Array,
    peerEphemeralKey: Uint8Array,
    oneTimePreKeyIndex?: number,
  ): void {
    this.ensureInitialized();
    const otpk = oneTimePreKeyIndex !== undefined ? this.oneTimePreKeys[oneTimePreKeyIndex] : undefined;

    const sharedSecret = x3dhRespond(
      this.identityKeyPair!,
      this.signedPreKey!,
      otpk,
      peerIdentityKey,
      peerEphemeralKey,
    );

    this.sessionManager!.createSessionAsBob(peerId, sharedSecret, this.signedPreKey!.privateKey);

    // Remove consumed one-time prekey
    if (oneTimePreKeyIndex !== undefined) {
      this.oneTimePreKeys.splice(oneTimePreKeyIndex, 1);
    }

    sharedSecret.fill(0);
  }

  /**
   * Encrypt a plaintext message for a peer.
   * @returns JSON string (base64-safe, opaque to server)
   */
  encrypt(peerId: string, plaintext: string): string {
    this.ensureInitialized();
    return this.sessionManager!.encrypt(peerId, plaintext);
  }

  /**
   * Decrypt an encrypted message from a peer.
   * @param ciphertext - JSON string from encrypt()
   * @returns Plaintext string
   */
  decrypt(peerId: string, ciphertext: string): string {
    this.ensureInitialized();
    return this.sessionManager!.decrypt(peerId, ciphertext);
  }

  /** Check if we have a session with a peer */
  hasSession(peerId: string): boolean {
    return this.sessionManager?.hasSession(peerId) ?? false;
  }

  /** Get identity public key */
  getIdentityPublicKey(): Uint8Array | null {
    return this.identityKeyPair?.publicKey ?? null;
  }

  private ensureInitialized(): void {
    if (!this.identityKeyPair || !this.sessionManager) {
      throw new Error('E2EEManager not initialized. Call initialize() or initializeWithKeys() first.');
    }
  }
}
