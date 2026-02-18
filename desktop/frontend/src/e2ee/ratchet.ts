/**
 * @module ratchet
 * Double Ratchet algorithm implementation.
 *
 * Wire-compatible with the Rust implementation in core/src/double_ratchet.rs.
 * Uses identical KDF info strings and derivation logic:
 *
 * Root KDF:   HKDF(salt=root_key, ikm=dh_output, info="accord-double-ratchet-root-v2") → new_root_key
 *             HKDF(salt=root_key, ikm=dh_output, info="accord-double-ratchet-ck-v2")   → chain_key
 * Chain KDF:  HKDF(salt=None, ikm=chain_key, info="accord-double-ratchet-chain-v2")    → new_chain_key
 *             HKDF(salt=None, ikm=chain_key, info="accord-double-ratchet-msg-v2")      → message_key
 *
 * Message encryption: AES-256-GCM with 12-byte random nonce.
 * Associated data: serialized header (must match Rust's bincode format).
 *
 * Reference: https://signal.org/docs/specifications/doubleratchet/
 */

// @ts-ignore
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';

import { x25519DH } from './keys';
// @ts-ignore
import { x25519 } from '@noble/curves/ed25519.js';

// ─── Constants (must match Rust) ─────────────────────────────────────────────

const KDF_RK_INFO = new TextEncoder().encode('accord-double-ratchet-root-v2');
const KDF_CK_CHAIN_INFO = new TextEncoder().encode('accord-double-ratchet-chain-v2');
const KDF_CK_MSG_INFO = new TextEncoder().encode('accord-double-ratchet-msg-v2');
const KDF_RK_CK_INFO = new TextEncoder().encode('accord-double-ratchet-ck-v2');

/** Maximum skipped message keys to store (prevents DoS) */
const MAX_SKIP = 100;

// ─── Types ───────────────────────────────────────────────────────────────────

/** Unencrypted message header (sent alongside ciphertext) */
export interface MessageHeader {
  /** Sender's current DH ratchet public key (32 bytes, hex-encoded for JSON) */
  dhPublicKey: string;
  /** Number of messages in the previous sending chain */
  previousChainLength: number;
  /** Message number in the current sending chain */
  messageNumber: number;
}

/** Complete Double Ratchet message (header + ciphertext) */
export interface DoubleRatchetMessage {
  header: MessageHeader;
  /** Base64-encoded: 12-byte nonce || AES-GCM ciphertext (with 16-byte tag) */
  ciphertext: string;
}

/** Serializable session state for persistence */
export interface RatchetSessionState {
  dhPrivateKey: string;  // hex
  dhPublicKey: string;   // hex
  dhRemote: string | null; // hex
  rootKey: string;       // hex
  chainKeySend: string | null; // hex
  chainKeyRecv: string | null; // hex
  sendN: number;
  recvN: number;
  previousChainLength: number;
  skippedKeys: Array<{ dhPub: string; n: number; mk: string }>; // hex keys
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
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
 * Serialize header as associated data for AES-GCM.
 *
 * Must match Rust's `bincode::serialize(&MessageHeader)`.
 * Bincode default config for this struct:
 *   - dh_public_key: [u8; 32] → 32 raw bytes
 *   - previous_chain_length: u32 → 4 bytes little-endian
 *   - message_number: u32 → 4 bytes little-endian
 *   Total: 40 bytes
 */
function headerToAD(header: MessageHeader): Uint8Array {
  const dhPub = fromHex(header.dhPublicKey);
  const ad = new Uint8Array(40);
  ad.set(dhPub, 0);
  const view = new DataView(ad.buffer);
  view.setUint32(32, header.previousChainLength, true); // little-endian
  view.setUint32(36, header.messageNumber, true);
  return ad;
}

// ─── KDF functions (matching Rust exactly) ───────────────────────────────────

/**
 * Root key KDF: (root_key, dh_output) → (new_root_key, chain_key)
 *
 * Rust: Hkdf::new(Some(root_key), dh_output) then expand with two different info strings.
 * Noble: hkdf(sha256, ikm=dh_output, salt=root_key, info, 32)
 */
function kdfRK(rootKey: Uint8Array, dhOutput: Uint8Array): { newRootKey: Uint8Array; chainKey: Uint8Array } {
  const newRootKey = hkdf(sha256, dhOutput, rootKey, KDF_RK_INFO, 32);
  const chainKey = hkdf(sha256, dhOutput, rootKey, KDF_RK_CK_INFO, 32);
  return { newRootKey, chainKey };
}

/**
 * Chain key KDF: chain_key → (new_chain_key, message_key)
 *
 * Rust: Hkdf::new(None, chain_key) then expand with two info strings.
 * Noble: hkdf(sha256, ikm=chain_key, salt=undefined, info, 32)
 */
function kdfCK(chainKey: Uint8Array): { newChainKey: Uint8Array; messageKey: Uint8Array } {
  const newChainKey = hkdf(sha256, chainKey, undefined, KDF_CK_CHAIN_INFO, 32);
  const messageKey = hkdf(sha256, chainKey, undefined, KDF_CK_MSG_INFO, 32);
  return { newChainKey, messageKey };
}

// ─── AES-GCM ────────────────────────────────────────────────────────────────

function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const nonce = randomBytes(12);
  const cipher = gcm(key, nonce, ad);
  const ciphertext = cipher.encrypt(plaintext);
  // Prepend nonce (matches Rust: nonce_bytes || ciphertext)
  const result = new Uint8Array(12 + ciphertext.length);
  result.set(nonce, 0);
  result.set(ciphertext, 12);
  return result;
}

function aesGcmDecrypt(key: Uint8Array, data: Uint8Array, ad: Uint8Array): Uint8Array {
  if (data.length < 12) throw new Error('Ciphertext too short');
  const nonce = data.slice(0, 12);
  const ciphertext = data.slice(12);
  const cipher = gcm(key, nonce, ad);
  return cipher.decrypt(ciphertext);
}

// ─── Double Ratchet Session ──────────────────────────────────────────────────

/**
 * A Double Ratchet session between two parties.
 *
 * Implements the full Signal Double Ratchet with:
 * - DH ratchet (X25519 key rotation on direction change)
 * - Symmetric ratchet (HKDF chain keys for forward secrecy per message)
 * - Out-of-order message handling (skipped message keys cache)
 */
export class DoubleRatchetSession {
  private dhPrivateKey: Uint8Array;
  private dhPublicKey: Uint8Array;
  private dhRemote: Uint8Array | null;
  private rootKey: Uint8Array;
  private chainKeySend: Uint8Array | null;
  private chainKeyRecv: Uint8Array | null;
  private sendN: number;
  private recvN: number;
  private previousChainLength: number;
  /** Skipped message keys: Map<"dhPubHex:messageNumber", messageKey> */
  private skippedKeys: Map<string, Uint8Array>;

  private constructor() {
    this.dhPrivateKey = new Uint8Array(32);
    this.dhPublicKey = new Uint8Array(32);
    this.dhRemote = null;
    this.rootKey = new Uint8Array(32);
    this.chainKeySend = null;
    this.chainKeyRecv = null;
    this.sendN = 0;
    this.recvN = 0;
    this.previousChainLength = 0;
    this.skippedKeys = new Map();
  }

  /**
   * Initialize as the session initiator (Alice).
   *
   * Alice has completed X3DH and knows the shared secret.
   * She uses Bob's signed prekey as his initial ratchet public key,
   * then immediately performs one DH ratchet step to establish
   * her sending chain.
   *
   * @param sharedSecret - 32-byte output from X3DH
   * @param bobRatchetPub - Bob's signed prekey (his initial DH ratchet key)
   */
  static initAlice(sharedSecret: Uint8Array, bobRatchetPub: Uint8Array): DoubleRatchetSession {
    const session = new DoubleRatchetSession();

    // Generate our DH ratchet keypair
    session.dhPrivateKey = randomBytes(32);
    session.dhPublicKey = x25519.getPublicKey(session.dhPrivateKey);
    session.dhRemote = bobRatchetPub;

    // Perform initial DH ratchet step (matching Rust's init_alice)
    const dhOutput = x25519DH(session.dhPrivateKey, bobRatchetPub);
    const { newRootKey, chainKey } = kdfRK(sharedSecret, dhOutput);
    session.rootKey = newRootKey;
    session.chainKeySend = chainKey;

    return session;
  }

  /**
   * Initialize as the session responder (Bob).
   *
   * Bob uses his signed prekey as the initial ratchet keypair.
   * He waits for Alice's first message to perform the DH ratchet.
   *
   * @param sharedSecret - 32-byte output from X3DH
   * @param ourSignedPreKeyPrivate - Bob's signed prekey private key
   */
  static initBob(sharedSecret: Uint8Array, ourSignedPreKeyPrivate: Uint8Array): DoubleRatchetSession {
    const session = new DoubleRatchetSession();
    session.dhPrivateKey = ourSignedPreKeyPrivate;
    session.dhPublicKey = x25519.getPublicKey(ourSignedPreKeyPrivate);
    session.rootKey = new Uint8Array(sharedSecret);
    return session;
  }

  /**
   * Encrypt a plaintext message, advancing the sending chain.
   *
   * Each call:
   * 1. Derives a message key from the sending chain key
   * 2. Encrypts plaintext with AES-256-GCM using the message key
   * 3. Includes the header as associated data (tamper-proof)
   * 4. Advances the chain key (forward secrecy)
   */
  encrypt(plaintext: Uint8Array): DoubleRatchetMessage {
    if (!this.chainKeySend) throw new Error('No sending chain key — session not fully initialized');

    const { newChainKey, messageKey } = kdfCK(this.chainKeySend);
    this.chainKeySend = newChainKey;

    const header: MessageHeader = {
      dhPublicKey: toHex(this.dhPublicKey),
      previousChainLength: this.previousChainLength,
      messageNumber: this.sendN,
    };

    const ad = headerToAD(header);
    const ciphertext = aesGcmEncrypt(messageKey, plaintext, ad);

    // Zeroize message key
    messageKey.fill(0);

    this.sendN++;

    return { header, ciphertext: toBase64(ciphertext) };
  }

  /**
   * Decrypt a received message, performing DH ratchet step if needed.
   *
   * Steps:
   * 1. Check skipped message keys (for out-of-order messages)
   * 2. If sender's DH key changed → perform DH ratchet (new receiving + sending chains)
   * 3. Skip ahead if message number > current receive counter
   * 4. Derive message key and decrypt
   */
  decrypt(msg: DoubleRatchetMessage): Uint8Array {
    const theirPubHex = msg.header.dhPublicKey;
    const theirPub = fromHex(theirPubHex);

    // 1. Try skipped keys first
    const skipKey = `${theirPubHex}:${msg.header.messageNumber}`;
    const skippedMk = this.skippedKeys.get(skipKey);
    if (skippedMk) {
      this.skippedKeys.delete(skipKey);
      const ad = headerToAD(msg.header);
      const result = aesGcmDecrypt(skippedMk, fromBase64(msg.ciphertext), ad);
      skippedMk.fill(0);
      return result;
    }

    // 2. Check if DH ratchet needed
    const currentRemoteHex = this.dhRemote ? toHex(this.dhRemote) : null;
    if (currentRemoteHex !== theirPubHex) {
      // Skip remaining messages in current receiving chain
      if (this.chainKeyRecv !== null) {
        this.skipMessageKeys(msg.header.previousChainLength);
      }

      // DH ratchet step: receiving
      const dhOutput = x25519DH(this.dhPrivateKey, theirPub);
      const { newRootKey, chainKey } = kdfRK(this.rootKey, dhOutput);
      this.rootKey = newRootKey;
      this.chainKeyRecv = chainKey;
      this.dhRemote = theirPub;
      this.recvN = 0;

      // DH ratchet step: sending (generate new keypair)
      this.previousChainLength = this.sendN;
      this.sendN = 0;
      this.dhPrivateKey = randomBytes(32);
      this.dhPublicKey = x25519.getPublicKey(this.dhPrivateKey);

      const dhOutput2 = x25519DH(this.dhPrivateKey, this.dhRemote!);
      const rk2 = kdfRK(this.rootKey, dhOutput2);
      this.rootKey = rk2.newRootKey;
      this.chainKeySend = rk2.chainKey;
    }

    // 3. Skip ahead if needed
    this.skipMessageKeys(msg.header.messageNumber);

    // 4. Derive message key and decrypt
    if (!this.chainKeyRecv) throw new Error('No receiving chain key');
    const { newChainKey, messageKey } = kdfCK(this.chainKeyRecv);
    this.chainKeyRecv = newChainKey;
    this.recvN++;

    const ad = headerToAD(msg.header);
    const result = aesGcmDecrypt(messageKey, fromBase64(msg.ciphertext), ad);
    messageKey.fill(0);
    return result;
  }

  /**
   * Store skipped message keys up to `until` message number.
   * These allow decrypting out-of-order messages later.
   */
  private skipMessageKeys(until: number): void {
    if (!this.chainKeyRecv) return;
    if (until - this.recvN > MAX_SKIP) {
      throw new Error(`Too many skipped messages (${until - this.recvN})`);
    }

    const dhPubHex = this.dhRemote ? toHex(this.dhRemote) : '00'.repeat(32);
    let ck = this.chainKeyRecv;

    while (this.recvN < until) {
      const { newChainKey, messageKey } = kdfCK(ck);
      ck = newChainKey;
      this.skippedKeys.set(`${dhPubHex}:${this.recvN}`, messageKey);
      this.recvN++;

      // Evict oldest if over limit
      if (this.skippedKeys.size > MAX_SKIP) {
        const firstKey = this.skippedKeys.keys().next().value;
        if (firstKey) this.skippedKeys.delete(firstKey);
      }
    }
    this.chainKeyRecv = ck;
  }

  /** Get our current ratchet public key */
  get ourPublicKey(): Uint8Array {
    return new Uint8Array(this.dhPublicKey);
  }

  /** Serialize session state for persistence */
  serialize(): RatchetSessionState {
    const skipped: Array<{ dhPub: string; n: number; mk: string }> = [];
    for (const [key, mk] of this.skippedKeys) {
      const [dhPub, nStr] = key.split(':');
      skipped.push({ dhPub, n: parseInt(nStr, 10), mk: toHex(mk) });
    }

    return {
      dhPrivateKey: toHex(this.dhPrivateKey),
      dhPublicKey: toHex(this.dhPublicKey),
      dhRemote: this.dhRemote ? toHex(this.dhRemote) : null,
      rootKey: toHex(this.rootKey),
      chainKeySend: this.chainKeySend ? toHex(this.chainKeySend) : null,
      chainKeyRecv: this.chainKeyRecv ? toHex(this.chainKeyRecv) : null,
      sendN: this.sendN,
      recvN: this.recvN,
      previousChainLength: this.previousChainLength,
      skippedKeys: skipped,
    };
  }

  /** Restore session from serialized state */
  static deserialize(state: RatchetSessionState): DoubleRatchetSession {
    const session = new DoubleRatchetSession();
    session.dhPrivateKey = fromHex(state.dhPrivateKey);
    session.dhPublicKey = fromHex(state.dhPublicKey);
    session.dhRemote = state.dhRemote ? fromHex(state.dhRemote) : null;
    session.rootKey = fromHex(state.rootKey);
    session.chainKeySend = state.chainKeySend ? fromHex(state.chainKeySend) : null;
    session.chainKeyRecv = state.chainKeyRecv ? fromHex(state.chainKeyRecv) : null;
    session.sendN = state.sendN;
    session.recvN = state.recvN;
    session.previousChainLength = state.previousChainLength;

    for (const { dhPub, n, mk } of state.skippedKeys) {
      session.skippedKeys.set(`${dhPub}:${n}`, fromHex(mk));
    }

    return session;
  }
}
