/**
 * Double Ratchet protocol implementation.
 * Matches Rust accord-core double_ratchet.rs exactly:
 *   - KDF_RK: HKDF(salt=root_key, ikm=dh_output, info="accord-double-ratchet-root-v2") -> new_root_key
 *             HKDF(salt=root_key, ikm=dh_output, info="accord-double-ratchet-ck-v2") -> chain_key
 *   - KDF_CK: HKDF(salt=None, ikm=chain_key, info="accord-double-ratchet-chain-v2") -> new_chain_key
 *             HKDF(salt=None, ikm=chain_key, info="accord-double-ratchet-msg-v2") -> message_key
 *   - AES-256-GCM with 12-byte random nonce
 *   - Associated data = bincode-serialized header (32 + 4 + 4 = 40 bytes, LE u32s)
 */

// @ts-ignore
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { sha256 } from '@noble/hashes/sha2.js';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';

import { generateX25519KeyPair, x25519DH, x25519GetPublic, randomBytes, constantTimeEqual, type X25519KeyPair } from './keys';

const MAX_SKIP = 100;

const KDF_RK_INFO = new TextEncoder().encode('accord-double-ratchet-root-v2');
const KDF_CK_ROOT_INFO = new TextEncoder().encode('accord-double-ratchet-ck-v2');
const KDF_CK_CHAIN_INFO = new TextEncoder().encode('accord-double-ratchet-chain-v2');
const KDF_CK_MSG_INFO = new TextEncoder().encode('accord-double-ratchet-msg-v2');

/** Message header (unencrypted, sent with each message) */
export interface MessageHeader {
  dhPublicKey: Uint8Array;      // 32 bytes - sender's current DH ratchet public key
  previousChainLength: number;  // u32
  messageNumber: number;        // u32
}

/** Complete encrypted message */
export interface DoubleRatchetMessage {
  header: MessageHeader;
  ciphertext: Uint8Array; // 12-byte nonce + AES-GCM ciphertext (with 16-byte tag)
}

// ─── KDF functions (matching Rust exactly) ─────────────────────────────────

/**
 * Root key KDF: (root_key, dh_output) -> (new_root_key, chain_key)
 * Rust: kdf_rk uses HKDF with salt=root_key, ikm=dh_output
 */
function kdfRk(rootKey: Uint8Array, dhOutput: Uint8Array): [Uint8Array, Uint8Array] {
  // noble hkdf: hkdf(hash, ikm, salt, info, length)
  // Rust: Hkdf::<Sha256>::new(Some(root_key), dh_output) then expand with different infos
  const newRk = hkdf(sha256, dhOutput, rootKey, KDF_RK_INFO, 32);
  const ck = hkdf(sha256, dhOutput, rootKey, KDF_CK_ROOT_INFO, 32);
  return [new Uint8Array(newRk), new Uint8Array(ck)];
}

/**
 * Chain key KDF: chain_key -> (new_chain_key, message_key)
 * Rust: kdf_ck uses HKDF with salt=None, ikm=chain_key
 */
function kdfCk(chainKey: Uint8Array): [Uint8Array, Uint8Array] {
  const newCk = hkdf(sha256, chainKey, undefined, KDF_CK_CHAIN_INFO, 32);
  const mk = hkdf(sha256, chainKey, undefined, KDF_CK_MSG_INFO, 32);
  return [new Uint8Array(newCk), new Uint8Array(mk)];
}

// ─── Header AD (matching Rust bincode serialization) ────────────────────────

/**
 * Serialize header as associated data, matching Rust's bincode::serialize(header).
 * bincode format for MessageHeader { dh_public_key: [u8; 32], previous_chain_length: u32, message_number: u32 }:
 *   - [u8; 32] -> 32 raw bytes (no length prefix for fixed arrays)
 *   - u32 -> 4 bytes little-endian
 * Total: 40 bytes
 */
function headerAD(header: MessageHeader): Uint8Array {
  const ad = new Uint8Array(40);
  ad.set(header.dhPublicKey, 0);
  const view = new DataView(ad.buffer);
  view.setUint32(32, header.previousChainLength, true); // little-endian
  view.setUint32(36, header.messageNumber, true);
  return ad;
}

// ─── AES-256-GCM (matching Rust) ───────────────────────────────────────────

function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array, header: MessageHeader): Uint8Array {
  const nonce = randomBytes(12);
  const ad = headerAD(header);
  const cipher = gcm(key, nonce, ad);
  const ct = cipher.encrypt(plaintext);
  // Prepend nonce to ciphertext (matching Rust: nonce_bytes.to_vec() + ciphertext)
  const result = new Uint8Array(12 + ct.length);
  result.set(nonce, 0);
  result.set(ct, 12);
  return result;
}

function aesGcmDecrypt(key: Uint8Array, ciphertext: Uint8Array, header: MessageHeader): Uint8Array {
  if (ciphertext.length < 12) {
    throw new Error('Ciphertext too short');
  }
  const nonce = ciphertext.slice(0, 12);
  const ct = ciphertext.slice(12);
  const ad = headerAD(header);
  const cipher = gcm(key, nonce, ad);
  return cipher.decrypt(ct);
}

// ─── Skipped key map ────────────────────────────────────────────────────────

/** Key for skipped message lookup: dhPublicKey (base64) + messageNumber */
function skippedKeyId(dhPub: Uint8Array, msgNum: number): string {
  // Use a simple string key for the Map
  return Array.from(dhPub).join(',') + ':' + msgNum;
}

// ─── Double Ratchet Session ─────────────────────────────────────────────────

export class DoubleRatchetSession {
  private dhPrivate: Uint8Array;
  private dhPublic: Uint8Array;
  private dhRemote: Uint8Array | null;
  private rootKey: Uint8Array;
  private chainKeySend: Uint8Array | null;
  private chainKeyRecv: Uint8Array | null;
  private sendN: number;
  private recvN: number;
  private previousChainLength: number;
  private skippedKeys: Map<string, Uint8Array>;

  private constructor() {
    this.dhPrivate = new Uint8Array(32);
    this.dhPublic = new Uint8Array(32);
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
   * Initialize as session initiator (Alice).
   * Alice completed X3DH and knows shared_secret + Bob's signed prekey (initial ratchet pub).
   */
  static initAlice(sharedSecret: Uint8Array, bobRatchetPub: Uint8Array): DoubleRatchetSession {
    const session = new DoubleRatchetSession();
    const kp = generateX25519KeyPair();
    session.dhPrivate = kp.privateKey;
    session.dhPublic = kp.publicKey;
    session.dhRemote = bobRatchetPub;

    // Initial DH ratchet step
    const dhOutput = x25519DH(session.dhPrivate, bobRatchetPub);
    const [newRootKey, chainKeySend] = kdfRk(sharedSecret, dhOutput);
    session.rootKey = newRootKey;
    session.chainKeySend = chainKeySend;

    return session;
  }

  /**
   * Initialize as session responder (Bob).
   * Bob uses signed prekey as initial ratchet key pair.
   */
  static initBob(sharedSecret: Uint8Array, signedPrekeyPrivate: Uint8Array): DoubleRatchetSession {
    const session = new DoubleRatchetSession();
    session.dhPrivate = signedPrekeyPrivate;
    session.dhPublic = x25519GetPublic(signedPrekeyPrivate);
    session.dhRemote = null;
    session.rootKey = sharedSecret;
    session.chainKeySend = null;
    session.chainKeyRecv = null;

    return session;
  }

  /** Encrypt a plaintext message, advancing the sending chain. */
  encrypt(plaintext: Uint8Array): DoubleRatchetMessage {
    if (!this.chainKeySend) {
      throw new Error('No sending chain key');
    }
    const [newCk, mk] = kdfCk(this.chainKeySend);
    this.chainKeySend = newCk;

    const header: MessageHeader = {
      dhPublicKey: new Uint8Array(this.dhPublic),
      previousChainLength: this.previousChainLength,
      messageNumber: this.sendN,
    };

    const ciphertext = aesGcmEncrypt(mk, plaintext, header);
    this.sendN++;

    return { header, ciphertext };
  }

  /** Decrypt a received message, performing DH ratchet if needed. */
  decrypt(msg: DoubleRatchetMessage): Uint8Array {
    // Try skipped keys first
    const skipId = skippedKeyId(msg.header.dhPublicKey, msg.header.messageNumber);
    const skippedMk = this.skippedKeys.get(skipId);
    if (skippedMk) {
      this.skippedKeys.delete(skipId);
      return aesGcmDecrypt(skippedMk, msg.ciphertext, msg.header);
    }

    const theirPub = msg.header.dhPublicKey;

    // Check if we need a DH ratchet step
    const needDhRatchet = !this.dhRemote ||
      !constantTimeEqual(this.dhRemote, theirPub);

    if (needDhRatchet) {
      // Skip remaining messages in current receiving chain
      if (this.chainKeyRecv) {
        this.skipMessageKeys(msg.header.previousChainLength);
      }

      // DH ratchet step: receiving
      const dhOutput = x25519DH(this.dhPrivate, theirPub);
      const [newRoot, newCkRecv] = kdfRk(this.rootKey, dhOutput);
      this.rootKey = newRoot;
      this.chainKeyRecv = newCkRecv;
      this.dhRemote = new Uint8Array(theirPub);
      this.recvN = 0;

      // DH ratchet step: sending (generate new key pair)
      this.previousChainLength = this.sendN;
      this.sendN = 0;
      const newKp = generateX25519KeyPair();
      this.dhPrivate = newKp.privateKey;
      this.dhPublic = newKp.publicKey;

      const dhOutput2 = x25519DH(this.dhPrivate, this.dhRemote!);
      const [newRoot2, newCkSend] = kdfRk(this.rootKey, dhOutput2);
      this.rootKey = newRoot2;
      this.chainKeySend = newCkSend;
    }

    // Skip messages before this one in current chain
    this.skipMessageKeys(msg.header.messageNumber);

    // Derive the message key
    if (!this.chainKeyRecv) {
      throw new Error('No receiving chain key');
    }
    const [newCk, mk] = kdfCk(this.chainKeyRecv);
    this.chainKeyRecv = newCk;
    this.recvN++;

    return aesGcmDecrypt(mk, msg.ciphertext, msg.header);
  }

  /** Store skipped message keys up to `until` message number. */
  private skipMessageKeys(until: number): void {
    if (!this.chainKeyRecv) return;
    if (until - this.recvN > MAX_SKIP) {
      throw new Error(`Too many skipped messages (${until - this.recvN})`);
    }

    const dhPubBytes = this.dhRemote || new Uint8Array(32);
    let ck = this.chainKeyRecv;

    while (this.recvN < until) {
      const [newCk, mk] = kdfCk(ck);
      ck = newCk;
      this.skippedKeys.set(skippedKeyId(dhPubBytes, this.recvN), mk);
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
  ourPublicKey(): Uint8Array {
    return new Uint8Array(this.dhPublic);
  }

  /** Serialize session state for storage */
  serialize(): SerializedSession {
    const skipped: Record<string, string> = {};
    for (const [k, v] of this.skippedKeys) {
      skipped[k] = bytesToB64(v);
    }
    return {
      dhPrivate: bytesToB64(this.dhPrivate),
      dhPublic: bytesToB64(this.dhPublic),
      dhRemote: this.dhRemote ? bytesToB64(this.dhRemote) : null,
      rootKey: bytesToB64(this.rootKey),
      chainKeySend: this.chainKeySend ? bytesToB64(this.chainKeySend) : null,
      chainKeyRecv: this.chainKeyRecv ? bytesToB64(this.chainKeyRecv) : null,
      sendN: this.sendN,
      recvN: this.recvN,
      previousChainLength: this.previousChainLength,
      skippedKeys: skipped,
    };
  }

  /** Deserialize session state from storage */
  static deserialize(data: SerializedSession): DoubleRatchetSession {
    const session = new DoubleRatchetSession();
    session.dhPrivate = b64ToBytes(data.dhPrivate);
    session.dhPublic = b64ToBytes(data.dhPublic);
    session.dhRemote = data.dhRemote ? b64ToBytes(data.dhRemote) : null;
    session.rootKey = b64ToBytes(data.rootKey);
    session.chainKeySend = data.chainKeySend ? b64ToBytes(data.chainKeySend) : null;
    session.chainKeyRecv = data.chainKeyRecv ? b64ToBytes(data.chainKeyRecv) : null;
    session.sendN = data.sendN;
    session.recvN = data.recvN;
    session.previousChainLength = data.previousChainLength;
    session.skippedKeys = new Map();
    for (const [k, v] of Object.entries(data.skippedKeys)) {
      session.skippedKeys.set(k, b64ToBytes(v));
    }
    return session;
  }
}

/** Serializable session state */
export interface SerializedSession {
  dhPrivate: string;
  dhPublic: string;
  dhRemote: string | null;
  rootKey: string;
  chainKeySend: string | null;
  chainKeyRecv: string | null;
  sendN: number;
  recvN: number;
  previousChainLength: number;
  skippedKeys: Record<string, string>;
}

function bytesToB64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

function b64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
