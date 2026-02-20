/**
 * @module senderKeys
 * Sender Keys E2EE for Accord channel encryption.
 *
 * Each channel member maintains their own symmetric ratchet chain.
 * Messages are encrypted once with the sender's key (O(1) per send).
 * Keys are distributed via Double Ratchet encrypted DMs.
 *
 * See docs/sender-keys-design.md for the full design.
 */

// @ts-ignore - noble v2 uses .js exports
import { sha256 } from '@noble/hashes/sha2.js';
// @ts-ignore
import { hmac } from '@noble/hashes/hmac.js';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';
// @ts-ignore
import { ed25519 } from '@noble/curves/ed25519.js';

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

function uint8ToBase64(u8: Uint8Array): string {
  const binary = String.fromCharCode(...u8);
  return btoa(binary);
}

function base64ToUint8(b64: string): Uint8Array {
  const binary = atob(b64);
  const u8 = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) u8[i] = binary.charCodeAt(i);
  return u8;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Private sender key — only held by the key owner */
export interface SenderKeyPrivate {
  chainKey: Uint8Array;        // 32 bytes — current chain key
  signingKey: Uint8Array;      // 32 bytes — Ed25519 private key
  signingPubKey: Uint8Array;   // 32 bytes — Ed25519 public key
  iteration: number;           // chain step counter
}

/** Public sender key — shared with channel members for decryption */
export interface SenderKeyPublic {
  chainKey: Uint8Array;        // 32 bytes (at distribution time)
  signingPubKey: Uint8Array;   // 32 bytes
  iteration: number;           // starting iteration
  senderKeyId: string;         // fingerprint for lookup
}

/** Receiver's state tracking a remote sender's key */
export interface SenderKeyState {
  key: SenderKeyPublic;
  currentChainKey: Uint8Array;
  currentIteration: number;
  skippedMessageKeys: Map<number, Uint8Array>; // iteration → messageKey
}

/** Compact wire format envelope (stored in message content) */
export interface SenderKeyEnvelope {
  v: 1;                        // version marker
  sk: string;                  // sender key ID (fingerprint)
  i: number;                   // chain iteration
  iv: string;                  // base64 12-byte nonce
  ct: string;                  // base64 ciphertext
  sig: string;                 // base64 Ed25519 signature over iv||ct
}

/** Distribution message sent via DR DM */
export interface SenderKeyDistributionMessage {
  type: 'skdm';
  ch: string;                  // channel ID
  skid: string;                // sender key ID
  ck: string;                  // base64 chain key
  spk: string;                 // base64 signing public key
  iter: number;                // starting iteration
  rep: string | null;          // replaces key ID (rotation)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_SKIP = 2000;
const CHAIN_KEY_INFO = new TextEncoder().encode('ChainKey');
const MESSAGE_KEY_INFO = new TextEncoder().encode('MessageKey');

// ---------------------------------------------------------------------------
// Key Generation
// ---------------------------------------------------------------------------

/** Generate a fresh sender key for a channel. */
export function generateSenderKey(): SenderKeyPrivate {
  const chainKey = randomBytes(32);
  const signingKey = ed25519.utils.randomSecretKey();
  const signingPubKey = ed25519.getPublicKey(signingKey);
  return { chainKey, signingKey, signingPubKey, iteration: 0 };
}

/** Compute a short hex fingerprint of a signing public key. */
export function senderKeyFingerprint(signingPubKey: Uint8Array): string {
  return Array.from(sha256(signingPubKey).slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Extract the public portion of a sender key (for distribution). */
export function senderKeyToPublic(sk: SenderKeyPrivate): SenderKeyPublic {
  return {
    chainKey: new Uint8Array(sk.chainKey),
    signingPubKey: new Uint8Array(sk.signingPubKey),
    iteration: sk.iteration,
    senderKeyId: senderKeyFingerprint(sk.signingPubKey),
  };
}

/** Create a SenderKeyState for tracking a received public key. */
export function createSenderKeyState(pub: SenderKeyPublic): SenderKeyState {
  return {
    key: pub,
    currentChainKey: new Uint8Array(pub.chainKey),
    currentIteration: pub.iteration,
    skippedMessageKeys: new Map(),
  };
}

// ---------------------------------------------------------------------------
// Chain Ratchet
// ---------------------------------------------------------------------------

function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
  return hmac(sha256, chainKey, MESSAGE_KEY_INFO);
}

function advanceChainKey(chainKey: Uint8Array): Uint8Array {
  return hmac(sha256, chainKey, CHAIN_KEY_INFO);
}

// ---------------------------------------------------------------------------
// Encrypt (sender side)
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext using the sender's own sender key.
 * Returns the wire envelope and the updated key (chain advanced).
 */
export function senderKeyEncrypt(
  sk: SenderKeyPrivate,
  plaintext: Uint8Array,
): { envelope: SenderKeyEnvelope; updatedKey: SenderKeyPrivate } {
  const messageKey = deriveMessageKey(sk.chainKey);
  const nextChainKey = advanceChainKey(sk.chainKey);

  const iv = randomBytes(12);
  const cipher = gcm(messageKey, iv);
  const ciphertext = cipher.encrypt(plaintext);

  // Sign iv || ciphertext
  const toSign = new Uint8Array(iv.length + ciphertext.length);
  toSign.set(iv);
  toSign.set(ciphertext, iv.length);
  const signature = ed25519.sign(toSign, sk.signingKey);

  const envelope: SenderKeyEnvelope = {
    v: 1,
    sk: senderKeyFingerprint(sk.signingPubKey),
    i: sk.iteration,
    iv: uint8ToBase64(iv),
    ct: uint8ToBase64(ciphertext),
    sig: uint8ToBase64(signature),
  };

  const updatedKey: SenderKeyPrivate = {
    ...sk,
    chainKey: nextChainKey,
    iteration: sk.iteration + 1,
  };

  return { envelope, updatedKey };
}

// ---------------------------------------------------------------------------
// Decrypt (receiver side)
// ---------------------------------------------------------------------------

/**
 * Decrypt a sender key envelope using the receiver's stored state for that sender.
 * Returns the plaintext and updated state (chain advanced, skipped keys cached).
 */
export function senderKeyDecrypt(
  state: SenderKeyState,
  envelope: SenderKeyEnvelope,
): { plaintext: Uint8Array; updatedState: SenderKeyState } {
  const iv = base64ToUint8(envelope.iv);
  const ciphertext = base64ToUint8(envelope.ct);
  const signature = base64ToUint8(envelope.sig);

  // Verify Ed25519 signature
  const toVerify = new Uint8Array(iv.length + ciphertext.length);
  toVerify.set(iv);
  toVerify.set(ciphertext, iv.length);
  if (!ed25519.verify(signature, toVerify, state.key.signingPubKey)) {
    throw new Error('Sender key signature verification failed');
  }

  let messageKey: Uint8Array;
  const newState: SenderKeyState = {
    ...state,
    currentChainKey: new Uint8Array(state.currentChainKey),
    currentIteration: state.currentIteration,
    skippedMessageKeys: new Map(state.skippedMessageKeys),
  };

  if (envelope.i < state.currentIteration) {
    // Out-of-order: use cached key
    const cached = newState.skippedMessageKeys.get(envelope.i);
    if (!cached) throw new Error(`No cached key for iteration ${envelope.i}`);
    messageKey = cached;
    newState.skippedMessageKeys.delete(envelope.i);
  } else {
    // Advance chain, caching skipped keys
    if (envelope.i - state.currentIteration > MAX_SKIP) {
      throw new Error(`Too many skipped messages: ${envelope.i - state.currentIteration}`);
    }

    let chainKey = newState.currentChainKey;
    let iter = newState.currentIteration;

    while (iter < envelope.i) {
      newState.skippedMessageKeys.set(iter, deriveMessageKey(chainKey));
      chainKey = advanceChainKey(chainKey);
      iter++;
    }

    messageKey = deriveMessageKey(chainKey);
    newState.currentChainKey = advanceChainKey(chainKey);
    newState.currentIteration = iter + 1;
  }

  // Prune excess skipped keys
  if (newState.skippedMessageKeys.size > MAX_SKIP) {
    const sorted = [...newState.skippedMessageKeys.keys()].sort((a, b) => a - b);
    while (newState.skippedMessageKeys.size > MAX_SKIP) {
      newState.skippedMessageKeys.delete(sorted.shift()!);
    }
  }

  const decipher = gcm(messageKey, iv);
  const plaintext = decipher.decrypt(ciphertext);

  return { plaintext, updatedState: newState };
}

// ---------------------------------------------------------------------------
// Distribution message helpers
// ---------------------------------------------------------------------------

/** Build a distribution message to send via DR DM. */
export function buildDistributionMessage(
  channelId: string,
  sk: SenderKeyPrivate,
  replacesKeyId?: string,
): SenderKeyDistributionMessage {
  return {
    type: 'skdm',
    ch: channelId,
    skid: senderKeyFingerprint(sk.signingPubKey),
    ck: uint8ToBase64(sk.chainKey),
    spk: uint8ToBase64(sk.signingPubKey),
    iter: sk.iteration,
    rep: replacesKeyId ?? null,
  };
}

/** Parse a distribution message and create a SenderKeyPublic + State from it. */
export function parseDistributionMessage(
  msg: SenderKeyDistributionMessage,
): { pub: SenderKeyPublic; state: SenderKeyState } {
  const pub: SenderKeyPublic = {
    chainKey: base64ToUint8(msg.ck),
    signingPubKey: base64ToUint8(msg.spk),
    iteration: msg.iter,
    senderKeyId: msg.skid,
  };
  return { pub, state: createSenderKeyState(pub) };
}

// ---------------------------------------------------------------------------
// Envelope detection
// ---------------------------------------------------------------------------

/** Check if a message content string is a sender key envelope. */
export function isSenderKeyEnvelope(content: string): boolean {
  try {
    const obj = JSON.parse(content);
    return obj && obj.v === 1 && typeof obj.sk === 'string' && typeof obj.i === 'number';
  } catch {
    return false;
  }
}

/** Parse a sender key envelope from a message content string. */
export function parseSenderKeyEnvelope(content: string): SenderKeyEnvelope {
  const obj = JSON.parse(content);
  if (obj.v !== 1) throw new Error(`Unknown sender key envelope version: ${obj.v}`);
  return obj as SenderKeyEnvelope;
}

// ---------------------------------------------------------------------------
// SenderKeyStore — manages all sender keys for all channels
// ---------------------------------------------------------------------------

export class SenderKeyStore {
  /** My own sender keys: channelId → SenderKeyPrivate */
  private myKeys = new Map<string, SenderKeyPrivate>();

  /** Peer sender key states: channelId → (userId → SenderKeyState) */
  private peerKeys = new Map<string, Map<string, SenderKeyState>>();

  // ── My keys ──

  /** Get or generate my sender key for a channel. */
  getOrCreateMyKey(channelId: string): SenderKeyPrivate {
    let sk = this.myKeys.get(channelId);
    if (!sk) {
      sk = generateSenderKey();
      this.myKeys.set(channelId, sk);
    }
    return sk;
  }

  getMyKey(channelId: string): SenderKeyPrivate | undefined {
    return this.myKeys.get(channelId);
  }

  setMyKey(channelId: string, sk: SenderKeyPrivate): void {
    this.myKeys.set(channelId, sk);
  }

  /** Update my key after sending (chain advanced). */
  updateMyKey(channelId: string, updatedKey: SenderKeyPrivate): void {
    this.myKeys.set(channelId, updatedKey);
  }

  /** Rotate my key for a channel (generates fresh key). Returns the new key. */
  rotateMyKey(channelId: string): SenderKeyPrivate {
    const sk = generateSenderKey();
    this.myKeys.set(channelId, sk);
    return sk;
  }

  // ── Peer keys ──

  /** Store a peer's sender key state. */
  setPeerKey(channelId: string, userId: string, state: SenderKeyState): void {
    let channelPeers = this.peerKeys.get(channelId);
    if (!channelPeers) {
      channelPeers = new Map();
      this.peerKeys.set(channelId, channelPeers);
    }
    channelPeers.set(userId, state);
  }

  /** Get a peer's sender key state. */
  getPeerKey(channelId: string, userId: string): SenderKeyState | undefined {
    return this.peerKeys.get(channelId)?.get(userId);
  }

  /** Update a peer's state after decryption (chain advanced). */
  updatePeerKey(channelId: string, userId: string, state: SenderKeyState): void {
    this.setPeerKey(channelId, userId, state);
  }

  /** Remove a specific peer's key (on member removal). */
  removePeerKey(channelId: string, userId: string): void {
    this.peerKeys.get(channelId)?.delete(userId);
  }

  /** Remove all peer keys for a channel (on full rotation). */
  clearChannelPeerKeys(channelId: string): void {
    this.peerKeys.delete(channelId);
  }

  /** Check if we have sender keys set up for a channel. */
  hasChannelKeys(channelId: string): boolean {
    return this.myKeys.has(channelId);
  }

  /** Check if we have a specific peer's key for a channel. */
  hasPeerKey(channelId: string, userId: string): boolean {
    return this.peerKeys.get(channelId)?.has(userId) ?? false;
  }

  // ── Serialization (for persistence) ──

  /** Export store to a JSON-serializable object. */
  exportStore(): object {
    const myKeysObj: Record<string, object> = {};
    for (const [chId, sk] of this.myKeys) {
      myKeysObj[chId] = {
        chainKey: uint8ToBase64(sk.chainKey),
        signingKey: uint8ToBase64(sk.signingKey),
        signingPubKey: uint8ToBase64(sk.signingPubKey),
        iteration: sk.iteration,
      };
    }

    const peerKeysObj: Record<string, Record<string, object>> = {};
    for (const [chId, peers] of this.peerKeys) {
      peerKeysObj[chId] = {};
      for (const [userId, state] of peers) {
        const skipped: Record<string, string> = {};
        for (const [iter, key] of state.skippedMessageKeys) {
          skipped[iter.toString()] = uint8ToBase64(key);
        }
        peerKeysObj[chId][userId] = {
          key: {
            chainKey: uint8ToBase64(state.key.chainKey),
            signingPubKey: uint8ToBase64(state.key.signingPubKey),
            iteration: state.key.iteration,
            senderKeyId: state.key.senderKeyId,
          },
          currentChainKey: uint8ToBase64(state.currentChainKey),
          currentIteration: state.currentIteration,
          skippedMessageKeys: skipped,
        };
      }
    }

    return { myKeys: myKeysObj, peerKeys: peerKeysObj };
  }

  /** Import store from a previously exported object. */
  importStore(data: any): void {
    this.myKeys.clear();
    this.peerKeys.clear();

    if (data.myKeys) {
      for (const [chId, sk] of Object.entries(data.myKeys) as any[]) {
        this.myKeys.set(chId, {
          chainKey: base64ToUint8(sk.chainKey),
          signingKey: base64ToUint8(sk.signingKey),
          signingPubKey: base64ToUint8(sk.signingPubKey),
          iteration: sk.iteration,
        });
      }
    }

    if (data.peerKeys) {
      for (const [chId, peers] of Object.entries(data.peerKeys) as any[]) {
        const peerMap = new Map<string, SenderKeyState>();
        for (const [userId, stateObj] of Object.entries(peers) as any[]) {
          const skipped = new Map<number, Uint8Array>();
          if (stateObj.skippedMessageKeys) {
            for (const [iter, key] of Object.entries(stateObj.skippedMessageKeys) as any[]) {
              skipped.set(parseInt(iter), base64ToUint8(key));
            }
          }
          peerMap.set(userId, {
            key: {
              chainKey: base64ToUint8(stateObj.key.chainKey),
              signingPubKey: base64ToUint8(stateObj.key.signingPubKey),
              iteration: stateObj.key.iteration,
              senderKeyId: stateObj.key.senderKeyId,
            },
            currentChainKey: base64ToUint8(stateObj.currentChainKey),
            currentIteration: stateObj.currentIteration,
            skippedMessageKeys: skipped,
          });
        }
        this.peerKeys.set(chId, peerMap);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// High-level encrypt/decrypt for channel messages
// ---------------------------------------------------------------------------

/**
 * Encrypt a channel message using sender keys.
 * Returns the JSON envelope string and the updated sender key.
 */
export function encryptChannelMessage(
  store: SenderKeyStore,
  channelId: string,
): { encryptFn: (plaintext: string) => string } {
  return {
    encryptFn(plaintext: string): string {
      const sk = store.getOrCreateMyKey(channelId);
      const data = new TextEncoder().encode(plaintext);
      const { envelope, updatedKey } = senderKeyEncrypt(sk, data);
      store.updateMyKey(channelId, updatedKey);
      return JSON.stringify(envelope);
    },
  };
}

/**
 * Decrypt a channel message that's a sender key envelope.
 * Returns plaintext or throws if the sender's key is unknown.
 */
export function decryptChannelMessage(
  store: SenderKeyStore,
  channelId: string,
  senderId: string,
  envelopeStr: string,
): string {
  const envelope = parseSenderKeyEnvelope(envelopeStr);
  const state = store.getPeerKey(channelId, senderId);
  if (!state) {
    throw new Error(`No sender key for user ${senderId} in channel ${channelId}`);
  }
  const { plaintext, updatedState } = senderKeyDecrypt(state, envelope);
  store.updatePeerKey(channelId, senderId, updatedState);
  return new TextDecoder().decode(plaintext);
}
