/**
 * @module metadata
 * Node Metadata Key (NMK) encryption for node/channel names and descriptions.
 *
 * The relay stores metadata as opaque encrypted blobs; only NMK holders can
 * read names. The NMK is derived deterministically by the node creator and
 * shared with members over Double Ratchet sessions.
 *
 * Wire format (must match `core/src/metadata_crypto.rs`):
 *   [version: 1 byte] [nonce: 12 bytes] [AES-256-GCM ciphertext + 16-byte tag]
 *
 * Key derivation: HKDF-SHA256(ikm = creator identity key material,
 * salt = node ID bytes, info = "accord-node-metadata-v1") → 32 bytes.
 * By convention the node ID is the UTF-8 bytes of the lowercase hyphenated
 * UUID string.
 *
 * See docs/metadata-privacy.md for the full design.
 */

// @ts-ignore - noble v2 uses .js exports
import { sha256 } from '@noble/hashes/sha2.js';
// @ts-ignore
import { hkdf } from '@noble/hashes/hkdf.js';
// @ts-ignore
import { gcm } from '@noble/ciphers/aes.js';
import { deriveAtRestKey, hasStorageMasterKey, AT_REST_V2_TAG } from './storageKey';

const METADATA_VERSION = 1;
const NONCE_SIZE = 12;
const HKDF_INFO = 'accord-node-metadata-v1';

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Node Metadata Key
// ---------------------------------------------------------------------------

/** A node metadata key used to encrypt/decrypt node and channel names. */
export class NodeMetadataKey {
  private keyBytes: Uint8Array;

  private constructor(keyBytes: Uint8Array) {
    if (keyBytes.length !== 32) {
      throw new Error('NodeMetadataKey must be 32 bytes');
    }
    this.keyBytes = keyBytes;
  }

  /**
   * Derive a node metadata key from the creator's identity key material and
   * the node ID (lowercase hyphenated UUID string).
   */
  static derive(identityKeyMaterial: Uint8Array, nodeId: string): NodeMetadataKey {
    const salt = new TextEncoder().encode(nodeId);
    const info = new TextEncoder().encode(HKDF_INFO);
    const key = hkdf(sha256, identityKeyMaterial, salt, info, 32);
    return new NodeMetadataKey(key);
  }

  /** Create from raw 32-byte key (e.g. received over Double Ratchet). */
  static fromBytes(bytes: Uint8Array): NodeMetadataKey {
    return new NodeMetadataKey(new Uint8Array(bytes));
  }

  /** Export the raw key bytes (for sharing via Double Ratchet). */
  asBytes(): Uint8Array {
    return new Uint8Array(this.keyBytes);
  }

  /** Encrypt a metadata string. Returns the versioned blob. */
  encrypt(plaintext: string): Uint8Array {
    const nonce = randomBytes(NONCE_SIZE);
    const cipher = gcm(this.keyBytes, nonce);
    const ciphertext = cipher.encrypt(new TextEncoder().encode(plaintext));

    const out = new Uint8Array(1 + NONCE_SIZE + ciphertext.length);
    out[0] = METADATA_VERSION;
    out.set(nonce, 1);
    out.set(ciphertext, 1 + NONCE_SIZE);
    return out;
  }

  /** Decrypt a metadata blob back to a string. Throws on wrong key/tampering. */
  decrypt(blob: Uint8Array): string {
    if (blob.length === 0) throw new Error('empty metadata blob');
    if (blob[0] !== METADATA_VERSION) {
      throw new Error(`unsupported metadata version: ${blob[0]}`);
    }
    if (blob.length < 1 + NONCE_SIZE + 1) throw new Error('metadata blob too short');

    const nonce = blob.slice(1, 1 + NONCE_SIZE);
    const ciphertext = blob.slice(1 + NONCE_SIZE);
    const cipher = gcm(this.keyBytes, nonce);
    const plaintext = cipher.decrypt(ciphertext);
    return new TextDecoder().decode(plaintext);
  }

  /** Encrypt to a base64 string (the API wire representation). */
  encryptToBase64(plaintext: string): string {
    return toBase64(this.encrypt(plaintext));
  }

  /** Decrypt from a base64 string (the API wire representation). */
  decryptFromBase64(b64: string): string {
    return this.decrypt(fromBase64(b64));
  }
}

// ---------------------------------------------------------------------------
// NMK store persistence
// ---------------------------------------------------------------------------
// Mirrors the sender-key store pattern in ./persistence.ts: AES-256-GCM with a
// key derived from SHA-256(password || domain), stored per user in localStorage.

const NMK_STORAGE_PREFIX = 'accord_e2ee_nmk_';
const NMK_DOMAIN = 'accord-e2ee-nmk-storage';

/** Persist a map of nodeId → NodeMetadataKey. At-rest key is two-factor
 *  HKDF(password, SMK) on desktop; see ./storageKey. v2 blobs are tag-prefixed. */
export function saveNmkStore(
  userId: string,
  store: Map<string, NodeMetadataKey>,
  password: string,
): void {
  try {
    const entries: Record<string, string> = {};
    for (const [nodeId, key] of store) {
      entries[nodeId] = toBase64(key.asBytes());
    }
    const key = deriveAtRestKey(password, NMK_DOMAIN);
    const nonce = randomBytes(NONCE_SIZE);
    const plaintext = new TextEncoder().encode(JSON.stringify(entries));
    const ciphertext = gcm(key, nonce).encrypt(plaintext);
    if (hasStorageMasterKey()) {
      const combined = new Uint8Array(1 + NONCE_SIZE + ciphertext.length);
      combined[0] = AT_REST_V2_TAG;
      combined.set(nonce, 1);
      combined.set(ciphertext, 1 + NONCE_SIZE);
      localStorage.setItem(`${NMK_STORAGE_PREFIX}${userId}`, toBase64(combined));
    } else {
      const combined = new Uint8Array(NONCE_SIZE + ciphertext.length);
      combined.set(nonce, 0);
      combined.set(ciphertext, NONCE_SIZE);
      localStorage.setItem(`${NMK_STORAGE_PREFIX}${userId}`, toBase64(combined));
    }
  } catch (e) {
    console.warn('Failed to persist NMK store:', e);
  }
}

/** Load a persisted NMK store. Returns null if absent or undecryptable. */
export function loadNmkStore(
  userId: string,
  password: string,
): Map<string, NodeMetadataKey> | null {
  try {
    const stored = localStorage.getItem(`${NMK_STORAGE_PREFIX}${userId}`);
    if (!stored) return null;
    const combined = fromBase64(stored);
    const parse = (plaintext: Uint8Array): Map<string, NodeMetadataKey> => {
      const entries: Record<string, string> = JSON.parse(new TextDecoder().decode(plaintext));
      const store = new Map<string, NodeMetadataKey>();
      for (const [nodeId, b64] of Object.entries(entries)) {
        store.set(nodeId, NodeMetadataKey.fromBytes(fromBase64(b64)));
      }
      return store;
    };
    // v2 (tag-prefixed) first; GCM auth makes a misread safe (fall back to legacy).
    if (combined[0] === AT_REST_V2_TAG) {
      try {
        const key = deriveAtRestKey(password, NMK_DOMAIN);
        const nonce = combined.slice(1, 1 + NONCE_SIZE);
        const ciphertext = combined.slice(1 + NONCE_SIZE);
        return parse(gcm(key, nonce).decrypt(ciphertext));
      } catch {
        // fall through
      }
    }
    const key = deriveAtRestKey(password, NMK_DOMAIN, /* forceLegacy */ true);
    const nonce = combined.slice(0, NONCE_SIZE);
    const ciphertext = combined.slice(NONCE_SIZE);
    return parse(gcm(key, nonce).decrypt(ciphertext));
  } catch (e) {
    console.warn('Failed to load NMK store:', e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// API bundle helpers
// ---------------------------------------------------------------------------

/** Shape of GET/PUT /nodes/:id/metadata/encrypted payloads. */
export interface EncryptedMetadataBundle {
  node: {
    encrypted_name?: string;
    encrypted_description?: string;
    /** NMK-encrypted node settings blob (e.g. disappearing-messages policy). */
    encrypted_settings?: string;
  };
  /** channel_id → base64 blob */
  channels: Record<string, string>;
  /** category_id → base64 blob */
  categories: Record<string, string>;
}

/** Decrypted view of a node's metadata bundle. */
export interface DecryptedMetadata {
  nodeName?: string;
  nodeDescription?: string;
  channelNames: Map<string, string>;
  categoryNames: Map<string, string>;
  /** Decrypted node settings JSON string (e.g. disappearing-messages policy). */
  settings?: string;
}

/**
 * Decrypt a metadata bundle. Entries that fail to decrypt (wrong key,
 * tampered, or newer version) are skipped — the caller falls back to the
 * plaintext names the relay still serves during the migration phase.
 */
export function decryptMetadataBundle(
  bundle: EncryptedMetadataBundle,
  key: NodeMetadataKey,
): DecryptedMetadata {
  const tryDecrypt = (b64?: string): string | undefined => {
    if (!b64) return undefined;
    try {
      return key.decryptFromBase64(b64);
    } catch {
      return undefined;
    }
  };

  const channelNames = new Map<string, string>();
  for (const [id, b64] of Object.entries(bundle.channels ?? {})) {
    const name = tryDecrypt(b64);
    if (name !== undefined) channelNames.set(id, name);
  }
  const categoryNames = new Map<string, string>();
  for (const [id, b64] of Object.entries(bundle.categories ?? {})) {
    const name = tryDecrypt(b64);
    if (name !== undefined) categoryNames.set(id, name);
  }

  return {
    nodeName: tryDecrypt(bundle.node?.encrypted_name),
    nodeDescription: tryDecrypt(bundle.node?.encrypted_description),
    channelNames,
    categoryNames,
    settings: tryDecrypt(bundle.node?.encrypted_settings),
  };
}
