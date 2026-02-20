# Sender Keys E2EE for Accord Channels

## Technical Design Document

**Status:** Draft  
**Date:** 2026-02-20  
**Author:** Accord Team

---

## Table of Contents

1. [Overview](#1-overview)
2. [Key Lifecycle](#2-key-lifecycle)
3. [Message Encryption Flow](#3-message-encryption-flow)
4. [Member Join/Leave Flows](#4-member-joinleave-flows)
5. [Key Distribution](#5-key-distribution)
6. [Forward Secrecy Properties](#6-forward-secrecy-properties)
7. [Implementation Plan](#7-implementation-plan)
8. [Migration Path](#8-migration-path)
9. [Comparison with MLS](#9-comparison-with-mls)
10. [Limitations](#10-limitations)

---

## 1. Overview

### The Problem

Currently, channel encryption in Accord is a placeholder. The function `createChannelKeyFromId()` in `crypto.ts` derives a symmetric key via:

```
SHA-256(channelId + ":accord-channel-key-v1")
```

Every user — and critically, **the server** — can compute this key from the channel ID alone. This provides zero confidentiality against the server operator.

### What Are Sender Keys?

Sender Keys is a protocol (used by Signal for group messaging) where each group member maintains their own **symmetric ratchet chain**. When Alice sends a message to a channel with 50 members, she encrypts once with her Sender Key — not 50 times with 50 different keys.

```
┌─────────────────────────────────────────────────────┐
│                  CURRENT (BROKEN)                    │
│                                                      │
│  Channel ID ──SHA-256──► Shared Key                  │
│                          (server knows it too!)      │
│                                                      │
│  Alice ──encrypt(sharedKey, msg)──► Server ──► Bob   │
│                                    ▲                 │
│                              can decrypt!            │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│                  SENDER KEYS (E2EE)                  │
│                                                      │
│  Alice has: SenderKey_Alice (only members know)      │
│  Bob has:   SenderKey_Bob   (only members know)      │
│  Carol has: SenderKey_Carol (only members know)      │
│                                                      │
│  Alice ──encrypt(SK_Alice, msg)──► Server ──► Bob    │
│                                    ▲         Carol   │
│                              CANNOT decrypt!         │
└─────────────────────────────────────────────────────┘
```

### Why Sender Keys?

| Property | Current Placeholder | Sender Keys |
|----------|-------------------|-------------|
| Server can read messages | ✅ Yes | ❌ No |
| Encryption cost per message | O(1) | O(1)* |
| Key distribution cost | None | O(n) per join** |
| Forward secrecy | ❌ None | ✅ Per-message (chain ratchet) |
| Post-compromise recovery | ❌ None | ⚠️ On rotation only |

\* One symmetric encryption per send, regardless of group size.  
\** Each member sends their Sender Key to the new member via Double Ratchet DM.

---

## 2. Key Lifecycle

### 2.1 Sender Key Structure

Each member's Sender Key for a channel consists of:

```typescript
interface SenderKey {
  chainKey: Uint8Array;       // 32 bytes — current chain key
  signingKey: Uint8Array;     // 32 bytes — Ed25519 private key (authentication)
  signingPubKey: Uint8Array;  // 32 bytes — Ed25519 public key
  iteration: number;          // chain step counter
}

interface SenderKeyPublic {
  chainKey: Uint8Array;       // 32 bytes — initial chain key
  signingPubKey: Uint8Array;  // 32 bytes — for verifying sender
  iteration: number;          // starting iteration
}
```

The chain ratchets forward on each message:

```
chainKey_0 ──HMAC-SHA256("chain")──► chainKey_1 ──► chainKey_2 ──► ...
     │                                    │              │
  HMAC("msg")                         HMAC("msg")    HMAC("msg")
     │                                    │              │
  messageKey_0                       messageKey_1   messageKey_2
```

### 2.2 Generation

When a user joins a channel (or when rotation is triggered), they generate a fresh Sender Key:

```
chainKey     = randomBytes(32)
signingKey   = Ed25519.generateKeypair()
iteration    = 0
```

### 2.3 Distribution

Sender Keys are distributed via **existing Double Ratchet DM channels**. This is critical — the server never sees plaintext Sender Keys.

```
┌───────┐                    ┌────────┐                    ┌───────┐
│ Alice │                    │ Server │                    │  Bob  │
└───┬───┘                    └───┬────┘                    └───┬───┘
    │                            │                             │
    │  encryptE2EE(bob,          │                             │
    │    SenderKeyDistribution)  │                             │
    │ ──────────────────────────►│                             │
    │                            │  (opaque blob, can't read) │
    │                            │ ────────────────────────────►
    │                            │                             │
    │                            │              decryptE2EE()  │
    │                            │              extract SK     │
    │                            │              store locally  │
```

### 2.4 Rotation

Rotation generates a new Sender Key and distributes it to all current members. Triggered by:

1. **Member removal** — ALL members rotate (mandatory)
2. **Periodic rotation** — every N messages or T time (recommended: 100 messages or 24h)
3. **Manual rotation** — user-initiated re-key

### 2.5 Revocation

When a member is removed, their Sender Key is deleted from all other members' stores. Since the chain ratchets forward, old message keys derived before the current iteration are not recoverable from the new chain state — but see [Limitations](#10-limitations).

---

## 3. Message Encryption Flow

### 3.1 Sending a Message

```
Alice wants to send "hello" to #general:

1. Load Alice's SenderKey for #general
2. Derive messageKey from current chainKey:
     messageKey = HMAC-SHA256(chainKey, "MessageKey")
3. Advance chain:
     chainKey = HMAC-SHA256(chainKey, "ChainKey")
     iteration++
4. Encrypt:
     iv = randomBytes(12)
     ciphertext = AES-256-GCM(messageKey, iv, "hello")
5. Sign:
     signature = Ed25519.sign(signingKey, ciphertext || iv)
6. Build envelope:
     {
       senderKeyId: Alice's SK fingerprint,
       iteration: N,
       iv: base64(iv),
       ciphertext: base64(ciphertext),
       signature: base64(signature)
     }
7. Send envelope to server (server sees opaque blob)
```

### 3.2 Receiving a Message

```
Bob receives Alice's message on #general:

1. Extract senderKeyId from envelope
2. Look up Alice's SenderKeyPublic for #general
3. If Bob's stored iteration < message iteration:
     Advance chain key forward to match:
       for i in (stored_iteration..message_iteration):
         chainKey = HMAC-SHA256(chainKey, "ChainKey")
     Cache skipped message keys (for out-of-order delivery)
4. Derive messageKey = HMAC-SHA256(chainKey, "MessageKey")
5. Verify signature using Alice's signingPubKey
6. Decrypt: plaintext = AES-256-GCM.decrypt(messageKey, iv, ciphertext)
```

### 3.3 Out-of-Order Messages

Messages may arrive out of order. The receiver must:

1. If `message.iteration > stored.iteration`: advance chain, cache intermediate message keys
2. If `message.iteration == stored.iteration`: use current message key
3. If `message.iteration < stored.iteration`: look up cached message key

Cached keys should be pruned after a window (e.g., 2000 messages) to bound memory.

```typescript
interface SenderKeyState {
  chainKey: Uint8Array;
  signingPubKey: Uint8Array;
  iteration: number;
  // Cached message keys for out-of-order decryption
  skippedKeys: Map<number, Uint8Array>;  // iteration → messageKey
  maxSkip: number;  // default 2000
}
```

---

## 4. Member Join/Leave Flows

### 4.1 Member Joins Channel

```
Carol joins #general (members: Alice, Bob)

┌───────┐  ┌───────┐  ┌───────┐
│ Alice │  │  Bob  │  │ Carol │
└───┬───┘  └───┬───┘  └───┬───┘
    │          │          │
    │          │     Carol generates
    │          │     SenderKey_Carol
    │          │          │
    │◄─── DM(SK_Carol) ──┤  Carol sends her SK to
    │          │◄─────────┤  each existing member
    │          │          │
    ├── DM(SK_Alice) ────►│  Each existing member
    │          ├─────────►│  sends their SK to Carol
    │          │          │
    │    (no rotation     │
    │     needed)         │
```

**No key rotation needed.** Carol doesn't have old chain keys, so she can't decrypt messages sent before she joined. The chain has already ratcheted forward.

### 4.2 Member Leaves / Is Removed

```
Bob is removed from #general (remaining: Alice, Carol)

┌───────┐  ┌───────┐  ┌ ─ ─ ─┐
│ Alice │  │ Carol │  │  Bob  │ (removed)
└───┬───┘  └───┬───┘  └ ─ ┬ ─┘
    │          │           │
    │  Alice generates     │
    │  NEW SenderKey_Alice │
    │          │           │
    │  Carol generates     │  Bob still has OLD
    │  NEW SenderKey_Carol │  SK_Alice and SK_Carol
    │          │           │  but they'll never be
    ├─DM(new SK_Alice)───►│  used again.
    │◄─DM(new SK_Carol)──┤  │
    │          │           │
    │   ALL sender keys    │  Bob can't derive
    │   rotated. Bob's     │  new message keys.
    │   old keys are       │
    │   useless.           │
```

**ALL Sender Keys must rotate.** Bob had everyone's Sender Keys. If only Bob's key were revoked, he could still decrypt Alice's and Carol's future messages using their old chain keys. By rotating all keys, Bob can't read anything sent after his removal.

### 4.3 Multi-Device Considerations

A user with multiple devices shares the same Sender Key across devices. When sending, only one device advances the chain — other devices must sync the updated state. Options:

1. **Single-writer:** Only the device that sends advances the chain; other devices are receive-only for that channel's own SK (simplest)
2. **Chain fork:** Each device gets its own sub-chain (complex, not recommended initially)
3. **State sync via DM to self:** After sending, sync updated chain state to other devices via self-DM

**Recommendation:** Start with single-writer (most recent device that sent owns the chain). Address multi-device properly in a later phase.

---

## 5. Key Distribution

### 5.1 Distribution Protocol

Sender Keys are distributed as a special message type over the existing Double Ratchet DM channels:

```typescript
interface SenderKeyDistributionMessage {
  type: 'sender_key_distribution';
  channelId: string;
  nodeId: string;
  senderKeyId: string;           // fingerprint for lookup
  chainKey: string;              // base64
  signingPubKey: string;         // base64
  iteration: number;
  // Set when this replaces an old key (rotation)
  replacesKeyId?: string;
}
```

This message is encrypted with Double Ratchet (`encryptE2EE()`) and sent through the existing prekey/DM message infrastructure. The server stores and forwards it as an opaque blob.

### 5.2 Distribution Triggers

| Event | Who distributes | What |
|-------|----------------|------|
| User joins channel | Joiner → all members, all members → joiner | All current SKs |
| User leaves channel | All remaining members → each other | Fresh rotated SKs |
| Periodic rotation | Rotator → all members | New SK |
| New device added | Existing device → new device (self-DM) | All SKs |

### 5.3 Bootstrapping: No DM Channel Yet

If Alice joins a channel with Bob but they don't have a Double Ratchet session yet, the X3DH handshake must happen first. The flow:

1. Alice fetches Bob's key bundle from server
2. Alice performs X3DH → establishes DR session
3. Alice sends SenderKeyDistributionMessage via the new DR session

This is already supported by the existing E2EE infrastructure — `encryptE2EE()` handles session establishment transparently.

### 5.4 Server-Side Key Distribution Endpoint

The server doesn't need to understand Sender Keys, but it benefits from a dedicated endpoint to track which members need key distributions:

```
POST /channels/{channelId}/sender-key-ack
Body: { "keyId": "...", "fromUserId": "..." }

GET /channels/{channelId}/sender-key-status
Response: { "pending": ["userId1", "userId2"], "complete": ["userId3"] }
```

This is purely bookkeeping — the actual keys flow through DMs.

---

## 6. Forward Secrecy Properties

### 6.1 What Sender Keys Provide

**Per-message forward secrecy (within a chain):** Each message key is derived from the chain key, then the chain advances. A compromise of the current chain key does NOT reveal past message keys (chain ratchets are one-way via HMAC).

```
Compromise at iteration 5:
  ✅ Messages 0-4: SAFE (can't go backwards)
  ❌ Messages 5+: COMPROMISED (can derive forward)
```

**Post-removal forward secrecy:** After a member is removed and all keys rotate, the removed member cannot read future messages.

### 6.2 What Sender Keys DON'T Provide

**Break-in recovery (post-compromise security):** Unlike Double Ratchet which performs a DH ratchet on every message exchange, Sender Keys only rotate when explicitly triggered. If an attacker compromises a Sender Key, they can read all future messages on that chain until rotation.

**Comparison with Double Ratchet:**

| Property | Double Ratchet (DMs) | Sender Keys (Channels) |
|----------|---------------------|----------------------|
| Forward secrecy | ✅ Per-message (chain + DH) | ✅ Per-message (chain only) |
| Break-in recovery | ✅ Every message (DH ratchet) | ⚠️ Only on rotation |
| Deniability | ✅ (no signatures) | ❌ (Ed25519 signatures) |
| Cost per message | O(1) with 2-party DH | O(1) symmetric |
| Cost per send in group | N/A (1:1 only) | O(1) vs O(n) for pairwise |

### 6.3 Mitigation: Periodic Rotation

To improve break-in recovery, Sender Keys should rotate on a schedule:

- Every **100 messages** per sender, OR
- Every **24 hours**, whichever comes first

This bounds the window of compromise to at most 100 messages / 24 hours.

---

## 7. Implementation Plan

### 7.1 `crypto.ts` — New Sender Key Primitives

Add a new module `desktop/frontend/src/e2ee/sender-keys.ts`:

```typescript
// ─── sender-keys.ts ───

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { gcm } from '@noble/ciphers/aes.js';
import { ed25519 } from '@noble/curves/ed25519.js';

// --- Types ---

export interface SenderKeyPrivate {
  chainKey: Uint8Array;         // 32 bytes
  signingKey: Uint8Array;       // 32 bytes Ed25519 private
  signingPubKey: Uint8Array;    // 32 bytes Ed25519 public
  iteration: number;
}

export interface SenderKeyPublic {
  chainKey: Uint8Array;         // 32 bytes (at distribution time)
  signingPubKey: Uint8Array;    // 32 bytes
  iteration: number;
  senderKeyId: string;          // fingerprint
}

export interface SenderKeyState {
  key: SenderKeyPublic;
  currentChainKey: Uint8Array;
  currentIteration: number;
  skippedMessageKeys: Map<number, Uint8Array>;
}

export interface SenderKeyEnvelope {
  senderKeyId: string;
  iteration: number;
  iv: string;          // base64
  ciphertext: string;  // base64
  signature: string;   // base64
}

// --- Key Generation ---

export function generateSenderKey(): SenderKeyPrivate {
  const chainKey = randomBytes(32);
  const signingKey = ed25519.utils.randomPrivateKey();
  const signingPubKey = ed25519.getPublicKey(signingKey);
  return { chainKey, signingKey, signingPubKey, iteration: 0 };
}

export function senderKeyFingerprint(signingPubKey: Uint8Array): string {
  return Array.from(sha256(signingPubKey).slice(0, 8))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Chain Ratchet ---

function deriveMessageKey(chainKey: Uint8Array): Uint8Array {
  return hmac(sha256, chainKey, new TextEncoder().encode('MessageKey'));
}

function advanceChainKey(chainKey: Uint8Array): Uint8Array {
  return hmac(sha256, chainKey, new TextEncoder().encode('ChainKey'));
}

// --- Encrypt (Sender) ---

export function senderKeyEncrypt(
  sk: SenderKeyPrivate,
  plaintext: Uint8Array
): { envelope: SenderKeyEnvelope; updatedKey: SenderKeyPrivate } {
  const messageKey = deriveMessageKey(sk.chainKey);
  const nextChainKey = advanceChainKey(sk.chainKey);
  
  const iv = randomBytes(12);
  const cipher = gcm(messageKey, iv);
  const ciphertext = cipher.encrypt(plaintext);
  
  const toSign = new Uint8Array(iv.length + ciphertext.length);
  toSign.set(iv);
  toSign.set(ciphertext, iv.length);
  const signature = ed25519.sign(toSign, sk.signingKey);
  
  const envelope: SenderKeyEnvelope = {
    senderKeyId: senderKeyFingerprint(sk.signingPubKey),
    iteration: sk.iteration,
    iv: uint8ToBase64(iv),
    ciphertext: uint8ToBase64(ciphertext),
    signature: uint8ToBase64(signature),
  };
  
  const updatedKey: SenderKeyPrivate = {
    ...sk,
    chainKey: nextChainKey,
    iteration: sk.iteration + 1,
  };
  
  return { envelope, updatedKey };
}

// --- Decrypt (Receiver) ---

const MAX_SKIP = 2000;

export function senderKeyDecrypt(
  state: SenderKeyState,
  envelope: SenderKeyEnvelope
): { plaintext: Uint8Array; updatedState: SenderKeyState } {
  const iv = base64ToUint8(envelope.iv);
  const ciphertext = base64ToUint8(envelope.ciphertext);
  const signature = base64ToUint8(envelope.signature);
  
  // Verify signature
  const toVerify = new Uint8Array(iv.length + ciphertext.length);
  toVerify.set(iv);
  toVerify.set(ciphertext, iv.length);
  if (!ed25519.verify(signature, toVerify, state.key.signingPubKey)) {
    throw new Error('Sender Key signature verification failed');
  }
  
  let messageKey: Uint8Array;
  const newState = { ...state, skippedMessageKeys: new Map(state.skippedMessageKeys) };
  
  if (envelope.iteration < state.currentIteration) {
    // Out-of-order: use cached key
    const cached = newState.skippedMessageKeys.get(envelope.iteration);
    if (!cached) throw new Error(`No cached key for iteration ${envelope.iteration}`);
    messageKey = cached;
    newState.skippedMessageKeys.delete(envelope.iteration);
  } else {
    // Advance chain, caching skipped keys
    let chainKey = state.currentChainKey;
    let iter = state.currentIteration;
    
    if (envelope.iteration - iter > MAX_SKIP) {
      throw new Error(`Too many skipped messages: ${envelope.iteration - iter}`);
    }
    
    while (iter < envelope.iteration) {
      newState.skippedMessageKeys.set(iter, deriveMessageKey(chainKey));
      chainKey = advanceChainKey(chainKey);
      iter++;
    }
    
    messageKey = deriveMessageKey(chainKey);
    newState.currentChainKey = advanceChainKey(chainKey);
    newState.currentIteration = iter + 1;
  }
  
  // Prune old skipped keys
  if (newState.skippedMessageKeys.size > MAX_SKIP) {
    const sorted = [...newState.skippedMessageKeys.keys()].sort((a, b) => a - b);
    while (newState.skippedMessageKeys.size > MAX_SKIP) {
      newState.skippedMessageKeys.delete(sorted.shift()!);
    }
  }
  
  const cipher = gcm(messageKey, iv);
  const plaintext = cipher.decrypt(ciphertext);
  
  return { plaintext, updatedState: newState };
}
```

### 7.2 Changes to `crypto.ts`

The existing `encryptMessage` / `decryptMessage` functions stay for backward compatibility during migration. New functions are added:

```typescript
// In crypto.ts — add:

import {
  SenderKeyPrivate, SenderKeyState, SenderKeyEnvelope,
  generateSenderKey, senderKeyEncrypt, senderKeyDecrypt,
  senderKeyFingerprint
} from './e2ee/sender-keys';

// Channel message encryption via Sender Keys
export async function encryptChannelMessage(
  senderKey: SenderKeyPrivate,
  plaintext: string
): Promise<{ envelope: SenderKeyEnvelope; updatedKey: SenderKeyPrivate }> {
  const data = new TextEncoder().encode(plaintext);
  return senderKeyEncrypt(senderKey, data);
}

export async function decryptChannelMessage(
  state: SenderKeyState,
  envelope: SenderKeyEnvelope
): Promise<{ plaintext: string; updatedState: SenderKeyState }> {
  const { plaintext, updatedState } = senderKeyDecrypt(state, envelope);
  return { plaintext: new TextDecoder().decode(plaintext), updatedState };
}
```

### 7.3 State Management (App.tsx)

New state structures needed:

```typescript
// Sender Key store — per channel, per member
interface SenderKeyStore {
  // My own sender keys (I encrypt with these)
  myKeys: Map<string, SenderKeyPrivate>;  // channelId → my SK
  
  // Other members' sender keys (I decrypt with these)
  peerKeys: Map<string, Map<string, SenderKeyState>>;
  // channelId → (userId → SenderKeyState)
}
```

**Key operations to add to App.tsx / state management:**

1. **On channel join:** Generate my Sender Key, distribute to all members
2. **On receiving SenderKeyDistributionMessage:** Store the peer's SK
3. **On sending message:** Use `encryptChannelMessage()`, update stored SK
4. **On receiving message:** Look up sender's SK state, use `decryptChannelMessage()`
5. **On member removal:** Rotate my SK, distribute new SK to remaining members
6. **On periodic rotation:** Same as removal rotation

**Storage:** Sender Key state must persist across sessions. Use IndexedDB (not localStorage — too much data for large channels):

```typescript
// IndexedDB schema
const SENDER_KEY_STORE = 'accord_sender_keys';
// Object store: { channelId, peerId, state: SenderKeyState }
// Index on [channelId, peerId]
```

### 7.4 Server Changes

The server needs minimal changes — it never sees plaintext keys. Required:

#### New Database Table

```sql
CREATE TABLE IF NOT EXISTS sender_key_distributions (
    id TEXT PRIMARY KEY,                    -- UUID
    channel_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    -- Encrypted via Double Ratchet (opaque to server)
    encrypted_payload BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    claimed INTEGER DEFAULT 0,
    FOREIGN KEY (channel_id) REFERENCES channels(id),
    FOREIGN KEY (from_user_id) REFERENCES users(id),
    FOREIGN KEY (to_user_id) REFERENCES users(id)
);

CREATE INDEX idx_skd_recipient 
  ON sender_key_distributions(to_user_id, claimed);
CREATE INDEX idx_skd_channel 
  ON sender_key_distributions(channel_id);
```

#### New Endpoints

```rust
// In handlers.rs

/// Store a Sender Key distribution message for a recipient
/// POST /api/channels/{channelId}/sender-keys
/// Body: { "toUserId": "...", "payload": "<base64 DR-encrypted blob>" }
async fn store_sender_key_distribution(/* ... */) -> impl IntoResponse { /* ... */ }

/// Fetch pending Sender Key distributions for the current user
/// GET /api/sender-keys/pending
/// Response: [{ "id": "...", "channelId": "...", "fromUserId": "...", "payload": "..." }]
async fn get_pending_sender_keys(/* ... */) -> impl IntoResponse { /* ... */ }

/// Acknowledge receipt of Sender Key distributions
/// POST /api/sender-keys/ack
/// Body: { "ids": ["id1", "id2"] }
async fn ack_sender_keys(/* ... */) -> impl IntoResponse { /* ... */ }
```

#### Message Schema Change

Messages need a new field to indicate encryption type:

```sql
ALTER TABLE messages ADD COLUMN encryption_version INTEGER DEFAULT 0;
-- 0 = placeholder (channel-ID-derived key)
-- 1 = Sender Keys
```

The message `content` field already stores the encrypted blob. For Sender Key messages, it stores the JSON-serialized `SenderKeyEnvelope`.

### 7.5 WebSocket Events

New event types for real-time SK distribution:

```typescript
// Server → Client
interface SenderKeyDistributionEvent {
  type: 'sender_key_distribution';
  channelId: string;
  fromUserId: string;
  payload: string;  // DR-encrypted SenderKeyDistributionMessage
}

// Server → Client (on member removal, tells remaining to rotate)
interface SenderKeyRotationRequired {
  type: 'sender_key_rotation_required';
  channelId: string;
  removedUserId: string;
}
```

---

## 8. Migration Path

### Phase 1: Ship Sender Keys alongside placeholder (non-breaking)

1. Implement all Sender Key primitives in `sender-keys.ts`
2. Add `encryption_version` column to messages
3. Messages encrypted with Sender Keys get `encryption_version = 1`
4. Decryption code checks the version:
   - `0` → use `decryptMessage()` (old placeholder path)
   - `1` → use `decryptChannelMessage()` (Sender Keys)
5. Old clients that don't understand Sender Keys see `encryption_version = 1` messages as undecryptable (show "[Encrypted message — update your client]")

### Phase 2: Gradual rollout

1. Enable Sender Keys per-channel (server flag or channel setting)
2. Channels with ALL members on a Sender-Key-capable client version switch to Sender Keys
3. Mixed channels (old + new clients) stay on placeholder

### Phase 3: Deprecate placeholder

1. After sufficient adoption, new channels default to Sender Keys
2. Eventually, remove placeholder encryption entirely

### Backward Compatibility

```typescript
async function decryptChannelContent(
  message: Message,
  channelId: string,
  privateKey: CryptoKey,
  senderKeyStore: SenderKeyStore
): Promise<string> {
  if (message.encryptionVersion === 1) {
    // Sender Keys path
    const envelope = JSON.parse(message.content) as SenderKeyEnvelope;
    const state = senderKeyStore.peerKeys
      .get(channelId)?.get(message.senderId);
    if (!state) throw new Error('Missing sender key for ' + message.senderId);
    const { plaintext, updatedState } = await decryptChannelMessage(state, envelope);
    // Persist updated state
    senderKeyStore.peerKeys.get(channelId)!.set(message.senderId, updatedState);
    return plaintext;
  }
  
  // Legacy placeholder path
  const key = await getChannelKey(privateKey, channelId);
  return decryptMessage(key, message.content);
}
```

---

## 9. Comparison with MLS

**MLS (Messaging Layer Security)** is an IETF standard (RFC 9420) designed for group E2EE with strong forward secrecy and post-compromise security. It's the "proper" solution but comes with significant complexity.

| Aspect | Sender Keys | MLS |
|--------|------------|-----|
| **Complexity** | Low — symmetric chain + signatures | High — tree-based DH, epoch management |
| **Forward secrecy** | Chain ratchet only | Full tree-based FS |
| **Post-compromise security** | On rotation only | Every commit (update) |
| **Message overhead** | Small (just envelope) | Small per-message, larger for group ops |
| **Group operation cost** | O(n) per join/leave (DM each member) | O(log n) per commit (tree structure) |
| **Server state** | Minimal (distribution queue) | Significant (tree state, epochs) |
| **Existing implementations** | Simple to build | OpenMLS, but heavy dependency |
| **Spec maturity** | Signal battle-tested | RFC 9420, newer |
| **Our existing infra** | Reuses Double Ratchet DMs | Requires new subsystem |

### Why Sender Keys First

1. **We already have Double Ratchet DMs** — Sender Keys reuse this infrastructure for key distribution. MLS would require a separate key agreement mechanism.

2. **Simpler implementation** — Sender Keys are ~300 lines of crypto code. MLS is thousands.

3. **Good enough for our scale** — Sender Keys' O(n) distribution is fine for channels with <1000 members. MLS's O(log n) advantage only matters at scale.

4. **Incremental path** — Ship Sender Keys now, consider MLS later if needed. The message format (`encryption_version`) allows future migration.

### When to Consider MLS

- Channels regularly exceed 500+ members
- Post-compromise security becomes a hard requirement
- A mature, audited Wasm MLS library becomes available
- Federation requires interoperable group encryption

---

## 10. Limitations

### 10.1 Compromised Member Before Removal

If an attacker compromises Alice's device and reads her Sender Key store, they can decrypt all channel messages until:
- Alice's compromise is detected
- Alice is removed (triggering rotation)
- Periodic rotation occurs

**Mitigation:** Short rotation intervals (100 messages / 24h).

### 10.2 No Post-Compromise Security Between Rotations

Unlike Double Ratchet (which recovers on every DH exchange), Sender Keys only recover security when the key is rotated. Between rotations, a compromised chain key allows decryption of all messages.

### 10.3 Sender Key Authenticity Depends on Double Ratchet

If the Double Ratchet DM channel is compromised (e.g., through a bad X3DH), an attacker could inject fake Sender Keys. The security of channel E2EE is bounded by the security of the underlying DM E2EE.

### 10.4 No Deniability

Messages are signed with Ed25519. Unlike Double Ratchet (which uses MAC keys derivable by either party), Sender Key signatures are non-repudiable. Anyone with the signing public key can prove Alice sent a specific message.

**Possible mitigation (future):** Replace Ed25519 signatures with a symmetric MAC using a key derived from the chain, at the cost of losing third-party verifiability.

### 10.5 Metadata Exposure

The server still sees:
- Who sent a message
- When it was sent
- Which channel it was sent to
- Message size

Sender Keys encrypt **content**, not **metadata**. See `metadata-privacy.md` for Accord's metadata protection strategies.

### 10.6 Device Compromise = Full Channel Compromise

If a member's device is compromised, all channels that member belongs to are compromised (the attacker has all their Sender Keys). This is inherent to any group encryption scheme.

### 10.7 History on New Device

When a user adds a new device, they need Sender Keys to decrypt channel messages. Old messages encrypted with prior chain iterations are NOT decryptable on the new device (the chain has advanced). This is by design (forward secrecy), but may surprise users.

**Possible mitigation:** Allow optional encrypted history transfer between devices via the self-DM channel.

---

## Appendix A: Wire Format

### Sender Key Envelope (stored in `messages.content`)

```json
{
  "v": 1,
  "sk": "a1b2c3d4e5f6g7h8",
  "i": 42,
  "iv": "base64...",
  "ct": "base64...",
  "sig": "base64..."
}
```

Compact field names to minimize storage overhead:
- `v` — version (1 = Sender Keys v1)
- `sk` — sender key ID (fingerprint)
- `i` — chain iteration
- `iv` — 12-byte AES-GCM nonce
- `ct` — ciphertext
- `sig` — Ed25519 signature over `iv || ct`

### Sender Key Distribution Message (sent via DR DM)

```json
{
  "type": "skdm",
  "ch": "channel-uuid",
  "nd": "node-uuid",
  "skid": "a1b2c3d4e5f6g7h8",
  "ck": "base64(32 bytes)",
  "spk": "base64(32 bytes)",
  "iter": 0,
  "rep": null
}
```

---

## Appendix B: Cryptographic Dependencies

All crypto uses `@noble` libraries (already in Accord's dependency tree):

| Operation | Library | Function |
|-----------|---------|----------|
| Chain ratchet | `@noble/hashes` | `hmac(sha256, ...)` |
| Message encryption | `@noble/ciphers` | `gcm(key, iv)` |
| Signing | `@noble/curves` | `ed25519.sign()` / `.verify()` |
| Key fingerprint | `@noble/hashes` | `sha256()` |
| Random bytes | Web Crypto | `crypto.getRandomValues()` |

**No new dependencies required.**

---

## Appendix C: References

- [Signal Sender Keys](https://signal.org/docs/specifications/group-v2/) — Signal's group messaging specification
- [RFC 9420 — MLS](https://www.rfc-editor.org/rfc/rfc9420) — Messaging Layer Security protocol
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/) — Foundation for DM E2EE (already implemented in Accord)
- [X3DH Key Agreement](https://signal.org/docs/specifications/x3dh/) — Key agreement for establishing DR sessions (already implemented in Accord)
