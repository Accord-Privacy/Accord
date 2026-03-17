# Federation DM Routing Protocol — Design Document

> **Status:** Draft  
> **Date:** 2026-03-08  
> **Scope:** Cross-relay DM routing for the Accord relay mesh  

## Overview

Accord relays are independently operated servers. Federation lets users on different relays exchange DMs without either relay seeing plaintext. This document specifies the protocol-level decisions for discovery, identity, routing, encryption, and failure handling.

### Design Principles

1. **Relays are untrusted.** They route opaque ciphertext. They never hold plaintext, private keys, or session keys.
2. **Friendship is the gate.** Cross-relay DMs require a mutual friendship proof — no spam, no unsolicited contact.
3. **No global directory.** There is no central authority. Relays discover each other through bootstrap lists, DNS SRV, and gossip.
4. **Minimal metadata.** Relays learn *that* two users communicate, not *what* they say. Even "that" is minimized via blinded routing (see §Routing).

---

## 1. Discovery — How Relays Find Each Other

### 1.1 Bootstrap Peers

Each relay is configured with a `known_peers` list (host:port). On startup, the relay connects to each bootstrap peer via the mesh transport (TCP + optional TLS) and exchanges `RelayAnnounce` envelopes containing:

- `relay_id` (first 16 hex chars of SHA-256 of the relay's Ed25519 public key)
- `address` (host:port for mesh connections)
- `public_key` (Ed25519 verifying key, 32 bytes)

This is already implemented in `relay_mesh/service.rs`.

### 1.2 DNS SRV Bootstrap

Relays MAY query `_accord._tcp.<domain>` SRV records to discover peers in a domain. This is a cold-start mechanism — once peers are found, gossip takes over.

### 1.3 Peer Gossip

When relay A connects to relay B, B responds with its own `RelayAnnounce`. Periodically (every 5 minutes), relays exchange their peer lists via a new `PeerExchange` payload type:

```
PayloadType::PeerExchange
```

Payload:
```json
{
  "peers": [
    { "relay_id": "abc123...", "address": "10.0.0.2:9443", "public_key": "hex...", "last_seen": 1700000000 }
  ]
}
```

Receiving relays merge this into their `PeerRegistry`, connecting to new peers up to `max_peers`. Relays MUST NOT re-gossip peers they haven't directly verified (connected to and authenticated). This prevents phantom peer injection.

### 1.4 Authentication

All mesh connections are authenticated via the HMAC challenge-response handshake (already implemented in `transport.rs`). Relays sharing the same `mesh_secret` form a trust group. Relays with different secrets (or no secret) are isolated — this is intentional. Federation is opt-in per relay operator.

**Open question:** Should we support multi-mesh (relay participates in multiple trust groups)? For v1, no. A relay belongs to exactly one mesh.

---

## 2. Identity — How Users Are Addressed Cross-Relay

### 2.1 User Addressing

Users are identified by their **public key hash** (`public_key_hash`), which is relay-independent. A user's full cross-relay address is:

```
<public_key_hash>@<relay_id>
```

Example: `a1b2c3d4e5f6g7h8@3f4a5b6c7d8e9f0a`

The `@relay_id` suffix tells the mesh where to route. The `public_key_hash` is the user's stable identity regardless of which relay they're on.

### 2.2 Home Relay

A user has exactly one **home relay** — the relay they registered on. Their home relay:
- Stores their key bundles (X3DH identity key, signed prekey, one-time prekeys)
- Receives and queues DMs when the user is offline
- Serves as the authoritative source for their public key

Users MAY migrate to a different relay, but that's a future protocol extension (requires key bundle transfer and a redirect record on the old relay).

### 2.3 Relay ID Stability

A relay's identity is derived from its Ed25519 keypair (stored in `relay_key` / `relay_key.pub`). The relay ID is deterministic from the public key. Relay operators MUST preserve their keypair across restarts. Loss of the keypair = new relay identity = all peer relationships reset.

### 2.4 Cross-Relay Friendship

Before user A on relay 1 can DM user B on relay 2, they must establish a friendship. The friendship flow:

1. Users A and B meet on a shared Node (Nodes are relay-local, so both users must have accounts on the same relay for that Node, OR the Node itself is federated — out of scope for v1).
2. A sends a friend request including a `dm_key_bundle` (their X3DH public key material).
3. B accepts, establishing a `friendship_proof` (a mutually signed blob).
4. Both relays store the friendship in their `friendships` table, keyed by `(user_a_hash, user_b_hash)`.

**For cross-relay friendships specifically**, the friend request must travel via the mesh. New payload type:

```
PayloadType::FriendRequest
```

Payload:
```json
{
  "from_user_hash": "a1b2c3d4...",
  "from_relay_id": "3f4a5b6c...",
  "to_user_hash": "x9y8z7w6...",
  "dm_key_bundle": "<base64 X3DH bundle>",
  "proof_of_introduction": "<base64 signed blob>"
}
```

The `proof_of_introduction` is signed by both users and a shared Node, proving they have a legitimate social connection. This prevents relays from forging friend requests.

---

## 3. Message Routing — How a DM Travels Cross-Relay

### 3.1 Direct Routing (Happy Path)

```
User A (client) → Relay 1 → [mesh] → Relay 2 → User B (client)
```

1. **Client A** encrypts the DM using the Double Ratchet session with User B (E2EE, see §4).
2. **Client A** sends the ciphertext to Relay 1 via WebSocket, tagged with `to_user_hash` and `to_relay_id`.
3. **Relay 1** verifies:
   - A has a friendship with B (checks `friendships` table by hash pair)
   - `to_relay_id` is a known peer
4. **Relay 1** wraps the ciphertext in a `DmForward` envelope (already implemented):
   ```json
   {
     "to_user_id": "<UUID on relay 2>",
     "from_user_id": "<UUID on relay 1>",
     "encrypted_dm": "<opaque E2EE blob>"
   }
   ```
5. **Relay 1** signs the envelope with its Ed25519 key and sends it to Relay 2 via mesh transport.
6. **Relay 2** verifies the envelope signature against Relay 1's known public key.
7. **Relay 2** delivers the `encrypted_dm` blob to User B's WebSocket (or queues it).
8. **Client B** decrypts using their Double Ratchet session.

### 3.2 User ID Resolution

The current `DmForwardPayload` uses UUIDs (`to_user_id`), but UUIDs are relay-local. For cross-relay routing, the sending relay doesn't know the recipient's UUID on the remote relay. Resolution options:

**Option A (chosen): Route by public_key_hash.**  
Change `DmForwardPayload.to_user_id` to `to_user_hash: String`. The receiving relay resolves `public_key_hash → user_id` locally. This avoids leaking relay-internal UUIDs.

```json
{
  "to_user_hash": "a1b2c3d4e5f6g7h8",
  "from_user_hash": "x9y8z7w6v5u4t3s2",
  "from_relay_id": "3f4a5b6c7d8e9f0a",
  "encrypted_dm": "<base64>"
}
```

### 3.3 Store-and-Forward (Offline Delivery)

If User B is offline when the DM arrives:

1. Relay 2 stores the encrypted blob in a `pending_mesh_dms` table:
   ```sql
   CREATE TABLE pending_mesh_dms (
     id TEXT PRIMARY KEY,
     to_user_hash TEXT NOT NULL,
     from_user_hash TEXT NOT NULL,
     from_relay_id TEXT NOT NULL,
     encrypted_dm BLOB NOT NULL,
     received_at INTEGER NOT NULL
   );
   ```
2. When User B connects, Relay 2 delivers all pending mesh DMs and deletes them.
3. Pending DMs expire after **7 days** (configurable). Relay 2 has no obligation to store them longer — it's an untrusted intermediary.

### 3.4 Delivery Acknowledgment

After Relay 2 successfully receives and stores/delivers the DM, it sends back a `DmAck` envelope:

```
PayloadType::DmAck
```

Payload:
```json
{
  "ack_id": "<hash of the original envelope>",
  "status": "delivered" | "queued" | "rejected"
}
```

If Relay 1 doesn't receive an ack within 30 seconds, it queues the message for retry (see §5).

---

## 4. Encryption — E2EE Across Untrusted Relays

### 4.1 Threat Model

- **Relays are untrusted.** Both Relay 1 and Relay 2 see only ciphertext.
- **The mesh transport (TLS + HMAC) protects relay-to-relay links**, but this is defense-in-depth. Even without TLS, message confidentiality is guaranteed by E2EE.
- **Relays learn metadata:** who talks to whom (by public_key_hash), when, and how often. They do NOT learn message content or size (messages should be padded to fixed blocks).

### 4.2 Key Exchange (X3DH)

Accord already implements X3DH key bundles (`key_bundles` + `one_time_prekeys` tables). For cross-relay key exchange:

1. **Client A** requests User B's key bundle from Relay 2 via a new mesh payload:
   ```
   PayloadType::KeyBundleRequest
   ```
   Relay 1 forwards the request to Relay 2. Relay 2 responds with User B's public key bundle (identity key, signed prekey, one-time prekey).

2. **Client A** performs X3DH locally, deriving a shared secret.

3. **Client A** sends an initial prekey message (containing the X3DH ephemeral key and first ciphertext) via the normal `DmForward` path.

4. **Client B** completes X3DH on their side and enters the Double Ratchet.

**Key point:** The key bundle is public material — relays seeing it doesn't compromise E2EE. But to prevent bundle substitution attacks (relay swapping in its own keys), clients SHOULD verify the identity key fingerprint out-of-band (QR code, verbal confirmation, etc). This is standard Signal Protocol practice.

### 4.3 Double Ratchet

After X3DH, all subsequent messages use the Double Ratchet algorithm (Signal Protocol). Each message is encrypted with a unique message key derived from the ratchet state. The ratchet state lives exclusively on the clients — relays never see it.

### 4.4 Message Padding

To prevent relays from inferring message content by size, all `encrypted_dm` blobs MUST be padded to the nearest 256-byte boundary before encryption. The padding scheme:

```
[plaintext] [0x80] [0x00 ... 0x00]  (ISO 7816-4 padding to 256-byte boundary)
```

### 4.5 Metadata Minimization

Future consideration: **Sealed sender.** Client A encrypts the `from_user_hash` inside the E2EE payload so that Relay 2 can deliver the message without knowing who sent it. Relay 2 routes only by `to_user_hash`. This requires Relay 2 to accept DMs without verifying the sender's friendship status — the friendship check would move to the client side. Trade-off: more spam surface vs. less metadata. Defer to v2.

---

## 5. Failure Handling

### 5.1 Relay Down (Target Unreachable)

If Relay 1 cannot reach Relay 2:

1. The mesh transport's auto-reconnect loop kicks in (exponential backoff, 1s → 60s max, already implemented in `transport.rs`).
2. Outbound DMs are queued in memory (bounded queue, 1000 messages per target relay).
3. If the queue fills, oldest messages are dropped and the sender's client is notified via WebSocket:
   ```json
   { "type": "mesh_dm_failed", "to_user_hash": "...", "reason": "relay_unreachable" }
   ```
4. The client can retry or inform the user.

### 5.2 Relay Down (Source Unreachable)

If Relay 2 cannot reach Relay 1 to send an ack, it still stores/delivers the DM. Relay 1 treats the missing ack as a potential failure and retries (idempotent delivery — Relay 2 deduplicates by envelope hash).

### 5.3 Split Brain

Two relays may temporarily disagree about the mesh topology (different peer lists, stale connections). This is benign for DMs because:

- DMs are point-to-point (Relay 1 → Relay 2). There's no consensus requirement.
- If Relay 1 has a stale address for Relay 2, the TCP connection will fail and trigger re-discovery via gossip.
- Peer registry entries expire after **24 hours** without a ping. Stale peers are pruned automatically.

### 5.4 Message Deduplication

Retries can cause duplicate delivery. Each `DmForward` envelope includes a unique envelope hash (SHA-256 of the signed envelope bytes). Relay 2 maintains a deduplication set (bloom filter or bounded LRU cache) of recently seen envelope hashes. Duplicates are silently dropped.

```sql
CREATE TABLE mesh_dm_dedup (
  envelope_hash TEXT PRIMARY KEY,
  received_at INTEGER NOT NULL
);
-- Prune entries older than 24 hours periodically
```

### 5.5 Relay Misbehavior

If a relay is suspected of dropping, delaying, or forging messages:

- **Dropping:** Client-level read receipts (E2EE-encrypted) let the sender detect non-delivery. The client can switch to an alternative route or alert the user.
- **Forging:** Impossible for message content (E2EE). Envelope forgery is prevented by Ed25519 signatures. A relay cannot forge an envelope from another relay.
- **Replaying:** Deduplication (§5.4) + monotonic timestamps in envelopes. Relays reject envelopes with timestamps more than 5 minutes in the past.

### 5.6 Graceful Degradation

If the mesh subsystem is disabled (`mesh.enabled = false`) or crashes, local functionality is unaffected. DMs between users on the same relay continue normally. Cross-relay DMs simply stop working until the mesh recovers. No data loss — the client retains unsent messages locally.

---

## 6. Protocol Summary

### New Payload Types

| Type | Direction | Purpose |
|---|---|---|
| `DmForward` | Relay → Relay | Forward an E2EE DM blob (existing) |
| `DmAck` | Relay → Relay | Acknowledge DM receipt |
| `RelayAnnounce` | Relay → Relay | Identity announcement (existing) |
| `RelayPing` | Relay → Relay | Keepalive (existing) |
| `PeerExchange` | Relay → Relay | Gossip peer lists |
| `KeyBundleRequest` | Relay → Relay | Request a user's X3DH public key bundle |
| `KeyBundleResponse` | Relay → Relay | Return a user's X3DH public key bundle |
| `FriendRequest` | Relay → Relay | Cross-relay friend request |

### New Database Tables

| Table | Purpose |
|---|---|
| `pending_mesh_dms` | Store-and-forward for offline recipients |
| `mesh_dm_dedup` | Envelope deduplication (24h TTL) |

### Configuration Additions

```toml
[mesh]
enabled = true
listen_port = 9443
known_peers = ["10.0.0.2:9443", "10.0.0.3:9443"]
mesh_secret = "shared-secret-for-trust-group"
pending_dm_ttl_days = 7        # How long to store undelivered DMs
outbound_queue_size = 1000     # Per-relay outbound queue limit
dedup_ttl_hours = 24           # Envelope dedup window
```

---

## 7. What This Design Does NOT Cover

- **Federated Nodes** (channels/groups spanning multiple relays) — much harder, deferred.
- **User migration** (moving from one relay to another) — needs key transfer protocol.
- **Sealed sender** (hiding sender identity from receiving relay) — v2.
- **Multi-device sync** for cross-relay DMs — handled by existing per-relay device sync; mesh just delivers to the home relay.
- **Rate limiting cross-relay DMs** — should be added but is an implementation detail, not a protocol decision.
- **Relay reputation / trust scoring** — interesting but premature.

---

## 8. Implementation Order

1. **Change `DmForwardPayload` to use `public_key_hash` instead of UUID** — small, backward-compatible.
2. **Add `DmAck` payload type and handler** — enables retry logic.
3. **Add `pending_mesh_dms` table and store-and-forward** — enables offline delivery.
4. **Add `PeerExchange` for gossip discovery** — reduces reliance on static bootstrap lists.
5. **Add `KeyBundleRequest/Response`** — enables cross-relay X3DH without out-of-band key exchange.
6. **Add `FriendRequest` mesh payload** — enables cross-relay friendship establishment.
7. **Add deduplication** — required once retries are enabled.
8. **Message padding** — privacy hardening.
