# Metadata Privacy — Phase 1

## Problem

Accord encrypts message *content* end-to-end, but node names, channel names, descriptions, and user display names are stored **in plaintext** on the relay server. A compromised server (or subpoena) reveals the organizational structure of every community.

## Solution: Encrypted Metadata Fields

Phase 1 adds **optional encrypted metadata fields** alongside the existing plaintext ones. This is backward-compatible — clients that don't support encrypted metadata continue working.

### Architecture

```
Creator's identity key + Node UUID
        │
        ▼
   HKDF-SHA256 (info: "accord-node-metadata-v1")
        │
        ▼
   Node Metadata Key (NMK) — 256-bit AES key
        │
        ▼
   AES-256-GCM encryption of names/descriptions
```

Each **Node** has one NMK. The NMK encrypts:
- Node name and description
- Channel names within that node
- Channel category names
- (Future) role names, emoji names, etc.

User display names use a **separate per-user key** (not yet implemented — Phase 2).

### Key Distribution

The NMK is derived deterministically from the node creator's identity key material and the node UUID. When a new member joins, the node admin shares the NMK via the existing Double Ratchet encrypted channel (piggybacked on session establishment).

### Wire Format

Encrypted metadata blobs use a simple versioned format:

```
[version: 1 byte] [nonce: 12 bytes] [AES-256-GCM ciphertext + 16-byte tag]
```

Stored as base64 in JSON payloads, raw bytes in the database.

### Database Schema Changes

New nullable columns (backward-compatible):

| Table | New Column | Type |
|-------|-----------|------|
| `nodes` | `encrypted_name` | `BLOB` |
| `nodes` | `encrypted_description` | `BLOB` |
| `channels` | `encrypted_name` | `BLOB` |
| `channel_categories` | `encrypted_name` | `BLOB` |
| `user_profiles` | `display_name_encrypted` | `BLOB` |

### Client Behavior

1. **Creating a node**: Client derives the NMK, encrypts the name/description, sends both plaintext and encrypted fields. (Plaintext can be a placeholder like `"encrypted-node"` once Phase 2 removes plaintext requirement.)
2. **Viewing a node**: Client decrypts `encrypted_name` if it has the NMK; falls back to plaintext `name` otherwise.
3. **Key sharing**: On member join, admin sends the NMK wrapped in the Double Ratchet session.

### Tradeoffs

| Feature | Impact |
|---------|--------|
| Server-side search by name | **Broken** for encrypted names. Search becomes client-side only. |
| Node discovery / listing | Server can't display names. Clients need the NMK first (via invite). |
| Audit logs | Server logs actions with UUIDs, not human-readable names. |
| Admin tooling | Server admin sees encrypted blobs, not community names. This is the point. |

### Migration Path

1. **Phase 1 (this PR)**: Add encrypted fields, crypto module, tests. Plaintext fields remain required.
2. **Phase 2**: Clients start sending encrypted metadata. Plaintext fields become optional (server accepts either).
3. **Phase 3**: Plaintext fields removed. Server stores only encrypted blobs + UUIDs.

### Code Locations

- **Crypto**: `core/src/metadata_crypto.rs` — `NodeMetadataKey`, `EncryptedMetadata`
- **Schema**: `server/src/db.rs` — migration adds nullable encrypted columns
- **Tests**: 13 unit tests in `metadata_crypto::tests`
