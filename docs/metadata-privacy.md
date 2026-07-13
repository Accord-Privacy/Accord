# Metadata Privacy (NMK)

> **Status:** implemented. Clients derive and distribute the Node Metadata Key,
> publish encrypted channel/category names and per-node policy, and prefer the
> decrypted values in the UI. `core/src/metadata_crypto.rs` +
> `GET/PUT /api/nodes/:id/metadata/encrypted`.

## What is (and isn't) hidden from the relay

Accord encrypts message *content* end-to-end. Beyond content, the **Node Metadata
Key (NMK)** hides the parts of a node's structure and policy that are nobody's
business but the members':

- **Channel names**, **category names**
- **Per-node policy** — disappearing-message retention, screenshot protection,
  and the client-side word-filter list — all serialized into one NMK-encrypted
  `encrypted_settings` blob the relay stores but cannot read
- (Future) role names, emoji names, per-user display names

**Deliberately NOT hidden:** a node's **name and description**. Per
[../GOVERNANCE.md](../GOVERNANCE.md), the relay owner is a landlord who may see
node names/descriptions (to run a node registry and create/delete nodes) but
nothing about who is inside. So the plaintext `nodes.name`/`description` columns
are intentionally retained — this is the one narrow metadata concession, not a
bug to be "fixed" by Phase 3.

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
- Channel names within that node
- Channel category names
- The per-node policy blob (`encrypted_settings`): disappearing-message
  retention, screenshot protection, client-side word filters
- (Future) role names, emoji names, etc.

A node's name/description may also be published in encrypted form, but the
plaintext copy is kept on purpose (the relay owner is allowed to see it — see
above). User display names use a **separate per-user key** (Phase 2).

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
| Server-side search by channel name | **Broken** for encrypted channel/category names. Search is client-side only. |
| Channel/category discovery | Relay can't display channel names; clients need the NMK first (via invite). |
| Per-node policy | Relay stores an opaque `encrypted_settings` blob; it can't read retention/screenshot/word-filter settings. |
| Node registry | Relay owner **can** see node names/descriptions by design (landlord surface), but nothing about channels, members, or policy. |

### Migration Path

1. **Phase 1 (done)**: encrypted fields, crypto module, tests; plaintext fields still written.
2. **Phase 2 (done)**: clients derive/distribute the NMK, publish encrypted channel/category names + the `encrypted_settings` policy blob, and prefer decrypted values in the UI.
3. **Phase 3 (partial)**: drop the plaintext columns the relay must not see (channel/category names) once no client depends on them. **Node name/description plaintext is intentionally retained** for the relay-owner registry (see [../GOVERNANCE.md](../GOVERNANCE.md)) — it is *not* removed.

### Code Locations

- **Crypto**: `core/src/metadata_crypto.rs` — `NodeMetadataKey`, `EncryptedMetadata`
- **Schema**: `server/src/db.rs` — migration adds nullable encrypted columns
- **Tests**: 13 unit tests in `metadata_crypto::tests`
