# Identity Model

How identity, authentication, and moderation work in Accord's zero-knowledge architecture.

---

## 1. Your Keypair Is Your Identity

Accord has no usernames, emails, phone numbers, or any personally identifiable information at the relay level. Your identity is an **Ed25519 keypair** generated on your device.

What the relay stores per user:

| Field | Description |
|-------|-------------|
| `id` | UUID v4 — internal identifier, assigned at registration |
| `public_key` | Your Ed25519 public key |
| `public_key_hash` | `SHA-256(public_key)` — the relay-level identifier |
| `password_hash` | Argon2 hash of your password |
| `created_at` | Unix timestamp |

That's the entire `users` table. No `username` column, no `email` column, no PII.

The `public_key_hash` is the canonical relay-level identifier. It's a one-way hash — even if the relay database leaks, an attacker gets SHA-256 hashes and Argon2 hashes, not keys.

---

## 2. Registration Flow

```
┌──────────┐                          ┌──────────┐
│  Client   │                          │  Relay   │
└─────┬────┘                          └─────┬────┘
      │  1. Generate Ed25519 keypair        │
      │  2. POST /register                  │
      │     { public_key, password }        │
      │─────────────────────────────────────►│
      │                                      │  3. Compute SHA-256(public_key)
      │                                      │  4. Hash password with Argon2
      │                                      │  5. Store (uuid, pkh, pk, pw_hash)
      │     { user_id: <uuid> }             │
      │◄─────────────────────────────────────│
```

1. **Client** generates an Ed25519 keypair locally. The private key never leaves the device.
2. **Client** sends `public_key` + `password` to `POST /register`.
3. **Relay** computes `public_key_hash = SHA-256(public_key)` and checks for uniqueness.
4. **Relay** hashes the password with Argon2, generates a UUID v4, stores the record.
5. **Relay** returns the UUID. Registration is complete.

No email verification. No CAPTCHA. No phone number. You exist because you have a keypair.

---

## 3. Authentication Flow

```
┌──────────┐                          ┌──────────┐
│  Client   │                          │  Relay   │
└─────┬────┘                          └─────┬────┘
      │  POST /auth                         │
      │  { public_key OR public_key_hash,   │
      │    password }                       │
      │─────────────────────────────────────►│
      │                                      │  1. Resolve public_key_hash
      │                                      │  2. Verify Argon2(password)
      │  { token, user_id, expires_at }     │
      │◄─────────────────────────────────────│
```

The client can authenticate with either:
- `public_key` (relay computes the hash)
- `public_key_hash` directly

The relay verifies the password against the stored Argon2 hash and returns a bearer token. All subsequent API calls use this token.

---

## 4. Per-Node Profiles

Display names and avatars are **not** relay-level concepts. They are **per-Node**, encrypted with the Node's metadata key (NMK), and opaque to the relay.

```sql
-- What the relay stores (node_user_profiles table)
node_id                  TEXT     -- which Node
user_id                  TEXT     -- which user (UUID)
encrypted_display_name   BLOB    -- opaque ciphertext
encrypted_avatar_url     BLOB    -- opaque ciphertext
joined_at                INTEGER
```

This means:
- You can be **"Alice"** in Node A and **"CryptoAnon"** in Node B
- The relay sees neither name — just encrypted blobs
- Only Node members with the NMK can decrypt your display name
- There is **no global profile** that links your identities across Nodes

The relay does maintain a minimal `user_profiles` table (with a default display name like `user-a1b2c3d4`) for backward compatibility, but the encrypted per-Node profiles are the canonical source.

---

## 5. Moderation: Kicks and Bans

Moderation in Accord is **strictly per-Node**. There is no global ban list, no cross-Node visibility, and no centralized moderation authority.

### Kick

- **What:** Removes a user from a Node's member list
- **Effect:** User is no longer a member, but **can rejoin** (via invite or open join)
- **Endpoint:** `DELETE /nodes/:id/members/:user_id`
- **Permission:** Requires `KickMembers` (admin/moderator role)

### Ban (Identity)

- **What:** Blocks a `public_key_hash` from rejoining a specific Node
- **Effect:** The banned user's membership is removed and they cannot rejoin with that keypair
- **Endpoint:** `POST /nodes/:id/bans` with `{ public_key_hash, ... }`
- **Supports:** Optional encrypted reason, optional expiry time
- **Scope:** This Node only

### Ban (Device)

- **What:** Blocks a `device_fingerprint_hash` from joining a specific Node — even with a new keypair
- **Effect:** Any account presenting the banned fingerprint hash is rejected at join time
- **Endpoint:** `POST /nodes/:id/bans` with `{ device_fingerprint_hash, ... }`
- **Scope:** This Node only

### What Bans Look Like in the Database

```sql
-- node_bans table
node_id                  TEXT     -- scoped to this Node
public_key_hash          TEXT     -- identity ban target
device_fingerprint_hash  TEXT     -- device ban target (nullable)
banned_by                TEXT     -- who issued the ban
banned_at                INTEGER
reason_encrypted         BLOB    -- encrypted with NMK (nullable)
expires_at               INTEGER -- nullable (null = permanent)
```

Bans are checked when a user attempts to join a Node. Both `public_key_hash` and `device_fingerprint_hash` are checked against the ban list, with expiry taken into account.

---

## 6. Ban Evasion Mitigation

| Evasion Attempt | Result |
|-----------------|--------|
| New keypair, same device | **Blocked** — device fingerprint hash matches the ban |
| New keypair + VPN | **Blocked** — fingerprinting is device-based, not IP-based |
| New keypair + new device (or factory reset) | **Gets through** — this is the deliberate tradeoff |
| Any attempt on invite-only Node | **Blocked** — needs a valid invite regardless of identity |

### Why device fingerprinting works

The fingerprint is computed from hardware and environment signals (device ID, screen resolution, GPU, OS version, timezone, locale), hashed with SHA-256 on-device. Only the hash is transmitted. See [device-fingerprinting.md](device-fingerprinting.md) for the full transparency document.

### Why we accept the factory-reset gap

Getting a new device or factory resetting is a **high barrier** — it costs time, money, or both. Combined with invite-only Nodes (already implemented), this makes persistent ban evasion impractical for most scenarios. Closing this gap completely would require invasive tracking that contradicts Accord's privacy principles.

### Strongest defense: Invite-only Nodes

Invite-only Nodes are the most effective anti-abuse measure. Even if someone evades a device ban, they still need a valid invite code to join. Invite codes can be:
- Limited to N uses
- Set to expire after N hours
- Revoked at any time

---

## 7. What the Relay Knows vs. What Nodes Know

| Data | Relay | Node Members |
|------|-------|-------------|
| Public key + hash | ✅ Stored in plaintext | ✅ (they sent it) |
| Password | ❌ Only Argon2 hash | ❌ |
| UUID | ✅ | ✅ |
| Display name | ❌ Encrypted blob | ✅ Decrypted with NMK |
| Avatar | ❌ Encrypted blob | ✅ Decrypted with NMK |
| Message content | ❌ Encrypted blob | ✅ E2E decrypted |
| Node name | ❌ Encrypted blob (Phase 2+) | ✅ Decrypted with NMK |
| Channel names | ❌ Encrypted blob (Phase 2+) | ✅ Decrypted with NMK |
| Device fingerprint | ❌ Only SHA-256 hash | Node admins only |
| Who is in which Node | ✅ Membership table (UUIDs) | ✅ |
| Ban list | ✅ Hashes only | Admins see encrypted reasons |
| IP address | ✅ At transport layer | ❌ |
| Message timestamps | ✅ | ✅ |
| Message sender UUID | ✅ | ✅ |

### What the relay explicitly does NOT know:
- Any display name, nickname, or human-readable identity
- Message content (E2E encrypted)
- Why someone was banned (reason is encrypted)
- What any Node is about (name/description encrypted in Phase 2+)
- Device hardware details (only the fingerprint hash)

---

## 8. Privacy Guarantees

### No PII collected
Registration requires only a public key and password. No email, no phone, no name, no age, no location. The relay cannot identify you as a person.

### Device fingerprint is hash-only
The six device signals (device ID, screen resolution, timezone, GPU, OS version, locale) are hashed with SHA-256 **on the client**. The raw signals never leave the device. The hash is a one-way function — the original values cannot be recovered. See [device-fingerprinting.md](device-fingerprinting.md).

### Per-Node isolation
Your identity in Node A is cryptographically unlinkable to your identity in Node B from the relay's perspective. Different encrypted display names, different encrypted avatars, no cross-Node profile.

### No cross-Node ban sharing
Bans are strictly per-Node. There is no mechanism for Node A's admin to see or import Node B's ban list. Device fingerprint hashes are stored per-Node and not shared.

### Encrypted metadata
Node names, channel names, display names, and ban reasons are encrypted with the Node Metadata Key (NMK). The relay stores opaque blobs. See [metadata-privacy.md](metadata-privacy.md).

### Open source auditability
Every component of the identity and fingerprinting system is open source under AGPL-3.0-or-later:
- Identity: `server/src/db.rs` (schema), `server/src/handlers.rs` (registration/auth)
- Fingerprinting: `core/src/device_fingerprint.rs`
- Metadata encryption: `core/src/metadata_crypto.rs`

### Honest tradeoffs

| Tradeoff | Explanation |
|----------|-------------|
| **Relay sees membership graphs** | The relay knows which UUIDs are in which Nodes. This is inherent to a relay architecture. Mitigated by UUIDs being pseudonymous. |
| **Relay sees IP addresses** | Standard for any TCP connection. Users should use Tor/VPN if this matters. |
| **Relay sees message timing** | Timestamps are stored for ordering. Timing metadata can leak patterns. |
| **Device bans aren't foolproof** | Factory reset or new device defeats them. This is by design — the alternative is invasive tracking. |
| **Plaintext metadata (Phase 1)** | Node/channel names are still plaintext during the transition period. Phase 2-3 will make encrypted metadata the default. |
