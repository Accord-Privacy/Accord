# Accord — Architecture

> Single source of truth for Accord's architecture decisions.
> Last updated: 2026-02-17

---

## 1. Core Philosophy

Accord exists because no platform combines Discord's community features with Signal's privacy guarantees. Four principles drive every decision:

1. **Privacy-first.** If the relay doesn't need data, it doesn't store it. If it must store something, it stores an encrypted blob or a one-way hash — never plaintext.

2. **Zero-knowledge relay.** The relay server is a dumb encrypted pipe. It stores encrypted blobs, routes traffic by UUID, and knows nothing about content, identities, or community structure.

3. **Simple self-hosting.** Run a single binary on a $5/month VPS or a spare desktop. No domain name, no Cloudflare, no reverse proxy, no infrastructure expertise required.

4. **No PII collected.** No phone numbers, emails, usernames, or personally identifiable information. Registration requires only a public key and a password. You exist because you have a keypair.

---

## 2. Architecture Overview

```
┌─────────────┐     E2E Encrypted     ┌──────────────┐     E2E Encrypted     ┌─────────────┐
│  Client App  │◄─────────────────────►│  Relay Server │◄─────────────────────►│  Client App  │
│              │                       │               │                       │              │
│ • Encryption │                       │ • Routing     │                       │ • Encryption │
│ • Decryption │                       │ • Storage     │                       │ • Decryption │
│ • Key mgmt   │                       │ • Auth        │                       │ • Key mgmt   │
│ • UI         │                       │ • WebSocket   │                       │ • UI         │
└─────────────┘                       └──────────────┘                       └─────────────┘
```

### Relay Server

The relay is a dumb pipe. It:
- Stores encrypted message blobs in SQLite
- Routes WebSocket traffic between clients by UUID
- Authenticates users via public key hash + Argon2 password
- Enforces rate limits and transport-level security
- **Knows nothing** about message content, display names, community names, or user identities

The relay admin is a landlord — they provide the building but cannot enter the apartments.

### Nodes

Nodes are community spaces hosted on a relay — analogous to Discord servers, but end-to-end encrypted. Each Node is a **walled garden**:
- Complete isolation from other Nodes on the same relay
- No cross-Node visibility of members, messages, bans, or metadata
- Contains channels, roles, permissions, and member profiles — all encrypted with the Node Metadata Key (NMK)

### Client App

The client does all the heavy lifting:
- Generates and manages keypairs
- Performs all encryption and decryption
- Manages relay connections invisibly (users never see server addresses)
- Handles key exchange (X3DH), ratcheting (Double Ratchet), and metadata encryption
- Available as desktop (Tauri), CLI, iOS (Swift FFI), and Android (Kotlin JNI)

---

## 3. User Experience Flow

Users never "join a relay." They join **Nodes** via invite links. The relay is invisible infrastructure.

```
1. User receives invite link
2. Client decodes the link → extracts relay address (obfuscated)
3. Client silently registers on the relay (generates keypair if first time)
4. Client joins the Node
5. User is chatting. Never saw a server address.
```

### Invite Link Design

Invite links encode the relay address in an encrypted/obfuscated form. Users **cannot** extract the server IP from an invite link. This provides:
- **UX simplicity** — one tap to join, no server configuration
- **DDoS protection by default** — attackers can't target what they can't find
- **Privacy** — relay operators aren't exposed unless they choose to be

### Registration Flow

```
Client                                    Relay
  │  Generate Ed25519 keypair               │
  │  POST /register { public_key, password }│
  │────────────────────────────────────────►│
  │                                         │ Compute SHA-256(public_key)
  │                                         │ Hash password with Argon2id
  │                                         │ Store (uuid, pkh, pk, pw_hash)
  │  { user_id: <uuid> }                   │
  │◄────────────────────────────────────────│
```

No email verification. No CAPTCHA. No phone number. You exist because you have a keypair.

---

## 4. Identity Model

### Keypair = Identity

Your identity is an **Ed25519 keypair** generated on your device. The private key never leaves the device.

What the relay stores per user:

| Field | Description |
|-------|-------------|
| `id` | UUID v4 — internal routing identifier |
| `public_key` | Ed25519 public key |
| `public_key_hash` | `SHA-256(public_key)` — the relay-level identifier |
| `password_hash` | Argon2id hash |
| `created_at` | Unix timestamp |

That's the entire `users` table. No `username`, no `email`, no PII.

### Human-Readable Short Codes

For sharing identities out-of-band, public keys can be represented as human-readable short codes derived from the public key hash:

```
ACCORD-XXXX-XXXX
```

These are deterministic — anyone with your public key can compute your short code. They're for human convenience; the canonical identifier is always the full `public_key_hash`.

### Per-Node Display Names

Display names are **not** a relay-level concept. They are per-Node, encrypted with the Node Metadata Key (NMK), and opaque to the relay.

- You can be **"Alice"** in Node A and **"CryptoAnon"** in Node B
- The relay sees neither name — just encrypted blobs
- Only Node members with the NMK can decrypt display names
- There is **no global profile** linking identities across Nodes

---

## 5. Node Isolation

Nodes are walled gardens. This is absolute and non-negotiable.

| Guarantee | Detail |
|-----------|--------|
| No shared member lists | Node A cannot see who is in Node B |
| No shared ban lists | A ban in Node A has zero effect on Node B |
| No shared messages | Messages exist only within their Node |
| No shared metadata | Names, descriptions, channels — all per-Node |
| No cross-Node profiles | Different encrypted display names per Node |

### Ban System

Bans are strictly per-Node and operate on hashes, never plaintext identifiers:

- **Identity ban**: blocks a `public_key_hash` from rejoining a specific Node
- **Device ban**: blocks a `device_fingerprint_hash` from joining with any keypair
- **Ban reasons**: encrypted with NMK — the relay cannot read them
- **Expiry**: optional, supports temporary bans

| Evasion Attempt | Result |
|-----------------|--------|
| New keypair, same device | **Blocked** — device fingerprint hash matches |
| New keypair + VPN | **Blocked** — fingerprinting is device-based, not IP-based |
| New keypair + new device / factory reset | **Gets through** — deliberate tradeoff (see §10) |

### Device Fingerprinting

Six signals (device ID, screen resolution, timezone, GPU, OS version, locale) are hashed with SHA-256 **on-device**. Only the hash is transmitted. Raw signals never leave the device. The fingerprint exists solely for ban enforcement — never for tracking, analytics, or cross-Node identification. Full transparency document: [device-fingerprinting.md](device-fingerprinting.md).

---

## 6. DMs and Friend System

### Adding Friends

- You must **share a Node** with someone to add them as a friend
- Friend request = exchange DM key bundles inside the Node's E2E encrypted channel
- The relay never sees who is friends with whom in plaintext — it routes encrypted blobs

### DM Architecture

- Once friends, DMs work even if both users leave the originating Node
- DMs are **relay-level**, not Node-level — they exist independently of any Node
- DMs use their own Double Ratchet sessions, separate from Node message encryption

### Cross-Relay DMs (Future — Tier 2)

When relay mesh is implemented:
- Friends on different relays can DM via relay-to-relay routing
- Requires a **friendship proof** — a mutual cryptographic attestation signed by both users
- The routing relay sees only encrypted blobs and destination UUIDs
- No relay can inject, read, or enumerate cross-relay DMs without valid proofs

---

## 7. Relay Mesh (Future — Tier 2)

Relay servers can optionally peer with each other. The mesh has **one purpose only**: route cross-relay DMs between established friends.

### Design Constraints

| Rule | Reason |
|------|--------|
| Zero Node data crosses relay boundaries | Nodes are local to their relay — always |
| Friendship proof required for routing | Both users must have signed the proof |
| No user enumeration across relays | Relays don't share member lists |
| No content visibility | All DMs are E2E encrypted end-to-end |

### Malicious Relay Protections

| Attack | Mitigation |
|--------|-----------|
| Inject fake DMs | Impossible — no valid friendship proof |
| Enumerate users on other relays | No discovery protocol exists |
| Read DM content | E2E encrypted — relay has no keys |
| Correlate users across relays | Only sees encrypted blobs + UUIDs |

---

## 8. Self-Hosting

### Getting Started

```bash
# Option 1: Binary
./accord-server

# Option 2: Docker
docker run accord
```

That's it. No domain name, no Cloudflare, no DNS proxy, no reverse proxy. An IP address works fine.

### Requirements

- A machine with a public IP (or port forwarding)
- ~128MB RAM, minimal CPU
- Target: $5/month VPS or free on spare hardware

### DDoS Protection Model

The primary DDoS protection is architectural: **users don't know the relay's IP address.** Invite links encode the address in an obfuscated form that clients decode internally. Attackers can't target what they can't find.

For operators who want additional protection:
- Cloudflare proxy — optional, documented separately
- Tor hidden service — optional, documented separately
- Neither is required for normal operation

### Server Admin Capabilities

The server admin can:
- Start, stop, and maintain the relay process
- See encrypted blobs, UUIDs, and timestamps
- Set Node creation policies (`admin_only | open | approval | invite`)

The server admin **cannot**:
- Read any message content
- See any display name, channel name, or Node name (encrypted with NMK)
- Access any Node as a member (unless explicitly invited)
- Decrypt any metadata

---

## 9. What the Relay Sees vs. Doesn't See

| Data | Relay Sees | Relay Does NOT See |
|------|:---:|:---:|
| Message content | ❌ Encrypted blob | ✅ Plaintext (client only) |
| Display names | ❌ Encrypted blob | ✅ Plaintext (Node members only) |
| Node names | ❌ Encrypted blob | ✅ Plaintext (Node members only) |
| Channel names | ❌ Encrypted blob | ✅ Plaintext (Node members only) |
| Ban reasons | ❌ Encrypted blob | ✅ Plaintext (Node admins only) |
| File names | ❌ Encrypted | ✅ Plaintext (client only) |
| Voice audio | ❌ SRTP encrypted | ✅ Audio (participants only) |
| Public key + hash | ✅ | — |
| User UUID | ✅ | — |
| Password | ❌ Only Argon2id hash | — |
| Node membership (UUIDs) | ✅ | — |
| Message timestamps | ✅ | — |
| Message sender UUID | ✅ | — |
| IP address | ✅ (transport layer) | — |
| Device fingerprint | ❌ Only SHA-256 hash | — |
| Device hardware details | ❌ | — |

### Honest Assessment

The relay **does** see:
- **Membership graphs** — which UUIDs belong to which Nodes. This is inherent to relay routing. Mitigated by UUIDs being pseudonymous.
- **IP addresses** — standard for any TCP connection. Users who care should use Tor or a VPN.
- **Message timing** — timestamps are stored for ordering. Timing patterns can leak metadata. Future mitigation: onion routing (Phase 7).
- **Traffic volume** — the relay knows how active a Node is, even if it can't read content.

---

## 10. Encryption Stack

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| Key agreement | X3DH (Extended Triple Diffie-Hellman) | Initial key exchange between users |
| Message encryption | Double Ratchet (AES-256-GCM) | Per-message forward secrecy |
| Metadata encryption | AES-256-GCM | Node names, channel names, display names |
| Key derivation | HKDF-SHA256 | Deriving per-purpose keys from shared secrets |
| Voice encryption | SRTP (AES-128-CTR + HMAC-SHA1) | Per-packet voice encryption with 30s key rotation |
| Identity keys | Ed25519 | Long-term identity for users and servers |
| Password hashing | Argon2id | Server-side password verification |

### Metadata Key Architecture

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
   AES-256-GCM encryption of all Node metadata
```

Each Node has one NMK. The NMK is distributed to new members via the existing Double Ratchet encrypted channel, piggybacked on session establishment.

### Encrypted Metadata Wire Format

```
[version: 1 byte] [nonce: 12 bytes] [AES-256-GCM ciphertext + 16-byte tag]
```

### Forward Secrecy

The Double Ratchet provides per-message forward secrecy: compromising a key reveals only the single message it encrypted. Past and future messages remain secure. Voice uses 30-second key rotation via SRTP.

### Future: Post-Quantum

Phase 7 will add hybrid key exchange (X25519 + ML-KEM/Kyber) to protect against quantum computing threats. The hybrid approach ensures security even if one algorithm is broken.

---

## Tradeoffs — What We Accept and Why

| Tradeoff | Why We Accept It |
|----------|-----------------|
| **Relay sees membership graphs** | Inherent to relay routing. UUIDs are pseudonymous. Full mitigation requires onion routing (Phase 7). |
| **Relay sees IP addresses** | Standard TCP. Users can use Tor/VPN. We don't log IPs beyond what's needed for active connections. |
| **Relay sees message timing** | Required for message ordering. Timing analysis is a known metadata risk. Onion routing planned for Phase 7. |
| **Device bans defeated by factory reset** | Closing this gap requires invasive hardware-level tracking that contradicts our privacy principles. The high barrier (new device or factory reset) is sufficient for most abuse scenarios. Invite-only Nodes provide the strongest defense. |
| **NMK shared to all Node members** | A compromised member can decrypt metadata. This is inherent to group encryption. Revoking a member requires NMK rotation (planned). |
| **No server-side search of encrypted fields** | Encrypted names can't be searched server-side. Search is client-side only. This is the point. |

---

## Code Map

| Component | Location |
|-----------|----------|
| Cryptography (encryption, keys, ratchet) | `core/src/` |
| Metadata encryption | `core/src/metadata_crypto.rs` |
| Device fingerprinting | `core/src/device_fingerprint.rs` |
| Relay server | `server/src/` |
| Database schema & migrations | `server/src/db.rs` |
| Registration & auth handlers | `server/src/handlers.rs` |
| Desktop app (Tauri + React) | `desktop/` |
| CLI client | `accord-cli/` |
| iOS bridge | Swift FFI via `core/` |
| Android bridge | Kotlin JNI via `core/` |

---

## Related Documents

- [Identity Model](identity-model.md) — keypair identity, authentication, moderation details
- [Device Fingerprinting](device-fingerprinting.md) — full transparency on what's collected and why
- [Metadata Privacy](metadata-privacy.md) — NMK architecture and migration phases
- [ROADMAP.md](../ROADMAP.md) — development phases and timeline
