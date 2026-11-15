# Security Policy

## Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Please report security issues privately through GitHub: open the repository's **Security** tab and click **Report a vulnerability**, or go directly to <https://github.com/Accord-Privacy/Accord/security/advisories/new>. This is the only channel for security reports; the project does not use a security email address. You'll receive a response within 48 hours.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We follow responsible disclosure. We'll coordinate with you on timing and credit.

---

## Known Limitations

Accord's goal is a relay that cannot read what you send (see the design overview below). The current release does not meet that goal in the following ways.

### Files (attachments) are not end-to-end encrypted

Files are encrypted before upload, but with a key derived only from the channel ID, which the relay knows. The relay operator, or anyone who obtains the relay's database, its file storage or a backup, can therefore decrypt and replace any file and its file name, including files uploaded in the past. If encryption fails or is not active, the desktop client uploads the file and its name unencrypted. Do not share a file through Accord unless you are comfortable with the relay operator being able to read it.

### Voice is not end-to-end encrypted

- **Relay mode (the default):** relay-mode voice is readable by the relay operator. Audio frames are encrypted with AES-256-GCM, but each participant's key is sent through the relay in a form the relay can read, so the operator can listen to calls and inject audio into them.
- **P2P mode and screen sharing:** P2P voice and P2P screen sharing reveal your IP address to the other participants, and they can be intercepted by the relay. They connect participants directly through browser WebRTC (DTLS-SRTP), and the connection setup passes through the relay without any check that the keys belong to the other participants. A channel's voice mode can be changed by other users, so joining any voice channel can expose your IP address this way, even if you did not choose P2P mode. These connections also contact public STUN servers run by Google, which learn your IP address; starting a screen share does this even in relay mode.

### Node membership is enforced by the relay, not by members' clients

The relay decides who may join a node: only with a valid invite, an approved join request, or as the node's owner (see [GOVERNANCE.md](GOVERNANCE.md#admission-is-enforced-by-the-relay)). This protects a node from other users of an honest relay. It does not protect against a malicious relay operator, who can add members, and clients still send group keys to whichever members the relay lists. Invite codes are bearer secrets: anyone holding a valid code can join until it expires, runs out or is revoked. Members who joined a node by its id before the relay enforced admission are still members until an owner removes them.

### A malicious relay can intercept encrypted sessions when they are set up

Until identity verification ships, a malicious relay can intercept end-to-end-encrypted (Double Ratchet) sessions when they are set up, by substituting keys. Prekeys are not signed, identity keys are not bound to accounts, and clients neither remember a contact's keys nor offer safety numbers to compare, so neither side can tell that the relay handed out its own keys instead of the contact's. A relay that does this can read and alter everything sent over the intercepted session. Channel keys (Sender Keys) and Node Metadata Keys are sent to other members over these sessions, so a relay that intercepts a session can also obtain the keys sent through it.

---

## Security Design Overview

Accord is built on the principle that **the server should never be trusted with user data**. The relay is designed as a zero-knowledge routing layer. [Known Limitations](#known-limitations) lists where the current release falls short of this design.

### Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Key agreement | X3DH (Extended Triple Diffie-Hellman) |
| Message encryption | Double Ratchet protocol |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Identity keys | Ed25519 / X25519 |
| Relay-mode audio | AES-256-GCM, with keys the relay can read (not end-to-end) |
| File encryption | AES-256-GCM, with a key the relay can compute (not end-to-end) |
| Identity backup | BIP39 mnemonic (12-word seed phrase) |

### End-to-End Encryption Flow

1. **Registration** — Client generates an Ed25519 keypair. No PII is sent to the relay.
2. **Key exchange** — X3DH establishes a shared secret between two users via prekey bundles stored on the relay. Prekeys are not signed yet, so a malicious relay can substitute them (see [Known Limitations](#known-limitations)).
3. **Messaging** — Double Ratchet derives per-message keys with forward secrecy. Each message is encrypted with AES-256-GCM.
4. **Voice** — Not end-to-end encrypted. In relay mode (the default) the relay forwards AES-256-GCM audio frames, but it also forwards the keys in a form it can read. P2P mode uses browser WebRTC (DTLS-SRTP) directly between participants, which reveals their IP addresses to each other and can be intercepted by the relay.
5. **Files** — Not end-to-end encrypted. Files are encrypted client-side before upload, but under a key derived from the channel ID, which the relay can compute.

### Forward Secrecy

Keys rotate with every message via the Double Ratchet. Compromising a single message key does not reveal past or future messages.

---

## What the Relay Sees vs. Doesn't See

### ✅ The relay **can** see:
- Which public keys are registered and online (presence)
- Which Node a user is connected to (routing metadata — never surfaced in the admin dashboard)
- **Node names and descriptions** — a deliberate concession so the relay owner can run a node registry and create/delete nodes (see [GOVERNANCE.md](GOVERNANCE.md))
- Encrypted blob sizes and timestamps
- **File contents and file names** — files are encrypted under a key the relay can compute (see [Known Limitations](#known-limitations))
- **Relay-mode voice audio** — the relay receives the voice keys (see [Known Limitations](#known-limitations))
- Which channel each message and file belongs to (channel IDs are stored in the clear; channel names are encrypted)
- Role names, role permission values, and which members hold which roles
- **Node membership, invites and join requests** — the relay enforces admission, so it knows which accounts are members of which node, holds each node's invite codes and bans, and sees who asked to join which node (pending join requests, kept for up to 14 days)
- IP addresses of connected clients — standard for any network service. The relay owner keeps a node-correlation-free connection log for DoS/DDoS defense and IP bans; IPs are **never** linked to nodes in that log and are not shown to node owners. P2P voice and P2P screen sharing do reveal IP addresses to the other participants (see [Known Limitations](#known-limitations))

### ❌ The relay **cannot** see:
- Message contents
- Display names, avatars, or profile information (encrypted per-Node)
- Per-node policy (disappearing-message retention, screenshot protection, word filters) — carried in the NMK-encrypted settings blob
- Why someone was banned (ban reasons are encrypted). The relay stores and enforces memberships, bans and roles, but there is no relay-level audit aggregate and no user roster in the admin surface

This list assumes a relay that follows the protocol. A malicious relay can read message contents, and anything protected by keys sent over an intercepted session, by intercepting sessions when they are set up (see [Known Limitations](#known-limitations)).

### Metadata Considerations

While message contents are fully encrypted, some metadata is inherently visible to the relay for routing purposes. See [docs/metadata-privacy.md](docs/metadata-privacy.md) for a detailed analysis of metadata exposure and available mitigation modes.

---

## Threat Model

### In scope:
- **Compromised relay** — The goal is that a malicious relay operator learns nothing beyond routing metadata. The current release does not meet this goal: see [Known Limitations](#known-limitations)
- **Network observers** — TLS protects the transport layer; E2EE protects the application layer
- **Stolen device** — Keys are stored locally; device compromise exposes that device's keys only (forward secrecy limits blast radius)

### Out of scope:
- **Compromised client** — If malware has full access to a user's device, it can read decrypted messages (this is true for any E2EE system)
- **Side-channel attacks** on the client application
- **Traffic analysis** — Timing and size metadata can leak information; we document this honestly rather than claiming to prevent it

---

## Dependency Security

- We run `cargo audit` in CI on every push
- All audit findings are investigated and tracked
- Security-critical dependencies use well-maintained, audited crates
- See [`.cargo/audit.toml`](.cargo/audit.toml) for any temporarily accepted advisories with justification

---

## Build Verification

Accord supports [reproducible builds](REPRODUCIBLE-BUILDS.md) so users can verify they're running unmodified code. Clients display build hash trust indicators.

---

## Contact

For security matters: report privately at <https://github.com/Accord-Privacy/Accord/security/advisories/new> (**Report a vulnerability** on the repository's Security tab)

For general questions: [GitHub Discussions](https://github.com/Accord-Privacy/Accord/discussions)
