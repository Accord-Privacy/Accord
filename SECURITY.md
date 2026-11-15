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

### Attachments are only as private and as authentic as their message

Desktop and web clients encrypt every attachment on the device before upload, with a new random 256-bit key and nonce prefix for that file only (AES-256-GCM in 64 KiB records, padded with Padmé). The key, the file name, the file type and the SHA-256 of the encrypted file travel only inside the end-to-end-encrypted message that carries the file: Sender Keys in node channels, the Double Ratchet in DMs. The relay stores a nameless blob, links it to its message and deletes it with the message; unclaimed uploads expire after an hour. Recipients check the blob's length, hash and every record before using any of it, and never fall back to unencrypted data or to the old channel key. This needs a relay that advertises `attachments/2`; on an older relay, clients do not send attachments at all.

The limits:

- **Authenticity.** Attachments are exactly as private and as authentic as the message that carries them. Until identity verification and key-recipient checks ship, a relay that holds an injected sender key for a channel, or that intercepted a Double Ratchet session when it was set up (see below), can read the attachments sent there and can forge attachments, with its own file, name and type, attributed to the member it impersonates.
- **Metadata.** The relay still sees that a message has attachments and how many, each file's padded size (the padding leaks only a few bits of the real size, plus 16 bytes per 64 KiB), when it was uploaded, by whom, in which channel, which message it belongs to, and which members download it, when and from which IP address. It does not see file names, file types, contents, keys or exact sizes.
- **Deletion and expiry signals.** To delete attachments with their messages, clients obey the relay's message-deletion, purge and expiry signals, which are not authenticated. A malicious relay can use them to make your device delete a message and the attachment keys it holds. For a DM attachment that can be the device's only copy of the key, so the file becomes unreadable on that device. Nothing is disclosed this way.
- **Files uploaded before this release are not end-to-end encrypted.** They were encrypted under a key derived from the channel ID, which the relay knows, so the relay operator, or anyone who obtains the relay's database, its file storage or a backup, can decrypt and replace them and their names. The relay keeps these legacy uploads read-only and deletes them when its retirement window ends (90 days after the upgrade by default, or earlier if the operator retires them). Clients show them only in an opt-in "Legacy uploads" section, with a warning on every item, until a fixed cutoff date, and never inside a message.
- **Older clients.** Clients released before end-to-end-encrypted attachments cannot upload files to an upgraded relay. They show a message with attachments as text that starts with a request to update; that text contains the attachment keys and stays on the recipient's device, but a bookmark copies it into unencrypted storage. If such a client edits that message in a DM, it sends the text, keys included, to the relay unencrypted. Update every client.
- **Availability.** A DM attachment that arrives while you are offline does not appear, and other members' channel attachments appear only on messages displayed as they arrive, until message history is cached on the device.
- **Other clients.** The mobile apps and the command-line client do not support attachments.

Relay operators: a reverse proxy in front of the relay must accept request bodies as large as the relay's attachment limit (100 MiB by default; nginx needs `client_max_body_size 101m`), or uploads fail with 413. See [Request body size for attachments](docs/SELF-HOSTING.md#request-body-size-for-attachments).

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
| File encryption | AES-256-GCM in 64 KiB records (`A256GCM-STREAM64K`) with a random key per file, carried inside the end-to-end-encrypted message. Legacy uploads from before this release: AES-256-GCM with a key the relay can compute (not end-to-end) |
| Identity backup | BIP39 mnemonic (12-word seed phrase) |

### End-to-End Encryption Flow

1. **Registration** — Client generates an Ed25519 keypair. No PII is sent to the relay.
2. **Key exchange** — X3DH establishes a shared secret between two users via prekey bundles stored on the relay. Prekeys are not signed yet, so a malicious relay can substitute them (see [Known Limitations](#known-limitations)).
3. **Messaging** — Double Ratchet derives per-message keys with forward secrecy. Each message is encrypted with AES-256-GCM.
4. **Voice** — Not end-to-end encrypted. In relay mode (the default) the relay forwards AES-256-GCM audio frames, but it also forwards the keys in a form it can read. P2P mode uses browser WebRTC (DTLS-SRTP) directly between participants, which reveals their IP addresses to each other and can be intercepted by the relay.
5. **Files** — Each file is encrypted on the device with its own random key and nonce prefix; the key, name, type and ciphertext hash travel only inside the end-to-end-encrypted message, so attachments are exactly as private and as authentic as that message (see [Known Limitations](#known-limitations)). Legacy uploads from before this release are not end-to-end encrypted.

### Forward Secrecy

Keys rotate with every message via the Double Ratchet. Compromising a single message key does not reveal past or future messages.

---

## What the Relay Sees vs. Doesn't See

### ✅ The relay **can** see:
- Which public keys are registered and online (presence)
- Which Node a user is connected to (routing metadata — never surfaced in the admin dashboard)
- **Node names and descriptions** — a deliberate concession so the relay owner can run a node registry and create/delete nodes (see [GOVERNANCE.md](GOVERNANCE.md))
- Encrypted blob sizes and timestamps
- **Attachment metadata** — that a message has attachments and how many, each file's padded size, when it was uploaded, by whom, in which channel and with which message, and which members download it, when and from which IP address
- **Legacy uploads** — the contents and names of files uploaded before end-to-end-encrypted attachments shipped, until they are retired (see [Known Limitations](#known-limitations))
- **Relay-mode voice audio** — the relay receives the voice keys (see [Known Limitations](#known-limitations))
- Which channel each message and file belongs to (channel IDs are stored in the clear; channel names are encrypted)
- Role names, role permission values, and which members hold which roles
- **Node membership, invites and join requests** — the relay enforces admission, so it knows which accounts are members of which node, holds each node's invite codes and bans, and sees who asked to join which node (pending join requests, kept for up to 14 days)
- IP addresses of connected clients — standard for any network service. The relay owner keeps a node-correlation-free connection log for DoS/DDoS defense and IP bans; IPs are **never** linked to nodes in that log and are not shown to node owners. P2P voice and P2P screen sharing do reveal IP addresses to the other participants (see [Known Limitations](#known-limitations))

### ❌ The relay **cannot** see:
- Message contents
- Attachment contents, file names, file types, keys and exact sizes (as long as the carrying message is not intercepted; see [Known Limitations](#known-limitations))
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
