# Security Policy

## Reporting Vulnerabilities

**Do NOT open public issues for security vulnerabilities.**

Please report security issues through [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories). You'll receive a response within 48 hours.

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We follow responsible disclosure. We'll coordinate with you on timing and credit.

---

## Security Design Overview

Accord is built on the principle that **the server should never be trusted with user data**. The relay is designed as a zero-knowledge routing layer.

### Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Key agreement | X3DH (Extended Triple Diffie-Hellman) |
| Message encryption | Double Ratchet protocol |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA256 |
| Identity keys | Ed25519 / X25519 |
| Voice encryption | SRTP |
| Identity backup | BIP39 mnemonic (12-word seed phrase) |

### End-to-End Encryption Flow

1. **Registration** — Client generates an Ed25519 keypair. No PII is sent to the relay.
2. **Key exchange** — X3DH establishes a shared secret between two users via prekey bundles stored (encrypted) on the relay.
3. **Messaging** — Double Ratchet derives per-message keys with forward secrecy. Each message is encrypted with AES-256-GCM.
4. **Voice** — SRTP with keys negotiated client-side. The relay forwards encrypted audio packets without decryption.
5. **Files** — Encrypted client-side before upload. The relay stores opaque blobs.

### Forward Secrecy

Keys rotate with every message via the Double Ratchet. Compromising a single message key does not reveal past or future messages.

---

## What the Relay Sees vs. Doesn't See

### ✅ The relay **can** see:
- Which public keys are registered and online (presence)
- Which Node a user is connected to (routing metadata)
- Encrypted blob sizes and timestamps
- IP addresses of connected clients (standard for any network service)

### ❌ The relay **cannot** see:
- Message contents
- File names or file contents
- Voice audio
- Display names, avatars, or profile information (encrypted per-Node)
- Role names or permission assignments within a Node
- Which specific channel within a Node a message belongs to (encrypted routing)

### Metadata Considerations

While message contents are fully encrypted, some metadata is inherently visible to the relay for routing purposes. See [docs/metadata-privacy.md](docs/metadata-privacy.md) for a detailed analysis of metadata exposure and available mitigation modes.

---

## Threat Model

### In scope:
- **Compromised relay** — A malicious relay operator should learn nothing beyond routing metadata
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

For security matters: [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories)

For general questions: [GitHub Discussions](https://github.com/Accord-Privacy/Accord/discussions)
