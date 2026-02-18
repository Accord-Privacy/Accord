# Accord

**Privacy-first community communications** — Discord's features with Signal's security

[![CI](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml)
[![Windows Build](https://github.com/Accord-Privacy/Accord/actions/workflows/windows.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/windows.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

## What is Accord?

Accord fills the gap between Discord (great features, no privacy) and Signal (great privacy, no community features). It's an open-source, end-to-end encrypted platform where the relay **never** has access to your messages, voice, or files.

> **The relay admin is just a landlord — they provide the building but can't enter your apartment.**

---

## Features

### 🔐 End-to-End Encryption
- **Double Ratchet + X3DH** key agreement (Signal protocol foundations)
- **AES-256-GCM** for all messages and files
- **Forward secrecy** — keys rotate per message
- **SRTP voice encryption** with periodic key rotation

### 🏘️ Nodes (Community Spaces)
- Discord-style UI: **categories, channels, roles with colors**
- **50+ permission bits** with category → channel cascade
- **Discord template import** — paste a discord.new link to scaffold your Node structure
- Node icon and user avatar uploads
- Custom user status

### 🔑 Zero-Knowledge Relay
- **Keypair-only registration** — no email, no phone, no PII
- **Per-Node encrypted profiles** — different display name/avatar per Node
- Relay stores only encrypted blobs and routing metadata

### 🎙️ Voice Channels
- **P2P mesh** for small groups (≤4 users), **relay fallback** for larger ones
- SRTP encryption on all voice traffic
- Mute/deafen controls, speaking indicators
- Opus codec for high-quality audio

### 🪪 Identity Portability
- **BIP39 mnemonic** — your identity is a 12-word seed phrase
- **Export/import file** for full account backup
- **QR code sync** between devices
- Auto session reconnect on token expiry

### 🤖 Bot API
- Scoped access with fine-grained permissions
- Webhook support for integrations
- Bots see only what their scopes allow

### 🛡️ Admin Dashboard
- Live server logs
- **Build hash verification** — clients display trust indicators so users can verify they're running unmodified code

---

## Architecture

```
┌─────────┐         ┌─────────────┐         ┌─────────┐
│  Client  │◄──E2E──►│  Relay Server│◄──E2E──►│  Client  │
│  (Tauri) │         │ (Zero-Know.) │         │  (Tauri) │
└─────────┘         └─────────────┘         └─────────┘
```

- **Relay** — routes encrypted blobs between clients. Has no decryption keys. Handles auth (keypair-based), presence, and channel metadata.
- **Node** — a community space (like a Discord server). All content is E2E encrypted; the relay only sees opaque ciphertext.
- **Client** — Tauri desktop app (Rust backend + React/TypeScript UI). Holds all crypto keys locally.

### Workspace Crates

| Crate | Purpose |
|-------|---------|
| `core/` | Cryptography, channels, bots, invites, voice, protocol |
| `server/` | WebSocket relay server (zero-knowledge routing) |
| `desktop/` | Tauri desktop app (Rust + React/TypeScript) |
| `accord-cli/` | Command-line client |

---

## Quick Start

### Requirements

- **Rust 1.86+**
- **Node.js** (for the desktop UI)
- System deps: `build-essential pkg-config libssl-dev`
- Desktop deps: `libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-2.4-dev`

### Build & Run

```bash
git clone https://github.com/Accord-Privacy/Accord
cd Accord

# Build the relay server
cargo build --release -p accord-server

# Build the desktop client
cd desktop/src-ui && npm install && cd ../..
cargo build --release -p accord-desktop

# Run the relay
./target/release/accord-server

# Run tests
cargo test
```

---

## Self-Hosting

Accord is designed to be self-hosted. A **$5/month VPS** or a spare desktop on your LAN is all you need.

1. Build `accord-server` (see above) or use the Docker setup in `docker/`
2. Open port **8080** (WebSocket) on your firewall
3. Point clients at your relay's address

The relay is lightweight — it never decrypts anything, so CPU and memory usage stay low. See **[docs/SELF-HOSTING.md](docs/SELF-HOSTING.md)** for detailed instructions.

---

## Security

### What the relay **can** see
- Which keypairs are online
- Which Node a user is connected to (routing metadata)
- Encrypted blob sizes and timestamps

### What the relay **cannot** see
- Message contents, file names, or file contents
- Voice audio
- Display names, avatars, or any profile information (encrypted per-Node)
- Permission assignments or role names within a Node

### Design Principles
- **No PII at registration** — identity is a keypair, optionally backed by a BIP39 mnemonic
- **Forward secrecy** — compromising a key doesn't reveal past messages
- **Build verification** — clients ship a build hash so users can verify binary integrity
- **Minimal trust surface** — the relay is designed to be untrusted by default

**Reporting Vulnerabilities:** Do **not** create public issues. Use [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories).

---

## Comparison

| | Accord | Discord | Signal | Matrix |
|---|:---:|:---:|:---:|:---:|
| E2E encryption | ✅ | ❌ | ✅ | ✅ |
| Community features | ✅ | ✅ | ❌ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ |
| Zero-knowledge server | ✅ | ❌ | ✅ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ |
| No PII required | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ❌ | ✅ | ✅ |

---

## Contributing

See **[CONTRIBUTING.md](CONTRIBUTING.md)** for development guidelines.

---

## License

**GNU Affero General Public License v3.0** — see [LICENSE](LICENSE).

You can use, modify, and distribute this software, but any modifications must also be open-source under AGPL v3.

---

**Built with ❤️ for privacy-conscious communities** · [accord.chat](https://accord.chat)
