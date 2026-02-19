<div align="center">

# 🔒 Accord

**Privacy-first community communications platform**

*Discord's features with Signal's security*

[![CI](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml)
[![Windows Build](https://github.com/Accord-Privacy/Accord/actions/workflows/windows.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/windows.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust 1.86+](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)

[Website](https://accord.chat) · [Quick Start](#quick-start) · [Self-Hosting](docs/SELF-HOSTING.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Roadmap](ROADMAP.md)

</div>

---

<!-- TODO: Add screenshot of the desktop app here -->
<!-- ![Accord Screenshot](docs/assets/screenshot.png) -->

## What is Accord?

Accord fills the gap between **Discord** (great features, no privacy) and **Signal** (great privacy, no community features). It's an open-source, end-to-end encrypted platform where the relay server **never** has access to your messages, voice, or files.

> **The relay admin is just a landlord — they provide the building but can't enter your apartment.**

## ✨ Features

### 🔐 End-to-End Encryption
- **Double Ratchet + X3DH** key agreement (Signal protocol foundations)
- **AES-256-GCM** for all messages and files
- **Forward secrecy** — keys rotate per message
- **SRTP voice encryption** with periodic key rotation

### 🏘️ Nodes (Community Spaces)
- Discord-style UI: **categories, channels, roles with colors**
- **50+ permission bits** with category → channel cascade
- **Discord template import** — paste a discord.new link to scaffold your Node
- Node icons, user avatars, custom status

### 🔑 Zero-Knowledge Relay
- **Keypair-only registration** — no email, no phone, no PII
- **Per-Node encrypted profiles** — different display name/avatar per Node
- Relay stores only encrypted blobs and routing metadata

### 🎙️ Voice Channels
- **P2P mesh** for small groups (≤4), **relay fallback** for larger ones
- SRTP encryption on all voice traffic
- Mute/deafen controls, speaking indicators, Opus codec

### 🪪 Identity Portability
- **BIP39 mnemonic** — your identity is a 12-word seed phrase
- **Export/import** for full account backup
- **QR code sync** between devices

### 🤖 Bot API
- Scoped access with fine-grained permissions
- Webhook support for integrations

### 📦 More
- **File sharing** with E2E encrypted uploads
- **Themes** and customizable UI
- **Build hash verification** — clients display trust indicators
- **Reproducible builds** — verify you're running unmodified code

---

## Architecture

```
┌─────────┐         ┌──────────────┐         ┌─────────┐
│  Client  │◄──E2E──►│ Relay Server │◄──E2E──►│  Client  │
│  (Tauri) │         │(Zero-Knowledge)│        │  (Tauri) │
└─────────┘         └──────────────┘         └─────────┘
```

**Relay** — routes encrypted blobs. Has no decryption keys. Handles auth, presence, and channel metadata.

**Node** — a community space (like a Discord server). All content is E2E encrypted; the relay sees only opaque ciphertext.

**Client** — Tauri desktop app (Rust backend + React/TypeScript UI). All crypto keys stay local.

### Workspace Crates

| Crate | Purpose |
|---|---|
| [`core/`](core/) | Cryptography, protocol, channels, voice, bots, invites |
| [`server/`](server/) | WebSocket relay server (zero-knowledge routing) |
| [`desktop/`](desktop/) | Tauri desktop app (Rust + React/TypeScript) |
| [`accord-cli/`](accord-cli/) | Command-line client |
| [`core-minimal/`](core-minimal/) | Lightweight core for resource-constrained targets |
| [`standalone-demo/`](standalone-demo/) | Self-contained demo |

---

## Quick Start

### Prerequisites

- **Rust 1.86+** — [rustup.rs](https://rustup.rs)
- **Node.js 20+** — for the desktop UI
- **System deps** (Debian/Ubuntu):
  ```bash
  sudo apt install build-essential pkg-config libssl-dev
  ```
- **Desktop deps** (for Tauri):
  ```bash
  sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-2.4-dev
  ```

### Build & Run

```bash
git clone https://github.com/Accord-Privacy/Accord.git
cd Accord

# Run the relay server
cargo build --release -p accord-server
./target/release/accord-server

# Build the desktop client
cd desktop/frontend && npm ci && npm run build && cd ../..
cargo build --release -p accord-desktop

# Run tests
cargo test
```

See **[QUICKSTART.md](QUICKSTART.md)** for a more detailed walkthrough.

---

## Self-Hosting

Accord is designed to be self-hosted. A **$5/month VPS** or a spare machine on your LAN is all you need.

1. Build `accord-server` (see above) or use Docker
2. Open port **8080** (WebSocket)
3. Point clients at your relay's address

The relay is lightweight — it never decrypts anything, so resource usage stays low.

📖 **[Full self-hosting guide →](docs/SELF-HOSTING.md)**

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

## Documentation

- **[Architecture](docs/architecture.md)** — system design deep-dive
- **[Permission System](docs/permission-system.md)** — roles, bits, cascade model
- **[Identity Model](docs/identity-model.md)** — keypair identity & BIP39
- **[Metadata Privacy](docs/metadata-privacy.md)** — what's visible vs encrypted
- **[Bot API](docs/bot-api.md)** — building integrations
- **[Self-Hosting](docs/SELF-HOSTING.md)** — deployment guide
- **[Reproducible Builds](REPRODUCIBLE-BUILDS.md)** — build verification

---

## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions, coding standards, and PR guidelines.

## Security

For security design details and vulnerability reporting, see **[SECURITY.md](SECURITY.md)**.

**Never** open a public issue for security vulnerabilities — use [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories).

## License

**GNU Affero General Public License v3.0** — see [LICENSE](LICENSE).

You can use, modify, and distribute Accord, but any modifications to the server must also be open-source under AGPL v3.

---

<div align="center">

**Built with ❤️ for privacy-conscious communities** · [accord.chat](https://accord.chat)

</div>
