<div align="center">

# 🔒 Accord

**Privacy-first community communications platform**

*Discord's features with Signal's security*

[![CI](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml)
[![Windows Build](https://github.com/Accord-Privacy/Accord/actions/workflows/windows-build.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/windows-build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust 1.86+](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)

[Website](https://accord.chat) · [Quick Start](#quick-start) · [Self-Hosting](docs/SELF-HOSTING.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Security Audit](SECURITY-AUDIT.md) · [Roadmap](ROADMAP.md)

</div>

---

## What is Accord?

Accord fills the gap between **Discord** (great features, no privacy) and **Signal** (great privacy, no community features). It's an open-source, end-to-end encrypted platform where the relay server **never** has access to your messages, voice, or files.

> **The relay admin is just a landlord — they provide the building but can't enter your apartment.**

## ✨ Features

### 🔐 End-to-End Encryption
- **Double Ratchet + X3DH** for DMs (Signal protocol foundations)
- **AES-256-GCM** channel encryption for all group messages and files (Sender Keys upgrade planned)
- **Forward secrecy** — keys rotate per message
- **SRTP voice encryption** with periodic key rotation
- **Encrypted file sharing** — relay stores only opaque blobs
- **Client-side encrypted search** — messages are decrypted locally before indexing

### 🎙️ Voice Channels
- **WebRTC** with relay-routed default for NAT traversal
- **P2P mesh** for small groups (≤4), relay fallback for larger ones
- SRTP encryption on all voice traffic
- Mute/deafen controls, speaking indicators, Opus codec
- Jitter buffer for smooth audio

### 🏘️ Nodes (Community Spaces)
- Discord-style UI: categories, channels, roles with colors
- **50+ permission bits** with category → channel cascade
- **Invite links** with configurable max uses and expiration
- **Discord template import** — paste a discord.new link to scaffold your Node
- **Channel drag-and-drop reordering** (and role reordering)
- Node icons, user avatars

### 💬 Messaging
- **Message reactions** (add/remove with real-time broadcast)
- **Message pinning** and unpinning
- **Threads / replies** — reply to specific messages with thread view
- **Rich link previews** — Open Graph metadata fetched server-side
- **Custom emoji** — upload, list, and manage per-Node emoji
- **User blocking** — blocks enforced server-side on DMs

### 🤖 Bot API v2
- **Airgapped command model** — bots respond to commands without persistent connections
- **E2EE bot tokens** (HKDF-derived v2 tokens)
- **Slash commands** with scoped permissions
- **Rich embeds** and interactive embedded elements
- **Webhook support** for external integrations
- **Bot SDK** (`bot-sdk/`) with examples

### 🪪 Identity & Profiles
- **Keypair-only registration** — no email, no phone, no PII
- **BIP39 mnemonic** — your identity is a 12-word seed phrase
- **Per-Node encrypted profiles** — different display name/avatar per Node
- **Custom status** per user
- **Export/import** for full account backup
- **QR code sync** between devices

### 🛡️ Server Security
- **TLS with auto-generated certs** — self-signed TLS by default, bring your own cert supported
- **CORS configuration** — configurable allowed origins
- **Batch API endpoints** — efficient member and channel queries
- **Admin dashboard** — token-gated stats, user management, and server overview
- **Rate limiting** and input validation
- **Auto-mod** with configurable word filters

### 📦 More
- **Themes** and customizable UI
- **Build hash verification** — clients display trust indicators
- **Reproducible builds** — verify you're running unmodified code
- **Audit logging** for administrative actions
- **Push notifications** — FCM, UnifiedPush, and APNs with encrypted payloads
- **Landing page** at [accord.chat](https://accord.chat) ([`website/`](website/))

---

## Architecture

```
┌─────────┐                                   ┌─────────┐
│ Desktop  │◄──E2E──┐                   ┌─E2E──►│ Desktop  │
│  (Tauri) │        │  ┌──────────────┐ │      │  (Tauri) │
├──────────┤        ├──►│ Relay Server │◄┤      ├──────────┤
│  iOS /   │        │  │(Zero-Knowledge)││      │  iOS /   │
│ Android  │◄──E2E──┘  └──────────────┘ └─E2E──►│ Android  │
└──────────┘                                    └──────────┘
```

**Relay** — routes encrypted blobs. Has no decryption keys. Handles auth, presence, and channel metadata.

**Node** — a community space (like a Discord server). All content is E2E encrypted; the relay sees only opaque ciphertext.

**Desktop** — Tauri app (Rust backend + React/TypeScript UI). All crypto keys stay local.

**Mobile** — Native iOS (SwiftUI) and Android (Jetpack Compose) apps with full E2EE via FFI/JNI to the Rust `core` crate.

### Workspace Crates

| Crate | Purpose |
|---|---|
| [`core/`](core/) | Cryptography, protocol, channels, voice, bots, invites |
| [`server/`](server/) | WebSocket relay server (zero-knowledge routing) |
| [`desktop/`](desktop/) | Tauri desktop app (Rust + React/TypeScript) |
| [`bot-sdk/`](bot-sdk/) | Bot SDK with examples (echo bot, moderation bot) |
| [`accord-cli/`](accord-cli/) | Command-line client |
| [`mobile/ios/`](mobile/ios/) | iOS app (SwiftUI + Rust FFI) |
| [`mobile/android/`](mobile/android/) | Android app (Jetpack Compose + Rust JNI) |
| [`core-minimal/`](core-minimal/) | Lightweight core for resource-constrained targets |
| [`standalone-demo/`](standalone-demo/) | Self-contained demo |

---

## Security Model

Accord's security is built on a zero-knowledge architecture:

1. **Registration requires only a keypair** — no PII ever touches the relay
2. **All messages and files are E2E encrypted** before leaving the client
3. **DMs use the Double Ratchet** (X3DH key agreement, per-message forward secrecy)
4. **Channel messages use AES-256-GCM** with shared channel keys
5. **Voice uses SRTP** with periodic key rotation
6. **The relay stores only encrypted blobs** — it cannot read messages, files, or voice
7. **Per-Node profiles** ensure the relay can't correlate your identity across communities
8. **Push notification payloads are encrypted** with 3 privacy levels (full, sender-only, minimal)

For full details, see **[SECURITY.md](SECURITY.md)**, **[SECURITY-AUDIT.md](SECURITY-AUDIT.md)**, and **[docs/metadata-privacy.md](docs/metadata-privacy.md)**.

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

The server starts with auto-generated TLS by default. Use `--no-tls` for development or `--tls-cert`/`--tls-key` to provide your own certificates.

---

## Self-Hosting

Accord is designed to be self-hosted. A **$5/month VPS** or a spare machine on your LAN is all you need.

1. Build `accord-server` (see above) or use Docker (`docker-compose.yml` included)
2. Open port **8080** (WebSocket)
3. Point clients at your relay's address

The relay is lightweight — it never decrypts anything, so resource usage stays low.

📖 **[Full self-hosting guide →](docs/SELF-HOSTING.md)**

### 🌐 Web Client

Accord works directly in the browser — no desktop app required. Serve the frontend from your relay:

```bash
# Build the frontend
cd desktop/frontend && npm install && npx vite build

# Run server with web client
./accord-server --port 8443 --frontend desktop/frontend/dist
```

Visit your relay URL in any browser. The web client works as a **standalone application** — no desktop app or installation required. It auto-detects the relay, handles identity creation, and provides the full encrypted messaging experience including voice channels. All E2EE operations happen client-side — your keys never leave the browser.

---

## Mobile Apps

Native mobile apps for **iOS** and **Android** are under active development:

- **iOS** — SwiftUI app with Rust FFI for E2EE (`mobile/ios/`)
- **Android** — Jetpack Compose app with Rust JNI for E2EE (`mobile/android/`)

Both apps have full networking (WebSocket + REST), E2EE (channel encryption + Double Ratchet DMs), WebRTC voice, and push notification support implemented. They are functional but not yet production-released.

See **[MOBILE.md](MOBILE.md)** for build instructions and current status.

---

## Comparison

| | Accord | Discord | Signal | Matrix | Fluxer |
|---|:---:|:---:|:---:|:---:|:---:|
| E2E encryption | ✅ | ❌ | ✅ | ✅ | ❌ |
| Community features | ✅ | ✅ | ❌ | ✅ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ | ✅ |
| Zero-knowledge server | ✅ | ❌ | ✅ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| No PII required | ✅ | ❌ | ❌ | ❌ | ❌ |
| No paywalled features | ✅ | ❌ | ✅ | ✅ | ⚠️¹ |
| Open source | ✅ | ❌ | ✅ | ✅ | ✅ |

> ¹ Fluxer is fully open source — all features are available when self-hosted. Paywalling only applies to their official hosted servers.

---

## Documentation

- **[Architecture](docs/architecture.md)** — system design deep-dive
- **[Permission System](docs/permission-system.md)** — roles, bits, cascade model
- **[Identity Model](docs/identity-model.md)** — keypair identity & BIP39
- **[Metadata Privacy](docs/metadata-privacy.md)** — what's visible vs encrypted
- **[Bot API](docs/bot-api.md)** — building integrations
- **[Self-Hosting](docs/SELF-HOSTING.md)** — deployment guide
- **[Reproducible Builds](REPRODUCIBLE-BUILDS.md)** — build verification
- **[Security Audit](SECURITY-AUDIT.md)** — latest audit findings and status

---

## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions, coding standards, and PR guidelines.

## Security

For security design details and vulnerability reporting, see **[SECURITY.md](SECURITY.md)**. For the latest audit results, see **[SECURITY-AUDIT.md](SECURITY-AUDIT.md)**.

**Never** open a public issue for security vulnerabilities — use [GitHub Security Advisories](https://github.com/Accord-Privacy/Accord/security/advisories).

## Funding & Philosophy

Accord is **donationware**. Every feature is available to every user — there are no premium tiers, no paywalled functionality, and no plans for monetization. We believe privacy tools should be accessible to everyone, not just those who can afford a subscription.

Development is sustained entirely by community donations. If Accord is useful to you, consider supporting the project:

- **[Donate →](https://accord.chat/donate)** *(coming soon)*

This is a deliberate choice: the moment a privacy tool has paying customers, incentives shift from protecting users to retaining subscribers. We'd rather build something good and let people support it voluntarily.

## Acknowledgments

Accord is built on the shoulders of great open-source projects. We'd like to credit:

- **[Fluxer](https://github.com/fluxerapp/fluxer)** — UI/UX design patterns and CSS architecture inspiration. Fluxer's component design system and visual polish influenced our frontend approach. Check out their project if you're looking for a feature-rich chat platform without the encryption focus.
- **[Signal](https://signal.org)** — Cryptographic protocol foundations (Double Ratchet, X3DH).
- **[Matrix](https://matrix.org)** — Federated architecture concepts.

## License

**GNU Affero General Public License v3.0** — see [LICENSE](LICENSE).

You can use, modify, and distribute Accord, but any modifications to the server must also be open-source under AGPL v3.

---

<div align="center">

**Built with ❤️ for privacy-conscious communities** · [accord.chat](https://accord.chat)

</div>
