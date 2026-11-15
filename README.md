<div align="center">

# 🔒 Accord

**Privacy-first community communications platform**

*Discord's features with Signal's security*

[![CI](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/ci.yml)
[![Windows Build](https://github.com/Accord-Privacy/Accord/actions/workflows/windows-build.yml/badge.svg)](https://github.com/Accord-Privacy/Accord/actions/workflows/windows-build.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust 1.86+](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org/)

[Releases](https://github.com/Accord-Privacy/Accord/releases) · [Quick Start](#quick-start) · [Self-Hosting](docs/SELF-HOSTING.md) · [Governance](GOVERNANCE.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Security Audit](SECURITY-AUDIT.md) · [Roadmap](ROADMAP.md)

</div>

---

## What is Accord?

Accord fills the gap between **Discord** (great features, no privacy) and **Signal** (great privacy, no community features). It's an open-source platform built on end-to-end encryption, designed so that the relay server can't read what you send.

**It does not fully meet that goal yet.** Relay-mode voice is readable by the relay operator, a malicious relay can intercept encrypted sessions when they are set up (and then read and forge the messages and attachments sent over them), and files uploaded before end-to-end-encrypted attachments shipped stay readable by the relay until they are retired. See [Current security limitations](#current-security-limitations).

> **The relay admin is just a landlord — they provide the building but can't enter your apartment.**

## ✨ Features

### 🔐 End-to-End Encryption
- **Double Ratchet + X3DH** for DMs (Signal protocol foundations)
- **Sender Keys** for channel group messaging — the relay stores only opaque `{v,sk,iv,ct}` envelopes it cannot read
- **AES-256-GCM** for channel content
- **Forward secrecy** — keys rotate per message
- **NMK metadata privacy** — channel/category names and per-node policies are encrypted under a Node Metadata Key the relay never sees (node names and descriptions are visible to the relay by design)
- **Client-side encrypted search** — messages are decrypted locally before indexing
- **End-to-end encrypted attachments** (desktop and web) — every file gets its own random key, which travels only inside the encrypted message that carries the file; the relay stores a nameless, padded blob and deletes it with its message. The relay still sees attachment metadata such as padded sizes — see [Current security limitations](#current-security-limitations)
- **Not yet end-to-end encrypted:** voice — see [Current security limitations](#current-security-limitations)

### 🎙️ Voice Channels
- **Relay mode** (the default) — audio goes through the relay, encrypted with AES-256-GCM, but the keys go through the relay too, so **relay-mode voice is readable by the relay operator**
- **P2P mode** — browser WebRTC connections directly between participants; **P2P voice and P2P screen sharing reveal your IP address to other participants and can be intercepted by the relay**. They also contact public STUN servers run by Google, which learn your IP address; starting a screen share does this even in relay mode
- The mode is set per channel and other users can change it, so joining any voice channel can expose your IP address
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

### 🕵️ Privacy & Anti-Coercion
- **Disappearing messages** — per-node default + per-channel override; enabling wipes older messages retroactively. The relay sees only an opaque `expires_at`; the policy itself rides the NMK-encrypted blob
- **Read-gated messages** — a message won't start its disappear timer until the intended readers have actually seen it; each reader's own copy vanishes after they read it
- **Screenshot protection** — asks the OS to exclude the window from capture (reliable on Windows/macOS, best-effort on Linux)
- **Panic wipe** — one action destroys all local identity, keys, and data
- **Duress password** — a decoy password wipes the real account and opens an empty offline decoy, leaving no forensic trace of a second account

### 🛡️ Node Moderation (owner-run)
- **Roles & permissions**, **bans**, **slow mode** — operated by node owners/moderators
- **Word filters** — a node-wide blocklist enforced **client-side** and distributed inside the NMK-encrypted node settings; the relay never sees it
- **Node-scoped audit log** — visible to the node owner, not the relay

> Moderation is the node owner's responsibility. Accord performs **no** central or relay-side moderation — see **[GOVERNANCE.md](GOVERNANCE.md)**.

### 🖥️ Relay Operation
- **TLS with auto-generated certs** — self-signed TLS by default, bring your own cert supported
- **CORS configuration** — configurable allowed origins
- **Batch API endpoints** — efficient member and channel queries
- **Localhost admin dashboard** — bound to `127.0.0.1` (localhost access *is* the relay owner, no login); shows aggregate stats, a node registry (names/descriptions only), and live logs
- **Rate limiting** and input validation
- **Build-hash allowlist** — relay owners can pin which client builds may connect

### 📦 More
- **Themes** and customizable UI
- **Build hash verification** — clients display trust indicators
- **Reproducible builds** — verify you're running unmodified code
- **Push notifications** — FCM, UnifiedPush, and APNs with encrypted payloads
- **Landing page** source in [`website/`](website/)

---

## Screenshots

> 📸 *Screenshots coming soon — want to help? See [CONTRIBUTING.md](CONTRIBUTING.md).*

<!--
<div align="center">
  <img src="docs/design/screenshot-desktop.png" alt="Desktop client" width="720">
  <img src="docs/design/screenshot-mobile.png" alt="Mobile client" width="280">
</div>
-->

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

**Relay** — routes encrypted blobs. It is not meant to hold decryption keys, but today it can decrypt relay-mode voice and files uploaded before end-to-end-encrypted attachments shipped (see [Current security limitations](#current-security-limitations)). Handles auth and presence; channel metadata is encrypted under a Node Metadata Key it never sees (node names and descriptions are visible to it by design). It does not show node membership to the relay owner — see [GOVERNANCE.md](GOVERNANCE.md).

**Node** — a community space (like a Discord server). Messages, attachments and channel metadata are E2E encrypted (node names and descriptions are visible to the relay by design); voice is not yet (see [Current security limitations](#current-security-limitations)).

**Desktop** — Tauri app (Rust backend + React/TypeScript UI). Identity private keys stay local.

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
2. **Messages and attachments are E2E encrypted** before leaving the client. Each file is encrypted with its own random key, carried inside the encrypted message; the relay still sees attachment metadata (see below)
3. **DMs use the Double Ratchet** (X3DH key agreement, per-message forward secrecy)
4. **Channel messages use AES-256-GCM** with shared channel keys
5. **Voice is not E2E encrypted** — see below
6. **The relay stores encrypted blobs** — it is designed not to read messages or attachments, but today it can read relay-mode voice and files uploaded before end-to-end-encrypted attachments shipped (see below)
7. **Per-Node profiles** ensure the relay can't correlate your identity across communities
8. **Push notification payloads are encrypted** with 3 privacy levels (full, sender-only, minimal)

### Current security limitations

The current release falls short of this design in these ways:

- **Attachments are end-to-end encrypted, but only as authentic as their message, and their metadata is visible.** Desktop and web clients encrypt every file with a new random key and send the key, the file name and the file type only inside the end-to-end-encrypted message. The relay still sees that a message has attachments, how many, each file's padded size, who uploaded it and when, in which channel and with which message, and who downloads it, when and from which IP address; it does not see file names, types, contents, keys or exact sizes. Attachments are exactly as private and as authentic as the message that carries them: until identity verification and key-recipient checks ship, a relay that injects its own sender key into a channel, or intercepts a Double Ratchet session (below), can read and forge attachments attributed to the member it impersonates. The relay's deletion and expiry signals are not authenticated, so a malicious relay can make your device delete a message together with its attachment keys; for a DM that can be the device's only copy of a file's key.
- **Files uploaded before end-to-end-encrypted attachments shipped are not end-to-end encrypted.** They were encrypted under a key derived from the channel ID, which the relay knows, so the relay operator, or anyone with the relay's database, file storage or a backup, can decrypt and replace them and their names. The relay keeps them read-only and deletes them after a retirement window (90 days by default); clients show them only in an opt-in, badged "Legacy uploads" section.
- **Voice is not end-to-end encrypted.** Relay-mode voice (the default) is readable by the relay operator, because each participant's key is sent through the relay in a form the relay can read. P2P voice and P2P screen sharing reveal your IP address to other participants and can be intercepted by the relay.
- **A malicious relay can intercept encrypted sessions when they are set up.** Until identity verification ships, nothing checks that a contact's keys really belong to that contact, so a malicious relay can substitute its own keys when an end-to-end-encrypted (Double Ratchet) session is set up.

[SECURITY.md](SECURITY.md#known-limitations) describes these limits in detail.

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
4. Behind a reverse proxy, raise its request body limit above the relay's attachment limit (100 MiB by default; nginx: `client_max_body_size 101m`), or larger attachment uploads fail with 413 — see [Request body size for attachments](docs/SELF-HOSTING.md#request-body-size-for-attachments)

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

Visit your relay URL in any browser. The web client works as a **standalone application** — no desktop app or installation required. It auto-detects the relay, handles identity creation, and provides the full encrypted messaging experience including voice channels. All E2EE operations happen client-side and your private keys never leave the browser. Attachments are end-to-end encrypted with the limits listed under [Current security limitations](#current-security-limitations); voice is not end-to-end encrypted. A relay that serves the web client also serves its code, so it can change what the web client does.

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
| E2E encryption | ⚠️² | ❌ | ✅ | ✅ | ❌ |
| Community features | ✅ | ✅ | ❌ | ✅ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ | ✅ |
| Zero-knowledge server | ⚠️² | ❌ | ✅ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ | ✅ |
| No PII required | ✅ | ❌ | ❌ | ❌ | ❌ |
| No paywalled features | ✅ | ❌ | ✅ | ✅ | ⚠️¹ |
| Open source | ✅ | ❌ | ✅ | ✅ | ✅ |

> ¹ Fluxer is fully open source — all features are available when self-hosted. Paywalling only applies to their official hosted servers.
>
> ² Messages and attachments (desktop and web). Voice is not end-to-end encrypted yet, the relay sees attachment metadata such as padded sizes, and a malicious relay can intercept encrypted sessions when they are set up — see [Current security limitations](#current-security-limitations).

---

## Documentation

- **[Governance](GOVERNANCE.md)** — moderation philosophy, relay-owner vs node-owner powers
- **[Architecture](docs/architecture.md)** — system design deep-dive
- **[Permission System](docs/permission-system.md)** — roles, bits, cascade model
- **[Identity Model](docs/identity-model.md)** — keypair identity & BIP39
- **[Metadata Privacy](docs/metadata-privacy.md)** — what's visible vs encrypted
- **[Bot API](docs/bot-api-v2.md)** — building integrations
- **[Self-Hosting](docs/SELF-HOSTING.md)** — deployment guide
- **[Reproducible Builds](REPRODUCIBLE-BUILDS.md)** — build verification
- **[Security Audit](SECURITY-AUDIT.md)** — latest audit findings and status

---

## Contributing

We welcome contributions! See **[CONTRIBUTING.md](CONTRIBUTING.md)** for setup instructions, coding standards, and PR guidelines.

## Security

For security design details and vulnerability reporting, see **[SECURITY.md](SECURITY.md)**. For the latest audit results, see **[SECURITY-AUDIT.md](SECURITY-AUDIT.md)**.

**Never** open a public issue for security vulnerabilities — report them privately at <https://github.com/Accord-Privacy/Accord/security/advisories/new> (**Report a vulnerability** on the repository's Security tab).

## Funding & Philosophy

Accord is **donationware**. Every feature is available to every user — there are no premium tiers, no paywalled functionality, and no plans for monetization. We believe privacy tools should be accessible to everyone, not just those who can afford a subscription.

Development is meant to be sustained entirely by community donations. Donations are not open yet, and there is no official donation link.

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

**Built with ❤️ for privacy-conscious communities** · [github.com/Accord-Privacy/Accord](https://github.com/Accord-Privacy/Accord)

</div>
