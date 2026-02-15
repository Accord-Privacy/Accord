# Accord

**Privacy-first community communication platform — Discord's features with Signal's security.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## What Is Accord?

Accord fills the gap between Discord (great features, no privacy) and Signal (great privacy, no community features). It's an open-source, end-to-end encrypted platform where the server **never** has access to your messages, voice, or files.

**Key Principles:**
- **Zero-knowledge server** — routes encrypted blobs, never decrypts
- **End-to-end encryption** — AES-256-GCM, X25519 key agreement, forward secrecy
- **Discord-like UX** — servers, channels, voice chat, bots, rich messaging
- **Self-hostable** — run your own server, own your data
- **Open source** — fully auditable, AGPL-3.0

## Architecture

```
[Client Apps] <--E2E Encrypted--> [Relay Server] <--E2E Encrypted--> [Client Apps]
     ^                                  ^                                  ^
  Full Crypto                     Routing Only                       Full Crypto
  All Features                  No Decryption Keys                  All Features
```

### Terminology
- **Relay Server** — the actual server process/machine. Can host multiple Nodes.
- **Node** — a community space that users join and communicate in (like a Discord "server"). Each Node has its own channels, members, roles, and invites.
- **Channel** — a text or voice channel within a Node.

One relay server instance can host many Nodes, making self-hosting efficient for communities that want to share infrastructure.

### Workspace Structure

| Crate | Purpose |
|-------|---------|
| `core/` | Cryptography, channels, bots, invites, voice, protocol |
| `server/` | WebSocket relay server (zero-knowledge) |
| `desktop/` | Tauri desktop app (Rust + TypeScript) |
| `accord-cli/` | CLI client |
| `core-minimal/` | Lightweight demo of core concepts |
| `standalone-demo/` | Zero-dependency proof of concept |

### Security Stack

- **Text encryption:** X25519 key agreement → AES-256-GCM with per-message forward secrecy
- **Voice encryption:** AES-256-GCM per packet, key rotation every 30s / 10k packets
- **Bot privacy:** Command-only visibility — bots never see regular messages
- **Invites:** Direct invite only, no public discovery, expiration + quality gates

## Building

**Requirements:** Rust 1.86+, build-essential, pkg-config, libssl-dev

```bash
# Core + server (no desktop GUI deps needed)
cargo check -p accord-core -p accord-server -p accord-cli

# Desktop (additional deps: libgtk-3-dev, libwebkit2gtk-4.1-dev, libsoup-2.4-dev)
cargo check -p accord-desktop

# Run tests
cargo test

# Build release
cargo build --release
```

## Current Status

**Core architecture complete.** Cryptography, channel system, bot framework, invite system, voice system, and network protocol are implemented. Currently fixing compilation issues and building out the server implementation.

See [ROADMAP.md](ROADMAP.md) for development plan and technical specifications.

## Security

**Reporting vulnerabilities:** Do NOT create public issues. Email the maintainers directly with:
- Vulnerability description and severity
- Steps to reproduce
- Suggested fix if applicable

Response within 48 hours. Fix timeline based on severity (critical: 24-48h, high: 1 week, medium: 2-4 weeks).

## License

AGPL-3.0 — see [LICENSE](LICENSE) for details.
