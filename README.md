# Accord

**Privacy-first community communications** — Discord's features with Signal's security

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/your-org/accord)

---

## 🚀 What is Accord?

Accord fills the gap between Discord (great features, no privacy) and Signal (great privacy, no community features). It's an open-source, end-to-end encrypted platform where the server **never** has access to your messages, voice, or files.

**Key Differentiators:**
- **Zero-knowledge server** — routes encrypted blobs, never decrypts
- **Discord-like UX** — Nodes (communities), channels, voice chat, bots, rich messaging
- **Signal-grade encryption** — X25519 + AES-256-GCM with forward secrecy
- **Self-hostable** — run your own server, own your data
- **Privacy-preserving bots** — bots see only commands, never regular messages

> **The server admin is just a landlord — they provide the building but can't enter your apartment.** Unlike Discord, where the company has god-mode access to everything, Accord's server admin has zero access to Node content.

---

## ✨ Features

### 🔒 **End-to-End Encryption**
- **X25519 key agreement** for secure key exchange
- **AES-256-GCM encryption** for all messages and files
- **Forward secrecy** — keys rotate per message
- **Voice encryption** — per-packet encryption with 30s key rotation

### 🏘️ **Nodes (Community Spaces)**
- Discord-like servers but fully encrypted
- Admin/moderator/member roles and permissions
- Invite-only or approval-based joining
- Multi-tenant architecture (one server, many communities)

### 🎙️ **Voice Channels**
- Real-time encrypted voice communication
- P2P for small groups, server-relayed for larger groups
- Mute/deafen controls, speaking indicators
- Opus codec for high-quality audio

### 📁 **Secure File Sharing**
- End-to-end encrypted file uploads (up to 100MB)
- Zero-knowledge filenames — server can't see file names
- Chunked uploads for reliability

### 🔧 **Self-Hostable**
- Run your own relay server
- Docker support for easy deployment
- No vendor lock-in — migrate your communities

### 🤖 **Privacy-Preserving Bots**
- Bots see only commands they're mentioned in
- Never access regular user messages
- Rich bot API while preserving privacy

---

## 🏗️ Architecture

```
[Client Apps] <--E2E Encrypted--> [Relay Server] <--E2E Encrypted--> [Client Apps]
     ^                                  ^                                  ^
  Full Crypto                     Routing Only                       Full Crypto
  All Features                  No Decryption Keys                  All Features
```

### Workspace Structure

This is a **Rust workspace** with multiple crates:

| Crate | Purpose |
|-------|---------|
| `core/` | Cryptography, channels, bots, invites, voice, protocol |
| `server/` | WebSocket relay server (zero-knowledge routing) |
| `desktop/` | Tauri desktop app (Rust + React/TypeScript) |
| `accord-cli/` | Command-line client |
| `core-minimal/` | Lightweight demo of core concepts |
| `standalone-demo/` | Zero-dependency proof of concept |

### Zero-Knowledge Relay Design

- **Server stores:** Encrypted blobs, routing metadata, user handles
- **Server never sees:** Message contents, file names, voice data
- **Relay server admin ≠ Node admin** — complete separation of privileges

---

## 🚀 Quick Start

### Building from Source

**Requirements:**
- Rust 1.86+
- build-essential, pkg-config, libssl-dev
- For desktop: libgtk-3-dev, libwebkit2gtk-4.1-dev, libsoup-2.4-dev

```bash
# Clone the repository
git clone https://github.com/your-org/accord
cd accord

# Build core components
cargo build --release -p accord-core -p accord-server -p accord-cli

# Build desktop app (requires GUI dependencies)
cargo build --release -p accord-desktop

# Run tests
cargo test
```

### Self-Hosting with Docker

For detailed self-hosting instructions, see **[docs/SELF-HOSTING.md](docs/SELF-HOSTING.md)**.

```bash
# Quick start with Docker Compose
docker-compose up -d

# The relay server will be available at localhost:8080
# Configure clients to connect to your server
```

---

## 📸 Screenshots

*Coming soon! We're focusing on security and functionality first, polish second.*

---

## 📊 Comparison

| | Accord | Discord | Signal | Matrix |
|---|:---:|:---:|:---:|:---:|
| **E2E encryption** | ✅ | ❌ | ✅ | ✅ |
| **Community features** | ✅ | ✅ | ❌ | ✅ |
| **Voice channels** | ✅ | ✅ | ❌ | ⚠️ |
| **Zero-knowledge server** | ✅ | ❌ | ✅ | ❌ |
| **Privacy-preserving bots** | ✅ | ❌ | ❌ | ❌ |
| **Self-hostable** | ✅ | ❌ | ⚠️ | ✅ |
| **Open source** | ✅ | ❌ | ✅ | ✅ |

**Why not just use...?**
- **Discord:** No encryption, no privacy, corporate control
- **Signal:** Great for 1:1 and small groups, but no community features
- **Matrix:** Complex protocol, servers can see metadata, no voice channels
- **Accord:** The best of all worlds — Discord UX + Signal privacy

---

## 🤝 Contributing

We welcome contributions! Please see **[CONTRIBUTING.md](CONTRIBUTING.md)** for development guidelines.

**Get Involved:**
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Community Q&A and feature brainstorming

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE) for details.

**TLDR:** You can use, modify, and distribute this software, but any modifications must also be open-source under GPL v3.

---

## 🔒 Security

**Current Status:** Core architecture complete, integration phase in progress. Not ready for production use.

**Reporting Vulnerabilities:** 
- **DO NOT** create public GitHub issues for security vulnerabilities
- Report security issues via **GitHub Security Advisories**
- Include: description, severity, reproduction steps, suggested fix
- For other inquiries, use GitHub Issues and Discussions

---

## 📈 Roadmap

**Phase 2 (Current):** Integration & polish — connecting E2E crypto to client flows
**Phase 3:** Voice & real-time features
**Phase 4:** Security audit and hardening
**Phase 5:** Mobile apps (iOS/Android)
**Phase 6:** Public beta

See **[ROADMAP.md](ROADMAP.md)** for detailed development timeline and technical specifications.

---

**Built with ❤️ for privacy-conscious communities**