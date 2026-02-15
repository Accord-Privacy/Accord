# Accord

**Privacy-first community communication platform with Discord-like features and Signal-level security.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange.svg)](https://www.rust-lang.org)
[![Security Audit](https://img.shields.io/badge/security%20audit-planned-yellow.svg)](#security)

Accord enables communities to communicate with end-to-end encryption, zero-knowledge servers, and self-hosting options while maintaining the organizational features essential for modern group collaboration.

## 🎯 **Why Accord?**

**The Problem:** Existing communication platforms force you to choose between community features and privacy. Discord has great organization but reads all your messages. Signal has perfect privacy but lacks community structure.

**The Solution:** Accord provides Discord-like servers and channels with Signal-level encryption. Zero-knowledge servers mean even we can't read your messages, while community features keep groups organized.

### **Key Features**

- 🔐 **End-to-end encryption** for all messages, voice, and files
- 🏠 **Self-hosting support** - run your own server with full control  
- 🌐 **Hosted service option** - we run servers but can't decrypt your data
- 📱 **Cross-platform** - Desktop (Windows, macOS, Linux) and Mobile (iOS, Android)
- 🎪 **Community organization** - Servers, channels, roles, and permissions
- 🎤 **Encrypted voice chat** - Real-time voice with <150ms latency
- 🤖 **Privacy-preserving bots** - Command-only bots that can't read messages
- 📂 **Secure file sharing** - Encrypted file uploads and sharing
- 🔄 **Federation ready** - Connect multiple Accord servers together

### **Privacy Guarantees**

- **Zero-knowledge servers** - mathematically impossible for us to read your messages
- **Forward secrecy** - compromising devices doesn't expose message history  
- **Minimal metadata** - we collect only what's needed for message routing
- **Local message storage** - your messages stay on your devices
- **Open source** - fully auditable code with no hidden backdoors

## 🚀 **Quick Start**

### **For Users**

*Desktop and mobile applications coming soon. Follow development progress in [ROADMAP.md](ROADMAP.md).*

### **For Self-Hosting**

```bash
# Clone the repository
git clone https://github.com/[USERNAME]/accord.git
cd accord

# Start with Docker Compose
docker-compose up -d

# Your Accord server is now running on https://localhost:8443
```

*Full self-hosting guide: [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md)*

### **For Developers**

```bash
# Prerequisites: Rust 1.86+, Node.js 18+
git clone https://github.com/[USERNAME]/accord.git
cd accord

# Install dependencies and build
cargo build
cd desktop && npm install && npm run tauri build

# Run development server
cargo run --bin accord-server
```

*Development guide: [CONTRIBUTING.md](CONTRIBUTING.md)*

## 📋 **Project Status**

**Current Phase:** Foundation Development (Phase 1 of 5)

- ✅ **Cryptographic Architecture** - E2E encryption and forward secrecy
- ✅ **Channel System** - Server/channel organization with access control
- ✅ **Invite System** - Direct invites with expiration and approval
- 🔧 **WebSocket Server** - Real-time message relay (in progress)
- 🔧 **Desktop Application** - Tauri-based cross-platform app (in progress)
- ⏳ **User Authentication** - Privacy-preserving registration (planned)

**Next Milestones:**
- **Month 2:** Working desktop app with encrypted messaging
- **Month 4:** Voice channels and file sharing
- **Month 6:** Mobile applications development
- **Month 9:** Mobile apps in app stores
- **Month 12:** Federation and advanced privacy features

See [ROADMAP.md](ROADMAP.md) for complete development timeline.

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Desktop App   │    │   Mobile App    │    │   Web Client    │
│   (Tauri)       │    │  (Native)       │    │   (Limited)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │     Accord Server         │
                    │                           │
                    │  ┌─────────────────────┐  │
                    │  │   Message Router    │  │ ← Zero-knowledge
                    │  │   (WebSocket)       │  │   message relay
                    │  └─────────────────────┘  │
                    │                           │
                    │  ┌─────────────────────┐  │
                    │  │   Voice Router      │  │ ← Encrypted
                    │  │   (WebRTC)          │  │   voice packets
                    │  └─────────────────────┘  │
                    │                           │
                    │  ┌─────────────────────┐  │
                    │  │   File Storage      │  │ ← Encrypted
                    │  │   (S3-Compatible)   │  │   file storage
                    │  └─────────────────────┘  │
                    └───────────────────────────┘
```

**Key Design Principles:**
- **Client-side encryption** - All encryption happens on user devices
- **Zero-knowledge servers** - Servers only route encrypted data
- **Decentralized identity** - Users control their own cryptographic keys
- **Federation-ready** - Designed for server-to-server communication

## 🔒 **Security**

Security is our highest priority. Accord implements multiple layers of protection:

### **Cryptographic Security**
- **Signal Protocol** - Double Ratchet with forward secrecy
- **X25519** key agreement for initial key exchange
- **AES-256-GCM** for message encryption
- **Ed25519** signatures for message authentication
- **HKDF** key derivation with proper salt handling

### **Network Security**
- **TLS 1.3** for all network connections
- **Certificate pinning** to prevent MITM attacks
- **Onion routing support** for metadata protection
- **DoH/DoT DNS** to prevent DNS surveillance

### **Operational Security**
- **Reproducible builds** - Verify binaries match published source
- **Automatic updates** with cryptographic signature verification
- **Secure key storage** using platform-specific secure enclaves
- **Memory protection** - Sensitive data cleared after use

### **Planned Security Audits**
- **Q2 2026:** Internal cryptographic review
- **Q3 2026:** Third-party security audit by reputable firm
- **Q4 2026:** Public penetration testing and bug bounty program

## 📚 **Documentation**

- **[PROJECT-CHARTER.md](PROJECT-CHARTER.md)** - Mission, philosophy, and goals
- **[ROADMAP.md](ROADMAP.md)** - Development timeline and milestones  
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - How to contribute to the project
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture details
- **[docs/](docs/)** - User guides, API documentation, and tutorials

## 🤝 **Contributing**

Accord is open source and welcomes contributions! We're especially looking for:

- **Rust developers** - Backend services and cryptography
- **Frontend developers** - Desktop (Tauri + React) and mobile apps
- **Security experts** - Cryptographic review and security testing
- **UX designers** - Privacy-focused user experience design
- **Documentation writers** - User guides and developer documentation

Before contributing, please read our [CONTRIBUTING.md](CONTRIBUTING.md) guide and [Code of Conduct](CODE_OF_CONDUCT.md).

## 💬 **Community**

- **GitHub Discussions** - Feature requests and general discussion
- **Matrix** - Real-time chat for developers (coming soon)
- **Security Issues** - security@accord.chat for responsible disclosure

## 📜 **License**

Accord is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 

This ensures that:
- ✅ You can use, modify, and distribute Accord freely
- ✅ Self-hosted deployments are completely unrestricted
- ✅ You can create commercial services using Accord
- ⚠️ Any modifications must be open-sourced under AGPL-3.0
- ⚠️ Network services using Accord must provide source code to users

For more details, see [LICENSE](LICENSE).

## ⭐ **Why AGPL?**

We chose AGPL-3.0 to ensure Accord remains open and auditable:

1. **Prevents proprietary forks** that could introduce backdoors
2. **Ensures hosted services** provide source code to users
3. **Maintains user freedom** to audit and modify the software
4. **Encourages community development** rather than proprietary extensions

This license protects user privacy by ensuring all Accord deployments remain transparent and auditable.

---

**Built with ❤️ for digital privacy and community collaboration.**

*Accord is in active development. Star the repository to follow our progress!*