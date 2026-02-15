# Accord Roadmap

## Current Status (Feb 2026)

### ✅ Phase 1: Foundation — COMPLETE
- [x] All 6 Rust crates compiling (core, core-minimal, server, desktop, cli, standalone-demo)
- [x] All unit + integration tests passing (20 unit, 11 integration, 5 DB)
- [x] Server: WebSocket relay (registration, auth, message routing, channels)
- [x] Server: SQLite persistence (users, channels, messages, nodes, node_members, files)
- [x] Multi-tenant Node architecture (CRUD, membership, roles: admin/mod/member)
- [x] Node creation policies (admin_only/open/approval/invite)
- [x] Server admin ≠ Node admin separation (zero-knowledge design)
- [x] CLI client (register, login, Node CRUD, interactive WebSocket chat)
- [x] E2E smoke test (server → registration → auth → Node creation)
- [x] Encrypted file sharing (upload/download/list/delete, zero-knowledge filenames)
- [x] Node invite links (8-char codes, expiration, usage limits, approval workflow)
- [x] Voice channel server-side support (join/leave/relay/speaking state)
- [x] React/TypeScript desktop frontend scaffold (Discord-like dark theme, 3-column layout)
- [x] Frontend connected to server (API client, WebSocket, auth flow)
- [x] Tauri 2.x desktop shell (Ubuntu 24.04 compatible)
- [x] CI/CD pipeline, Docker support
- [x] Core crypto: X25519 key agreement, AES-256-GCM, forward secrecy

### 🔧 Phase 2: Integration & Polish — IN PROGRESS
- [ ] Wire E2E encryption into client message flow (crypto exists but not connected)
- [ ] Frontend: real Node/channel navigation with live server data
- [ ] Frontend: file upload/download UI
- [ ] Frontend: user profiles and presence indicators
- [ ] Permissions system enforcement in frontend
- [ ] Message history loading and scroll-back
- [ ] Docker deployment guide for self-hosting

### 📋 Phase 3: Voice & Real-Time (Next)
- [ ] Client-side audio capture (browser/Tauri)
- [ ] Opus codec integration
- [ ] Real-time voice UI (mute, deafen, speaking indicators)
- [ ] P2P voice for small groups (≤4)
- [ ] Server-relayed voice for larger groups
- [ ] Jitter buffer and packet loss handling

### 📋 Phase 4: Hardening
- [ ] Security audit (internal, then third-party)
- [ ] Penetration testing
- [ ] Reproducible builds
- [ ] Self-hosting documentation
- [ ] Performance benchmarking (10k+ concurrent users target)

### 📋 Phase 5: Mobile
- [ ] iOS app (Swift + Rust FFI)
- [ ] Android app (Kotlin + Rust JNI)
- [ ] Push notifications with encryption preservation
- [ ] Background voice support

### 📋 Phase 6: Public Release
- [ ] Beta program
- [ ] Community feedback integration
- [ ] Federation protocol (multi-server communication)
- [ ] Bot API documentation for third-party developers

## Technical Specifications

### Cryptographic Protocol
| Component | Algorithm | Details |
|-----------|-----------|---------|
| Key agreement | X25519 ECDH | Per-session between clients |
| Message encryption | AES-256-GCM | Unique nonce per message |
| Forward secrecy | Double ratchet | Keys rotate per message |
| Voice encryption | AES-256-GCM | Per-packet, rekey every 30s |
| Identity keys | Ed25519 | Long-term identity verification |
| Key derivation | HKDF-SHA256 | For deriving session keys |

### Performance Targets
| Metric | Target |
|--------|--------|
| Voice latency | <150ms end-to-end |
| Voice quality | Opus 48kHz, 64kbps |
| Concurrent users | 10,000+ per server |
| Message throughput | 1,000+ msg/sec |
| Max file size | 100MB (chunked, encrypted) |
| CPU (voice) | <10% on modern hardware |

### Differentiators
| | Accord | Discord | Signal | Matrix |
|---|---|---|---|---|
| E2E encryption | ✅ | ❌ | ✅ | ✅ |
| Community features | ✅ | ✅ | ❌ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ |
| Zero-knowledge server | ✅ | ❌ | ✅ | ❌ |
| Privacy-preserving bots | ✅ | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ |
| Open source | ✅ | ❌ | ✅ | ✅ |

## Architecture

### Node Model
- **Nodes** = community spaces (like Discord servers, but E2E encrypted)
- **Relay server** = invisible infrastructure (users never interact with it directly)
- **Server admin ≠ Node admin** — "landlord can't enter apartments"
- **Node creation policies:** `admin_only | open | approval | invite`

### Trust Model
E2E encryption means even malicious relays can't read content. Remaining risks and mitigations:
- **Metadata** → minimize stored routing data, optional Tor support
- **Server fingerprinting** → Ed25519 identity key, TOFU + out-of-band verification
- **Traffic analysis** → padding, timing obfuscation (future)

### Server Discovery
- DNS SRV records (`_accord._tcp.example.com`)
- QR code / deep links with server fingerprint
- Optional federated server directory
- Word of mouth (primary, most secure)
