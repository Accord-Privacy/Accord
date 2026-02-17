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

### ✅ Phase 2: Integration & Polish — COMPLETE
- [x] Wire E2E encryption into client message flow
- [x] Frontend: real Node/channel navigation with live server data
- [x] Frontend: file upload/download UI
- [x] Frontend: user profiles and presence indicators
- [x] Permissions system enforcement in frontend
- [x] Message history loading and scroll-back
- [x] Docker deployment guide for self-hosting
- [x] Desktop UI: configurable server URL for cross-machine connectivity
- [x] Windows build pipeline (NSIS/MSI installers, GitHub Actions)
- [x] Startup scripts (Linux/Windows)

### ✅ Phase 3: Voice & Real-Time — COMPLETE (partial)
- [x] Client-side audio capture (browser/Tauri)
- [x] Opus codec integration
- [x] Real-time voice UI (mute, deafen, speaking indicators)
- [x] Server-relayed voice for groups
- [x] Voice packet encryption (placeholder, pending WebRTC/SRTP)
- [ ] P2P voice for small groups (≤4)
- [ ] Jitter buffer and packet loss handling

### ✅ Phase 2.5: Security Audit & Hardening — COMPLETE (Feb 17, 2026)
Full codebase audit: 7 CRITICAL, 16 HIGH, 26 MEDIUM, 24 LOW findings across Rust, frontend, and infra.

**CRITICAL fixes applied:**
- [x] Argon2 password hashing (registration + login)
- [x] Proper token validation (no more hardcoded UUIDs)
- [x] Safe crypto (removed unsafe `array_ref!` macro, TryInto)
- [x] REST endpoints validate tokens server-side (no client-supplied user_id)
- [x] XSS prevention (DOMPurify sanitization)
- [x] Improved E2E key derivation (user-specific, not just channel ID)

**HIGH fixes applied:**
- [x] HKDF key derivation with separate session/chain keys
- [x] Key ratcheting for forward secrecy
- [x] Token cleanup (expired token removal)
- [x] Auth tokens via Authorization: Bearer header
- [x] CORS restricted to configurable allowlist
- [x] File path canonicalization (traversal prevention)
- [x] Voice key rotation
- [x] Secure token storage with expiry (frontend)
- [x] Private key encryption at rest (PBKDF2 + AES-GCM)
- [x] WebSocket auth handshake (token out of URL)
- [x] Password strength validation
- [x] Tightened Tauri CSP

**Remaining (MEDIUM/LOW):**
- [ ] Fix `get_channel_category` nil UUID bug (M7)
- [ ] Wire up rate limiting to endpoints (L9)
- [ ] Replace `println!` with structured logging in bots (L1)
- [ ] Fix `delete_channel` / `update_node` stubs (M10/M11)
- [ ] Add clippy + `cargo audit` to CI
- [ ] Fix duplicate `PROTOCOL_VERSION` constants (M3)
- [ ] Bounded bot interactions vector (M4)
- [ ] Division-by-zero guard in `calculate_energy` (M5)
- [ ] Grapheme-aware validation lengths (M6)
- [ ] `unwrap()` → `?` in DB row parsing (M9)
- [ ] Error boundary for React frontend
- [ ] Remove console.log spam from production builds

### 📋 Phase 4: Hardening (Next)
- [ ] Internal security audit pass on remaining MEDIUM/LOW items
- [ ] Penetration testing
- [ ] Reproducible builds
- [ ] Performance benchmarking (10k+ concurrent users target)
- [ ] Full Double Ratchet protocol (replace current simplified ratchet)
- [ ] WebRTC/SRTP for voice encryption

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
| Forward secrecy | HKDF ratchet | Chain key advances per message |
| Voice encryption | AES-256-GCM | Per-packet, key rotation supported |
| Identity keys | Ed25519 | Long-term identity verification |
| Key derivation | HKDF-SHA256 | Separate info strings per key type |
| Password hashing | Argon2id | Server-side registration/login |

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
