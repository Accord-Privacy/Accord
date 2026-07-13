# Accord Roadmap

## Current Status: Phase 6 — Beta Packaging (July 2026)

> Working plan with per-milestone status lives in [PROJECT-MAP.md](PROJECT-MAP.md);
> this file tracks the phase-level picture.

---

### ✅ Phase 1–2: Foundation + Core Features — COMPLETE
- Server with WebSocket relay, SQLite persistence, Argon2 authentication
- REST API, React/TypeScript frontend (Discord-like dark theme)
- CLI client, Tauri desktop shell, Docker deployment
- E2E encryption (X25519, AES-256-GCM, HKDF forward secrecy)
- Multi-tenant Node architecture, invite links, file sharing
- Windows/Linux builds, CI/CD pipeline

### ✅ Phase 3: Voice & Real-Time — COMPLETE
- P2P voice mesh for small groups (≤4 users)
- ICE-lite connectivity, SRTP encryption
- Opus codec, jitter buffer, packet loss handling
- Relay fallback for restrictive NATs
- Voice UI (mute, deafen, speaking indicators)

### ✅ Phase 4: Security Hardening — COMPLETE
- **Double Ratchet** — full Signal protocol spec with X3DH key agreement
- **SRTP voice encryption** — replaced placeholder with proper WebRTC-grade encryption
- **Dependency upgrades** — quinn 0.11, sqlx 0.8, all audit findings resolved
- **Reproducible builds** verified
- **Performance benchmarks** (10k+ concurrent users target)
- **Comprehensive audit** — all CRITICAL (7), HIGH (16), MEDIUM (26), LOW (24) findings fixed
  - Argon2 hashing, token validation, XSS prevention, CORS lockdown
  - File path traversal prevention, private key encryption at rest
  - Rate limiting, structured logging, clippy + `cargo audit` in CI

### ✅ Phase 5: Mobile — COMPLETE
- **iOS** — Rust FFI bridge, Swift wrapper, Swift Package Manager distribution
- **Android** — Rust JNI bridge, Kotlin wrapper
- **Push notifications** — APNs/FCM traits, 3 privacy levels (full/metadata-only/silent), E2E encrypted metadata
- **Background voice** — state machine, keepalive, platform guidance docs

### 🚧 Phase 6: Public Release — IN PROGRESS
- [x] Bot API (permission scopes, webhooks, rate limiting, developer docs)
- [x] Channel group E2EE (Sender Keys) — verified two-client, fail-closed sends
- [x] Metadata encryption Phase 2 (NMK) — node/channel names as opaque relay blobs
- [x] Security hardening (CSP, OS-keyring tokens, error-detail sanitization, boundary tests)
- [x] Linux packaging (.deb/.AppImage, signed updater feed, release pipeline)
- [ ] Windows packaging (CI)
- [ ] Beta program
- [ ] Community feedback integration

### 📋 Phase 7: Post-Launch Hardening — PLANNED
- [ ] Metadata protection Phase 3 (drop plaintext name columns entirely; per-user display-name keys)
- [ ] Onion routing for metadata resistance
- [ ] Post-quantum key exchange (ML-KEM / hybrid X25519+Kyber)
- [ ] External security firm audit

---

## Technical Specifications

### Cryptographic Protocol
| Component | Algorithm | Details |
|-----------|-----------|---------|
| Key agreement | X3DH + X25519 | Full Signal protocol handshake |
| Message encryption | Double Ratchet (AES-256-GCM) | Per-message forward secrecy |
| Voice encryption | SRTP | Per-packet, key rotation |
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

### Differentiators
| | Accord | Discord | Signal | Matrix |
|---|---|---|---|---|
| E2E encryption | ✅ | ❌ | ✅ | ✅ |
| Community features | ✅ | ✅ | ❌ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ |
| Zero-knowledge server | ✅ | ❌ | ✅ | ❌ |
| Privacy-preserving bots | ✅ | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ |
| Mobile apps | ✅ | ✅ | ✅ | ✅ |
| Open source | ✅ | ❌ | ✅ | ✅ |

## Architecture

### Node Model
- **Nodes** = community spaces (like Discord servers, but E2E encrypted)
- **Relay server** = invisible infrastructure (users never interact with it directly)
- **Server admin ≠ Node admin** — "landlord can't enter apartments"
- **Node creation policies:** `admin_only | open | approval | invite`

### Trust Model
E2E encryption means even malicious relays can't read content. Remaining risks and mitigations:
- **Metadata** → Phase 7: encrypt usernames/channels, onion routing
- **Server fingerprinting** → Ed25519 identity key, TOFU + out-of-band verification
- **Quantum threats** → Phase 7: post-quantum key exchange

### Server Discovery
- DNS SRV records (`_accord._tcp.example.com`)
- QR code / deep links with server fingerprint
