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
- Voice channels routed through the relay (the early P2P mode has since been removed from current clients)
- Rust voice modules (`srtp`, `voice`, `p2p_voice`, `jitter_buffer`) — written, but unused: no shipped client uses them
- Opus codec, jitter buffer, packet loss handling
- Voice UI (mute, deafen, speaking indicators)

### ✅ Phase 4: Security Hardening — COMPLETE
- **Double Ratchet** — full Signal protocol spec with X3DH key agreement
- **Rust SRTP module** — written for an earlier voice design and unused by every shipped client
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
- [x] End-to-end-encrypted calls (desktop and web): a random key per sender and epoch, sent only inside Double Ratchet sessions, SFrame frames bound to channel, sender and call instance, rotation on every join, departure and removal and every 10 minutes; not verified until identity verification ships
- [x] End-to-end-encrypted screen sharing through the relay (`screen/1`): video only (VP8, no sound) under keys derived from the call's epoch keys, opt-in watching, viewing only in the macOS app; unavailable on relays without `screen/1`, and the relay still sees who shares and watches and the size and timing of the video
- [x] P2P voice and P2P screen sharing removed from clients, and P2P signaling retired at the relay in the same relay release as `screen/1`
- [ ] Relay refuses the readable voice of older clients (the first relay release after the client release)
- [ ] Mobile voice on the end-to-end-encrypted relay path (mobile voice does not work today)
- [ ] Windows packaging (CI)
- [ ] Beta program
- [ ] Community feedback integration

### 📋 Phase 7: Post-Launch Hardening — PLANNED
- [ ] Metadata protection Phase 3 (drop plaintext name columns entirely; per-user display-name keys)
- [ ] Onion routing for metadata resistance
- [ ] Post-quantum key exchange (ML-KEM / hybrid X25519+Kyber)
- [ ] External security firm audit

### 📋 Phase 8: Federated Node High Availability — PLANNED
> Design: [docs/FEDERATION-DESIGN.md §9](docs/FEDERATION-DESIGN.md). Today nodes
> are single-home (one relay per node); this phase makes them survive a relay outage.
- [ ] Multi-home nodes — owner-chosen, opt-in relay set per node
- [ ] Primary + warm-standby replication with epoch-numbered failover; client relay-set walk
- [ ] Collective, advisory node-deletion vote (signed, published tally; each relay decides for itself)
- [ ] Federation-map governance column (voting record + version build-hash) for trust-based peering

---

## Technical Specifications

### Cryptographic Protocol
| Component | Algorithm | Details |
|-----------|-----------|---------|
| Key agreement | X3DH + X25519 | Full Signal protocol handshake |
| Message encryption | Double Ratchet (AES-256-GCM) | Per-message forward secrecy |
| Calls and screen sharing | SFrame (RFC 9605), AES-256-GCM, HKDF-SHA512 | A random key per sender and epoch, sent only inside Double Ratchet messages; not yet verified. The Rust voice modules are unused |
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
| E2E encryption | ⚠️¹ | ❌ | ✅ | ✅ |
| Community features | ✅ | ✅ | ❌ | ✅ |
| Voice channels | ✅ | ✅ | ❌ | ⚠️ |
| Zero-knowledge server | ⚠️¹ | ❌ | ✅ | ❌ |
| Privacy-preserving bots | ✅ | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ⚠️ | ✅ |
| Mobile apps | ✅ | ✅ | ✅ | ✅ |
| Open source | ✅ | ❌ | ✅ | ✅ |

> ¹ Messages and attachments (desktop and web). Attachments are only as authentic as their message and the relay sees their metadata, files uploaded before encrypted attachments shipped stay readable by the relay until they are retired, calls and screen sharing are end-to-end encrypted but not yet verified, and a malicious relay can intercept encrypted sessions when they are set up — see [SECURITY.md](SECURITY.md#known-limitations).

## Architecture

### Node Model
- **Nodes** = community spaces (like Discord servers, but E2E encrypted)
- **Relay server** = invisible infrastructure (users never interact with it directly)
- **Relay owner ≠ Node owner** — "landlord can't enter apartments." Relay owner = whoever has localhost access; sees node names/descriptions, creates/deletes nodes, bans IPs for abuse — nothing inside a node. No central moderation. See [GOVERNANCE.md](GOVERNANCE.md).
- **Node creation policies:** `open | admin_only` (implemented); `approval | invite` (planned)

### Trust Model
E2E encryption is meant to stop even malicious relays from reading content; see [SECURITY.md](SECURITY.md#known-limitations) for where the current release falls short. Remaining risks and mitigations:
- **Metadata** → NMK encrypts channel/category names + per-node policy (done); Phase 7: onion routing for timing/graph metadata
- **Server fingerprinting** → Ed25519 identity key, TOFU + out-of-band verification
- **Quantum threats** → Phase 7: post-quantum key exchange

### Server Discovery
- DNS SRV records (`_accord._tcp.example.com`)
- QR code / deep links with server fingerprint
