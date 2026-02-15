# Accord Roadmap

## Current Status (Feb 2026)

### ✅ Complete
- **Cryptography** — X25519 key agreement, AES-256-GCM, forward secrecy, voice packet encryption
- **Channel system** — Hybrid lobby/private model, entry requests, permission-based access
- **Bot framework** — Command-only visibility, encrypted arguments, interactive elements
- **Invite system** — Direct invite only, expiration controls, quality gates, approval workflow
- **Voice system** — Real-time encrypted voice, VAD, quality profiles, group mixing
- **Network protocol** — Message types, validation, sequencing, heartbeat, error handling
- **Project infrastructure** — CI/CD, Docker support, license, documentation

### 🔧 In Progress
- Fixing compilation errors in core crates
- Installing desktop (Tauri) build dependencies

## Phase 1: Foundation (Months 1-2)
- [ ] All crates compiling cleanly
- [ ] Server: WebSocket message routing
- [ ] Server: User authentication (SRP / zero-knowledge)
- [ ] Server: SQLite persistence layer
- [ ] Integration tests for core crypto
- [ ] Basic CLI client for testing

## Phase 2: Voice & Real-Time (Months 2-3)
- [ ] Opus codec integration
- [ ] Real-time audio capture/playback
- [ ] P2P voice for small groups (≤4)
- [ ] Server-relayed voice for larger groups
- [ ] Jitter buffer and packet loss handling

## Phase 3: Desktop App (Months 3-5)
- [ ] Tauri app with React/TypeScript frontend
- [ ] Channel list, message views, voice controls
- [ ] Integration with Rust crypto backend
- [ ] Auto-updater and native system tray
- [ ] Cross-platform builds (Windows, macOS, Linux)

## Phase 4: Hardening (Months 5-7)
- [ ] Security audit (internal, then third-party)
- [ ] Penetration testing
- [ ] Reproducible builds
- [ ] Self-hosting documentation
- [ ] Performance benchmarking (10k+ concurrent users target)

## Phase 5: Mobile (Months 7-10)
- [ ] iOS app (Swift + Rust FFI)
- [ ] Android app (Kotlin + Rust JNI)
- [ ] Push notifications with encryption preservation
- [ ] Background voice support

## Phase 6: Public Release (Months 10-12)
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

## Server Trust & Node Creation Model

### Node Creation Policies (Server-Level Config)
Relay server operators choose how Nodes are created on their instance:

| Policy | Description | Use Case |
|--------|-------------|----------|
| `admin_only` | Only server operator creates Nodes | Managed hosting, corporate |
| `open` | Any authenticated user can create Nodes | Community hosting, public |
| `approval` | Users request, admin approves | Curated communities |
| `invite` | Existing Node owners can grant creation rights | Web of trust |

### Server Discovery
For users to find relay servers without direct links, we need a discovery mechanism:
- **Server directory** (optional, federated) — relay servers can opt-in to be listed
- **DNS-based discovery** — `_accord._tcp.example.com` SRV records
- **QR code / deep links** — share server address + fingerprint
- **Word of mouth** — direct URL sharing (primary, most secure)

### Trust Model & Security Concerns
A malicious relay server could attempt:
- **Metadata logging** — who connects, when, to which Nodes
- **Traffic analysis** — message timing, size patterns
- **Payload modification** — though E2E prevents reading content

**Mitigations:**
1. **Server fingerprinting** — Ed25519 server identity key, clients pin on first connect (TOFU) or verify out-of-band
2. **Client warnings** — prominent UI notice when connecting to a new/unverified server
3. **E2E guarantees** — encryption means content privacy holds even on malicious relays
4. **Metadata minimization** — relay server stores minimum necessary routing data
5. **Server transparency** — optional attestation of server version, config, and build reproducibility
6. **Community trust lists** — decentralized reputation (not a single authority)
7. **Tor/onion support** — users can connect via Tor to hide their IP from relay operators
