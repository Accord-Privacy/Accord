# Changelog

All notable changes to Accord are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — Phase 6: Public Release (In Progress)

### Security
- **Security audit** — full frontend + server audit with 0 critical, 1 high, 4 medium, 3 low findings ([SECURITY-AUDIT.md](SECURITY-AUDIT.md))
- Admin token removed from URL query parameters (H1 fix)
- Input validation tightened across all server endpoints

### Added
- **Responsive mobile web** — frontend adapts to phone/tablet screens
- **Playwright E2E test suite** — 7 tests covering critical flows
- **Expanded test coverage** — E2EE, REST API, and integration tests
- **Lazy loading** — SearchOverlay, SetupWizard, BotPanel load on demand
- Memoized `filteredMessages` for large channel performance

### Changed
- Extracted 6 hooks from App.tsx (useVoice, usePresence, useTyping, useUIState, useReadReceipts, useBlocking)
- Extracted 128+ inline styles to CSS classes
- All emoji replaced with SVG icon system for consistent rendering

### Fixed
- Login after logout — keypair detection for password-encrypted slots
- Display name restore after re-login
- Registration error surfacing (429/500/network no longer swallowed)
- Inverted create/join Node modal state names

---

## [0.1.0] — 2026-02-15 → 2026-02-22 — Foundation through Phase 5

Initial development spanning Phases 1–5 of the roadmap.

### Core Platform
- **Relay server** — WebSocket + REST API, SQLite persistence, Argon2 auth, TLS (auto-generated or BYO)
- **React/TypeScript frontend** — Discord-style dark theme, works in browser or Tauri desktop shell
- **CLI client** (`accord-cli`) for terminal-based usage
- **Bot SDK** (`bot-sdk/`) with airgapped command model and E2EE tokens

### End-to-End Encryption
- **Double Ratchet + X3DH** for DMs (Signal protocol foundations)
- **AES-256-GCM** channel encryption for group messages and files
- **SRTP voice encryption** with periodic key rotation
- **BIP39 mnemonic** keypair-only identity (no PII required)
- **Encrypted push notification payloads** (3 privacy levels)

### Voice
- **WebRTC voice channels** — P2P mesh (≤4 users), relay fallback for larger groups
- Opus codec, jitter buffer, mute/deafen, speaking indicators

### Nodes (Community Spaces)
- Categories, channels, 50+ permission bits with cascade model
- Invite links (configurable max uses + expiration)
- Discord template import, drag-and-drop reordering
- Custom emoji, message reactions, pinning, threads/replies
- Rich link previews (Open Graph), user blocking
- Per-Node encrypted profiles, custom status
- Admin dashboard with audit logging, auto-mod

### Mobile
- **iOS** — SwiftUI + Rust FFI bridge
- **Android** — Jetpack Compose + Rust JNI bridge
- Push notifications (APNs, FCM, UnifiedPush)
- Background voice support

### Infrastructure
- CI/CD via GitHub Actions (Linux + Windows builds)
- `scripts/pre-push-qa.sh` — mandatory fmt, clippy, test, audit gate
- Reproducible builds, build hash verification
- Docker deployment support
- Landing page at [accord.chat](https://accord.chat)
