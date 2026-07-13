# Changelog

All notable changes to Accord are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — Phase 6: Public Release (In Progress)

### Security hardening (2026-07-13 endpoint-threat sweep)
- **Two-factor at-rest keys (audit L1).** Local encrypted stores now derive their
  key from `HKDF(password, salt = per-user 256-bit secret held in the OS
  keyring)` instead of `SHA-256(password‖domain)`. Recovering history at rest
  requires both the password and the device's keyring secret — a locked, seized
  device cannot yield it without the password, and a leaked password is useless
  without the device. Legacy blobs migrate transparently. Web build keeps the
  legacy path (documented residual-risk surface).
- **Microphone permission scoped (desktop).** getUserMedia is granted only while
  actively in a voice call; camera/video is always denied. Previously all
  user-media requests were granted unconditionally.
- **`--disable-rate-limits` gated behind `--no-tls`** so abuse protection (rate
  limits + per-device account cap) cannot be turned off on a production-shaped
  deployment by accident.
- **Endpoint threat model** documented (`docs/threat-model-endpoint.md`): the
  compromised/seized-device model, disappearing-messages and duress designs, and
  reproducible-builds-as-scanning-resistance for the legislative angle.

### Added (2026-07-12 desktop testing sweep)
- **Friends in the desktop app** — friend requests (sent automatically when DMing a non-friend), pending-request accept/reject UI in the DM sidebar; DMs require friendship per relay policy
- **Listen-only voice** — joining a voice channel no longer requires a working microphone or audio output; capture and playback degrade independently
- **Desktop two-client automation suite** — drives two real desktop instances through node/invite, channel E2EE, friends, DMs, and voice presence (`npm run auto:two`)

### Fixed (2026-07-12 desktop testing sweep)
- **Sender-key exchange no longer depends on UI state** — node join initiates E2EE key exchange from the join event itself, with retry while the peer's prekey bundle publishes; previously messages could stay permanently undecryptable depending on user-ID ordering and member-list load timing
- **DM channels work end-to-end in the desktop app** — relay node-permission checks no longer block DM join/read/send; received DMs are cached (encrypted at rest) so history survives Double Ratchet advancement; the DM list refreshes on the first message from a new channel
- **Voice capture** — ScriptProcessorNode buffer size was invalid (960, must be a power of two); voice audio capture never worked in any browser or webview
- **Desktop Tauri integration** — `withGlobalTauri` was missing, so OS-keyring token storage and device identity silently fell back to browser behavior in the packaged app
- Voice participant sidebar shows display names instead of user-ID prefixes
- DM list crash when a DM channel's last message has no plaintext content

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
