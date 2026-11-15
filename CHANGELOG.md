# Changelog

All notable changes to Accord are documented here. This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — Phase 6: Public Release (In Progress)

### Relay admission (SPEC-01) — operator release note

The relay now enforces who may join a node. This closes the empty-password login
of the DM system account, the takeover of the node that holds every DM, and
joins by node id. Back up before upgrading, and read this before the first boot
of the new binary: several changes happen once, at that boot, and are final.

**What changes for users and node owners**

- **Joining needs an invite, an approval or ownership.** `POST /nodes/:id/join`
  and WebSocket `JoinNode` no longer admit anyone who knows a node id. Invites are
  validated and consumed atomically, so use limits hold under concurrent joins.
  An owner can switch a node's `join_policy` to `request`, so that people can ask
  to join and members with CREATE_INVITE approve or deny them. The relay sees
  these join requests (who asked to join which node) for up to 14 days.
- **CREATE_INVITE now means "may admit people".** It gates creating, listing and
  revoking invites and approving join requests. At the first boot it is removed
  once from every node's `@everyone` role. Owners who want every member to be able
  to admit people must grant it to `@everyone` again; that choice then stays.
  Invites created by members who lose CREATE_INVITE, this way or by a later
  demotion, stop working. Template imports no longer write CREATE_INVITE,
  ADMINISTRATOR or any other privileged bit to `@everyone`.
- **Old permanent invite links expire.** Every invite created before the upgrade
  without an expiry (all invites made by the desktop app so far, which sent its
  expiry under a field the relay ignored) stops working 7 days after the first
  boot of this release. Owners must create a new invite for any link they want to
  keep, and may choose "never" explicitly. Operators can change the grace period
  with `--legacy-invite-grace-hours <n>` (`0` = expire at once) or keep those
  invites permanent with `--keep-legacy-permanent-invites`; the choice made at
  the first boot is final. Invites created after the upgrade are never touched.
  Older 8-character codes that carry an explicit expiry keep working until they
  expire; the relay logs how many are still live. New codes are 22 characters.
- **Legacy role markers are reset.** The legacy Admin/Moderator conversion runs
  one last time and never again, then every member who is not a node owner gets
  the plain `member` marker. They keep their roles and the permissions those
  carry, but lose the marker-only powers (encrypted metadata writes, bot
  management, deleting other people's files). Deleting or unassigning a role now
  survives restarts. A demotion made between the old binary's last start and the
  upgrade is undone this one last time: **owners should review role assignments
  after upgrading.**
- **Review your member lists.** Members who joined a node by its id before this
  release cannot be told apart from legitimate members and remain. Owners should
  review member lists and remove anyone they do not recognise. `GET /health`
  reports `admission_since`, the time admission enforcement began, so clients can
  flag members whose `joined_at` is earlier.
- **Device bans and build allowlists apply to every join.** On a node with at
  least one device ban, every admission, invite redemption included, needs a
  device fingerprint; a client that sends none gets `fingerprint_required`. Older
  desktop builds send none, so they cannot join such nodes until users update.
  A node's per-node build allowlist now also applies to invite redemption; a
  client that sends no `X-Build-Hash` counts as the empty hash and is refused by
  a non-empty allowlist.
- **Leave, kick and ban.** Leaving or kicking a user who is not a member now
  returns `404 not_member` instead of a silent success. REST leave and the ban of
  a member now broadcast `sender_key_rotation_required` like WebSocket leave and
  kick, and every removal deletes queued sender-key distributions in both
  directions. Membership actions, kicks included, are limited to 10 per minute
  per user. A re-admitted user starts without their old roles.
- **Error reasons.** Admission errors carry a machine-readable `reason` (and
  `retry_after` for rate limits) next to the existing `error` text. Relays list
  `admission/1` in the new `features` array of `GET /health` and the WebSocket
  `hello`.

**Locked accounts**

- Accounts without a password, and the built-in DM system account, are locked
  permanently (their stored password hash becomes `!locked`) and their sessions
  are deleted. Logins to them are refused exactly like a wrong password. There is
  no recovery path: affected users must register again. Official desktop and
  mobile clients always set a password, so this affects only API, test or legacy
  keyless accounts. Registration now requires a password.

**What operators will see**

- **Boot repair log lines.** At every start the relay checks the DM system node
  and account and reverts any hijacked state (owners, members, invites, roles,
  bots, webhooks and non-DM channels in the DM node, and DMs with the system
  account, whose files are deleted). It logs one WARN line per step that changed
  rows, with counts only, such as `admission repair: step B5 changed 3 rows`.
  Such lines mean a past compromise was reverted. On a clean database the repair
  changes nothing.
- **One-time migration log lines**, under the target `accord::admission`, with
  counts only: the role conversion, the `@everyone` CREATE_INVITE strip, the
  invite expiry (or the number kept with the opt-out), and the removal of invite
  codes from existing audit entries. Audit entries no longer contain invite codes.
- **Orphaned legacy nodes.** Nodes other than the DM node that are still owned
  by the DM system account (a "Management" node from early versions) are left in
  place without an owner; the relay logs their count at every start.
- **Fail-closed start.** If the repair, the database triggers or a one-time
  migration cannot run, the relay exits with `admission repair failed` and does
  not serve. Fix the cause (read-only or locked database, full disk) and restart.
- **New flags:** `--legacy-invite-grace-hours`, `--keep-legacy-permanent-invites`
  and `--preview-rate-limit` (unauthenticated invite previews per minute per
  client network, default 30; loopback peers such as a same-host reverse proxy are
  not limited; `0` disables it). See [docs/admin-guide.md](docs/admin-guide.md).

This protects members from other users of an honest relay. It is not a
protection against the relay operator.

### Governance & privacy (2026-07-13)
- **Governance model documented** ([GOVERNANCE.md](GOVERNANCE.md)) — no central or
  relay-side moderation; parent model; node owners are 100% responsible for their
  communities; Accord is explicitly not a "safe space". Reflected across README,
  CONTRIBUTING, architecture, admin-guide, and metadata-privacy docs.
- **Relay owner = localhost.** The admin dashboard now binds to `127.0.0.1` only
  (`--admin-port`, default 6789; `--no-admin`) and is off the public router.
  `ACCORD_ADMIN_TOKEN` is optional defense-in-depth (unset = localhost-trusted).
- **Relay blindness tightened.** Removed the all-users roster (it exposed each
  user's node memberships) and the cross-node audit-log aggregate (per-node
  governance + actor IPs). The node registry now shows names/descriptions only.
- **Disappearing messages** — per-node default + per-channel override, retroactive
  wipe-old on enable; policy distributed via the NMK-encrypted settings blob (the
  relay sees only an opaque `expires_at`).
- **Read-gated messages** — composer control to hold a message's disappear timer
  until chosen readers (users and/or roles) have seen it, with per-recipient,
  per-device expiry after each reader opens it.
- **Screenshot protection** — per-node/channel; reliable on Windows/macOS,
  best-effort on Linux (honestly scoped in-app).
- **Auto-mod word filters moved fully client-side** — distributed inside the
  NMK-encrypted node settings and enforced on the client; all relay auto-mod
  endpoints, storage, and enforcement removed (they leaked the wordlist and were
  non-functional against E2E-encrypted messages anyway).
- **Panic wipe** and **duress password** (decoy account, no forensic trace).

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
- Landing page at accord.chat
