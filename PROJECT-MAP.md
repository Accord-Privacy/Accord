# Accord — Project Map to First Public Beta

**Generated:** 2026-07-12 · **Basis:** full codebase audit at commit `48c8c0d`
**Updated:** 2026-07-12 (post-M0/M1; M2 in progress — statuses below reflect the working tree, not the original audit)
**Goal:** first running beta with the full advertised featureset (desktop + web client, self-hostable relay, true E2EE for DMs *and* channels).

---

## 1. Codebase as It Sits

### Scale

| Component | LOC | State |
|---|---|---|
| `server/` (relay) | 66,639 Rust | Compiles clean, well-featured |
| `core/` (crypto/protocol) | 20,439 Rust | Compiles clean, best-tested code in repo |
| `desktop/frontend/` | 45,382 TS/TSX | Could not verify on this machine (no Node.js installed) |
| `core-minimal/` | 1,749 Rust | Compiles |
| `bot-sdk/` | 2,696 Rust | Compiles, no functional tests |
| `accord-cli/` | 779 Rust | Minimal client |
| `mobile/ios` + `mobile/android` | ~7,900 Swift/Kotlin | Functional per MOBILE.md, not release-packaged |

### Verified health (this audit, this machine)

- ✅ `cargo check --workspace --exclude accord-desktop --lib --bins` — **clean**
- ✅ `cargo test -p accord-core -p accord-server` — **583 passed, 0 failed**
- ❌ `server/benches/server_benchmarks.rs:230` — **does not compile** (`add_connection` gained a third `Option<Uuid>` parameter; bench never updated). Undetected because the QA gate omits `--all-targets`.
- ⚠️ `accord-desktop` needs `javascriptcoregtk-4.1` / `webkit2gtk` system packages (dev-environment gap, not a code bug)
- ⚠️ No Node.js/npm on this machine — frontend build, vitest, and Playwright unverifiable locally
- ⚠️ `cargo-audit` not installed locally, and `scripts/pre-push-qa.sh` **does not actually run it** despite CONTRIBUTING.md calling it mandatory
- ⚠️ Docs lag code: recent commits (auth/identity split, voice overhaul with screen sharing, partial Sender Keys wiring) are ahead of ROADMAP/SECURITY-AUDIT/TEST-COVERAGE docs (all dated Feb–Mar 2026)
- 📋 5 unmerged remote `test/*` branches + 2 open good-first issues (rate-limit edge cases, useVoice tests)

---

## 2. Core Sections Missing — Ranked

### ✅ A. Channel E2EE never actually activates (THE beta blocker) — CLOSED

**Resolved 2026-07-12** (`f4d11cb` + follow-ups): sender key bootstrap on channel
select and on-demand before send/edit, real rotation redistribution on member
removal, pending-distribution drain/ack on connect, and fail-closed sends (legacy
symmetric crypto is an explicit `accord_legacy_channel_crypto` opt-in, badged in
the UI). Bonus fix found by the new tests: Double Ratchet decrypt in both Rust
core and the TS client mutated state before AES-GCM verification — a replayed or
tampered message permanently desynced the session (`4c40935`). Exit criteria
(two fresh clients, server provably can't decrypt; kick test) pending the new
`e2e/sender-keys.spec.ts` run. Original finding preserved below.

<details><summary>Original finding</summary>

The flagship promise ("relay can never read messages") is currently only true for DMs.

What exists (≈70% of the work is done):
- `core/src/sender_keys.rs` (Rust, 9 tests) and `e2ee/senderKeys.ts` (TS, ~30 tests) — full Sender Keys implementation
- Server distribution plumbing: `POST /channels/:id/sender-keys`, `GET /sender-keys/pending`, `POST /sender-keys/ack`, plus `sender_key_distribution` / `sender_key_new_member` / `sender_key_rotation_required` WS events
- Send path in `App.tsx:2800` prefers sender keys when available

What's missing — three precise gaps in `desktop/frontend/src/App.tsx`:
1. **No bootstrap.** `hasChannelKeys()` checks `myKeys.has(channelId)`, but the only call to `getOrCreateMyKey()` is *inside* the encrypt function that is only reached when `hasChannelKeys()` is already true. Chicken-and-egg: **a fresh client never creates a sender key**, so every channel message silently uses the placeholder crypto. Nothing on channel join/select creates + distributes a key to existing members, and nothing fetches `/sender-keys/pending` on connect.
2. **Rotation redistribution is a stub.** `distributeSenderKeyToChannel()` (App.tsx:99) only `console.log`s. On member removal the client rotates its key locally but never sends the new key to remaining members — messages after a kick become undecryptable or silently downgrade.
3. **Silent downgrade chain.** Send path falls back: sender keys → deterministic symmetric key (`SHA-256(channelId + fixed salt)` — server-derivable, audit finding M3) → **plaintext** on error, with only a console.warn. Beta needs a policy (fail closed) and a visible per-message encryption indicator (`e2eeType` field already exists).

</details>

### ✅ B. Metadata encryption (NMK) not wired into the client — CLOSED

**Closed 2026-07-12** (`8956c45` + `67bd09a`, verified two-client): relay
exposes `GET/PUT /api/nodes/:id/metadata/encrypted` (opaque blob storage,
member read / admin write, node isolation tested); client derives the NMK on
node create, publishes encrypted name/description/channel-name blobs, shares
the NMK with joiners over Double Ratchet (piggybacked on sender-key
distributions), and prefers decrypted names in the UI. Cross-impl vectors
locked between `core/src/metadata_crypto.rs` and `e2ee/metadata.ts`.
`e2e/metadata-privacy.spec.ts` proves the relay rows hold only AES-GCM blobs
and the joiner can decrypt. Plaintext columns still exist during Phase 2
(compatibility); Phase 3 drops them — until then the README "relay sees"
table should note metadata encryption is client-optional.

### 🟠 C. Security-audit items still open (verified in code)

| Item | Status now (2026-07-12) |
|---|---|
| H1 admin token in URL | ✅ Fixed |
| L2 non-constant-time admin token compare | ✅ Fixed (test exists) |
| M4 rate-limiting gaps | ✅ HTTP middleware + WS checks; `rate_limit.rs` now has 34 tests incl. edge cases |
| M1 no CSP header | ✅ Fixed — full security-header stack in `main.rs` (CSP, nosniff, frame-ancestors, referrer, permissions-policy) |
| M2 auth tokens in localStorage | ✅ Fixed — `tokenStorage.ts` uses Tauri plugin-store (OS keychain) with localStorage web fallback + migration |
| L1 weak session key-wrap passphrase | ✅ Fixed (`f8ff2e5`): two-factor at-rest keys — HKDF(password, salt=OS-keyring SMK). See `docs/threat-model-endpoint.md` |
| L3 error messages leak internals | ✅ Fixed — 54 sites log detail server-side, return category only |

### ✅ D. Test coverage holes at security boundaries — CLOSED

All four server boundary files now tested (`files.rs` 36, `db/encryption.rs` 22,
`federation.rs` 35, `webhooks.rs` 26). Frontend: `ws.test.ts` exists,
`e2ee/session.test.ts` added 2026-07-12 (`e12bc24`), `e2ee/metadata.test.ts`
added with M2. Remaining smaller gap: voice stack / `useVoice` (open issue #3).

### 🟡 E. Beta program infrastructure (Phase 6 checklist, all unstarted)

- No packaged releases (Tauri `.deb`/`.AppImage`/`.msi`, no GitHub Releases)
- No beta feedback channel; website donate link "coming soon"; README screenshots missing
- `UpdateChecker.tsx` exists but no release channel to check against
- Mobile apps functional but unpackaged (recommend: **explicitly out of scope for first beta**; desktop + web only)

### 🟡 F. Repo/CI hygiene — MOSTLY CLOSED

- ✅ Bench fixed; QA gate hardened (`--all-targets`, `cargo audit`, mandatory frontend checks) — `4d850a8`
- Remaining: 4 remote `test/*` branches still carry unmerged commits (`frontend-component-tests`, `state-and-push-tests`, `rate-limit-edge-cases`, `frontend-hook-tests`) — merge or close
- Remaining: ROADMAP/SECURITY-AUDIT/TEST-COVERAGE docs still describe Feb–Mar 2026 state
- Note: full `pre-push-qa.sh` needs `webkit2gtk-4.1`/`javascriptcoregtk-4.1` system libs for the desktop crate; without them run clippy/check with `--workspace --exclude accord-desktop`

---

## 3. Milestone Plan to Beta

### ✅ M0 — Foundation & hygiene — DONE (`4d850a8`)
1. ✅ Fix `server_benchmarks.rs:230`
2. ✅ Harden `pre-push-qa.sh` (`--all-targets`, `cargo audit`, fail if Node missing)
3. ⏳ Merge or close remote `test/*` branches (4 still carry unmerged commits)
4. ✅ Node 20+ and `cargo-audit` installed; ❌ `webkit2gtk-4.1` still missing (desktop crate can't compile locally)
5. ⏳ Stale docs refresh (this file updated; ROADMAP/SECURITY-AUDIT/TEST-COVERAGE still pending)

### ✅ M1 — Close the E2EE loop — DONE pending e2e verification (`f4d11cb`, `4c40935`, `e12bc24`)
1. ✅ Bootstrap on channel select + on-demand before send/edit; pending distributions drained/acked on connect
2. ✅ Real rotation redistribution (stub replaced); join paths broadcast `sender_key_new_member`
3. ✅ Fail closed; legacy symmetric = explicit opt-in; per-message badge differentiates DR / sender keys / legacy
4. ✅ Session recovery tests (+ Double Ratchet decrypt-rollback fix in Rust core and TS, found by these tests)
5. ⏳ Exit criteria: `e2e/sender-keys.spec.ts` written, needs a green run (two fresh clients; kick test)

### ✅ M2 — Metadata privacy Phase 2 — DONE (`8956c45`, `67bd09a`; verified two-client)
1. ✅ Relay blob storage + `GET/PUT /api/nodes/:id/metadata/encrypted`; NMK client crypto (`e2ee/metadata.ts`) with cross-impl vectors
2. ✅ App.tsx wiring: NMK derived on node create, encrypted names published on create, decrypted names preferred in UI
3. ✅ NMK distribution to joiners over DR (piggybacked on sender-key distributions); `e2e/metadata-privacy.spec.ts` green
4. Remaining honesty note: plaintext columns persist through Phase 2 — README "relay sees" table should say metadata encryption is active for new nodes, plaintext fallback until Phase 3

### ✅ M3 — Security hardening — DONE
1. ✅ CSP middleware (full security-header stack in `main.rs`)
2. ✅ Tauri OS-keyring token storage (`tokenStorage.ts`); web-client residual risk documented in SECURITY-AUDIT.md
3. ✅ Sanitize client-facing error strings (L3) — 54 sites swept
4. ✅ P1 unit tests: `files.rs` (36), `db/encryption.rs` (22), `federation.rs` (35), `webhooks.rs` (26)
5. ✅ Rate-limit edge-case tests (34 tests in `rate_limit.rs`)

### 🔶 M4 — Beta packaging & program — IN PROGRESS (2026-07-12)
1. ✅ Linux artifacts built + signed (.deb 4MB, .AppImage 107MB + minisign .sig); `scripts/release.sh` = QA gate → build → latest.json + HASHES.json → gh release. ⏳ Windows nsis/msi: CI needed
2. ✅ Web client serving verified (`--frontend dist`); ⏳ `docker-compose up` unverified (no docker on dev machine)
3. ✅ Updater wired: signing keypair generated (private key OUTSIDE repo — `~/.tauri/accord-updater.key`, BACK IT UP), pubkey + createUpdaterArtifacts in tauri.conf.json, endpoint → releases/latest/download/latest.json, release.sh emits latest.json
4. ⏳ Screenshots, beta signup/feedback (GitHub Discussions), donate link
5. ✅ Full Playwright suite green against local relay (14/14 chromium); ⏳ load scripts against staged relay
6. ✅ Desktop automation harness (2026-07-12, `50a9b2f`): dev-only WS bridge drives the real Tauri binary headlessly — `desktop/frontend/automation/` (driver + smoke), `npm run auto:build && npm run auto:smoke`. Tree-shaken from release builds; release.sh rebuilds dist and asserts bridge marker absent. First run found + fixed 4 desktop-only launch blockers browser e2e can't see: NVIDIA blank window (`388f872`), relay CORS missing tauri:// origins (`8675481`), tauri://localhost persisted as server URL so registration silently went offline (`51cf689`), GetPendingSenderKeys serialized as map → pending E2EE sender keys never fetched on connect (`9f5905d`). Desktop smoke (account → node → message) green, zero console errors.
7. ✅ Two-client (friend-and-friend) automation suite (2026-07-12): `npm run auto:two` — two isolated desktop instances: node/invite join, channel E2EE both directions, friend request/accept, DMs both directions, voice presence. Found + fixed a second wave of bugs invisible to browser e2e: sender-key exchange starved by UI state (join event now initiates with retry — was a UUID-ordering coin flip), `withGlobalTauri` missing (keyring/device identity dead in packaged app), DM channels blocked by node-permission checks relay-side, DR DM history undecryptable by design (plaintext now cached encrypted at rest), DM list stale-closure + crash on E2EE last_message, voice capture broken everywhere (ScriptProcessor 960 buffer illegal), no listen-only voice, WebKitGTK mic permission denied (Tauri handler added; ACCORD_MOCK_MEDIA=1 for tests), per-device account cap now skipped under --disable-rate-limits. Client friends UI added (auto-request on DM, accept/reject rows in sidebar).

### M5 — Post-beta (explicitly out of scope for first beta)
Mobile store releases · federation/relay-mesh hardening + cross-relay DMs · onion routing · post-quantum hybrid KEX · external security firm audit (Phase 7)

---

## 4. Sequencing Logic

```
M0 ✅ ──► M1 ✅ (verified) ──────┐
  └──► M2 ✅ (verified) ────────┼──► M3 ✅ ──► M4 (packaging) ──► BETA
                                 │
        M5 deferred ─────────────┘
```

M1 is the only truly serial dependency: **the product's core claim is false until it lands.** Everything else is polish, honesty, or armor around that claim.

**Critical path remaining to beta (2026-07-12):** M4 packaging & beta program only. Housekeeping: 4 `test/*` branches, stale ROADMAP/SECURITY docs,
README "relay sees" honesty note.
