# Accord — Project Map to First Public Beta

**Generated:** 2026-07-12 · **Basis:** full codebase audit at commit `48c8c0d`
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

### 🔴 A. Channel E2EE never actually activates (THE beta blocker)

The flagship promise ("relay can never read messages") is currently only true for DMs.

What exists (≈70% of the work is done):
- `core/src/sender_keys.rs` (Rust, 9 tests) and `e2ee/senderKeys.ts` (TS, ~30 tests) — full Sender Keys implementation
- Server distribution plumbing: `POST /channels/:id/sender-keys`, `GET /sender-keys/pending`, `POST /sender-keys/ack`, plus `sender_key_distribution` / `sender_key_new_member` / `sender_key_rotation_required` WS events
- Send path in `App.tsx:2800` prefers sender keys when available

What's missing — three precise gaps in `desktop/frontend/src/App.tsx`:
1. **No bootstrap.** `hasChannelKeys()` checks `myKeys.has(channelId)`, but the only call to `getOrCreateMyKey()` is *inside* the encrypt function that is only reached when `hasChannelKeys()` is already true. Chicken-and-egg: **a fresh client never creates a sender key**, so every channel message silently uses the placeholder crypto. Nothing on channel join/select creates + distributes a key to existing members, and nothing fetches `/sender-keys/pending` on connect.
2. **Rotation redistribution is a stub.** `distributeSenderKeyToChannel()` (App.tsx:99) only `console.log`s. On member removal the client rotates its key locally but never sends the new key to remaining members — messages after a kick become undecryptable or silently downgrade.
3. **Silent downgrade chain.** Send path falls back: sender keys → deterministic symmetric key (`SHA-256(channelId + fixed salt)` — server-derivable, audit finding M3) → **plaintext** on error, with only a console.warn. Beta needs a policy (fail closed) and a visible per-message encryption indicator (`e2eeType` field already exists).

### 🔴 B. Metadata encryption (NMK) not wired into the client

`core/src/metadata_crypto.rs` (28 tests) and the nullable `encrypted_name` DB columns exist, but the frontend contains **zero** references to NMK or `encrypted_name`. Node names, channel names, and display names are stored in plaintext on the relay — directly contradicting the README's "What the Relay Sees" table. Either ship metadata-privacy Phase 2 (client encrypts) or correct the public claims before beta.

### 🟠 C. Security-audit items still open (verified in code)

| Item | Status now |
|---|---|
| H1 admin token in URL | ✅ Fixed |
| L2 non-constant-time admin token compare | ✅ Fixed (test exists) |
| M4 rate-limiting gaps | ~80% fixed — HTTP middleware covers messages/files/invites/DMs/profile/node-create; WS path checks at `main.rs:140`; needs edge-case tests (open issue #6) |
| M1 no CSP header | ❌ Still missing (`grep` confirms zero CSP references in server) |
| M2 auth tokens in localStorage | ❌ Unchanged; Tauri keyring migration recommended |
| L1 weak session key-wrap passphrase | ❌ Document-only fix pending |
| L3 error messages leak internals | ❌ Unverified/unaddressed |

### 🟠 D. Test coverage holes at security boundaries

Per the coverage audit (and still true): `server/src/files.rs`, `db/encryption.rs`, `federation.rs`, `webhooks.rs` have **0 unit tests**; frontend `ws.ts`, voice stack, and `e2ee/session.ts` untested. Federation (1,095 LOC, live routes, background maintenance task) is an untested trust boundary — **either test it or feature-flag it off for beta.**

### 🟡 E. Beta program infrastructure (Phase 6 checklist, all unstarted)

- No packaged releases (Tauri `.deb`/`.AppImage`/`.msi`, no GitHub Releases)
- No beta feedback channel; website donate link "coming soon"; README screenshots missing
- `UpdateChecker.tsx` exists but no release channel to check against
- Mobile apps functional but unpackaged (recommend: **explicitly out of scope for first beta**; desktop + web only)

### 🟡 F. Repo/CI hygiene

- Broken bench target (see §1); QA gate lacks `--all-targets`, `cargo audit`, and any bench compile
- 5 stale remote test branches to merge or close
- Docs (ROADMAP, SECURITY-AUDIT, TEST-COVERAGE-AUDIT) 4 months stale relative to code

---

## 3. Milestone Plan to Beta

### M0 — Foundation & hygiene *(~1 week)*
1. Fix `server_benchmarks.rs:230` (pass `None` for the new param)
2. Harden `pre-push-qa.sh`: add `--all-targets`, `cargo audit`, fail if Node missing
3. Merge or close the 5 remote `test/*` branches
4. Dev env: install Node 20+, `webkit2gtk`/`javascriptcoregtk-4.1`, `cargo-audit`
5. Refresh stale docs to match code reality

### M1 — Close the E2EE loop *(the critical path, ~2–3 weeks)*
1. **Bootstrap:** on channel join/select, `getOrCreateMyKey()` + distribute to every member via existing Double Ratchet sessions + `POST /channels/:id/sender-keys`; fetch `/sender-keys/pending` + ack on every connect
2. **Real rotation:** replace the `distributeSenderKeyToChannel` stub with actual member iteration + redistribution
3. **Fail-closed policy:** remove plaintext fallback; gate symmetric fallback behind an explicit "compatibility mode"; surface `e2eeType` as a per-message/per-channel UI badge
4. **Session recovery tests:** unit tests for `e2ee/session.ts` (missing bundle, stale session) — this flow now carries group security
5. Exit criteria: two fresh clients in one channel exchange messages the server provably cannot decrypt; kick a member → remaining members still decrypt

### M2 — Metadata privacy Phase 2 *(~1–2 weeks, parallelizable with M1)*
1. Client derives NMK on node create, sends `encrypted_name`/`encrypted_description` alongside plaintext
2. NMK distribution to joiners over the DR channel (design already in `docs/metadata-privacy.md`)
3. Client prefers decrypted names, falls back to plaintext
4. If this slips: amend README/SECURITY "relay sees" tables — don't ship a beta with overclaimed privacy

### M3 — Security hardening *(~1–2 weeks)*
1. CSP middleware (audit M1) — one axum layer, spec already written in SECURITY-AUDIT.md
2. Tauri: move tokens/identity to OS keyring (M2); document web-client residual risk
3. Sanitize client-facing error strings (L3)
4. P1 unit tests: `files.rs`, `db/encryption.rs`, `federation.rs` — or feature-flag federation off for beta
5. Rate-limit edge-case tests (open issue #6)

### M4 — Beta packaging & program *(~1–2 weeks)*
1. `cargo tauri build` artifacts for Linux/Windows + GitHub Releases with reproducible-build hashes (HASHES.json flow exists)
2. One-command relay deploy verified (`docker-compose up`) + web client serving (`--frontend dist`)
3. Wire `UpdateChecker` to the releases feed
4. Screenshots, beta signup/feedback via GitHub Discussions, website donate link resolution
5. Run the full Playwright suite + load scripts against a staged relay; fix fallout

### M5 — Post-beta (explicitly out of scope for first beta)
Mobile store releases · federation/relay-mesh hardening + cross-relay DMs · onion routing · post-quantum hybrid KEX · external security firm audit (Phase 7)

---

## 4. Sequencing Logic

```
M0 ──► M1 (E2EE loop) ──────────┐
  └──► M2 (metadata, parallel) ─┼──► M3 (hardening) ──► M4 (packaging) ──► BETA
                                 │
        M5 deferred ─────────────┘
```

M1 is the only truly serial dependency: **the product's core claim is false until it lands.** Everything else is polish, honesty, or armor around that claim.
