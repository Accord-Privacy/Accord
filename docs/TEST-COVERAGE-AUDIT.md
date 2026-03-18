# Accord Test Coverage Audit

**Generated:** 2026-03-18  
**Scope:** Full workspace — Rust (core, server, core-minimal, bot-sdk, accord-cli, standalone-demo) + Frontend (vitest + Playwright E2E)

---

## Summary Table

### Rust Crates

| Crate / Module | Unit Tests | Integration Tests | Assessment |
|---|---|---|---|
| **accord-core** | **205** (across 25 files) | — | ✅ Good |
| core/background_voice | 23 | — | ✅ Good |
| core/metadata_crypto | 28 | — | ✅ Good |
| core/p2p_voice | 30 | — | ✅ Good |
| core/double_ratchet | 9 | — | ✅ Good |
| core/sender_keys | 9 | — | ✅ Good |
| core/jitter_buffer | 11 | — | ✅ Good |
| core/membership_privacy | 9 | — | ✅ Good |
| core/srtp | 10 | — | ✅ Good |
| core/timing_privacy | 8 | — | ✅ Good |
| core/mnemonic | 9 | — | ✅ Good |
| core/build_hash | 9 | — | ✅ Good |
| core/friendship_privacy | 7 | — | ✅ Good |
| core/device_fingerprint | 5 | — | ✅ Good |
| core/release_signing | 5 | — | ✅ Good |
| core/crypto | 3 | — | ⚠️ Partial |
| core/channels | 3 | — | ⚠️ Partial |
| core/voice | 4 | — | ⚠️ Partial |
| core/session_manager | 4 | — | ⚠️ Partial |
| core/protocol | 4 | — | ⚠️ Partial |
| core/invites | 3 | — | ⚠️ Partial |
| core/push_crypto | 3 | — | ⚠️ Partial |
| core/ffi | 3 | — | ⚠️ Partial |
| core/bots | 2 | — | ⚠️ Partial |
| core/jni | 0 | — | ❌ None |
| **accord-server** | **~65** (unit) | **33** (integration) | ✅ Good overall |
| server/state | 9 | — | ⚠️ Partial (in-memory only) |
| server/validation | 19 | — | ✅ Good |
| server/relay_mesh/* | 31 (7 files) | — | ✅ Good |
| server/bot_api | 9 | — | ✅ Good |
| server/backup | 6 | — | ✅ Good |
| server/rate_limit | 9 | — | ✅ Good |
| server/permissions | 4 | — | ⚠️ Partial |
| server/push | 5 | — | ⚠️ Partial |
| server/metadata | 2 | — | ⚠️ Partial |
| server/handlers | 0 | covered by integration | ⚠️ Partial |
| server/files | 0 | 1 (upload/download) | ⚠️ Partial |
| server/admin | 0 | — | ❌ None |
| server/federation | 0 | — | ❌ None |
| server/webhooks | 0 | — | ❌ None |
| server/db/* (all) | 0 | covered by integration | ⚠️ Partial |
| server/batch_handlers | 0 | partial (node_overview) | ⚠️ Partial |
| server/models | 0 | — | ❌ None |
| server/node | 0 | — | ❌ None |
| **accord-core-minimal** | **16** | — | ✅ Good |
| **accord-bot-sdk** | 0 (2 doc-test compile checks) | — | ❌ None |
| **accord-cli** | 0 | — | ❌ None |
| **standalone-demo** | 0 | — | ❌ None (demo-only) |

### Frontend (Vitest — 87 tests, 7 test files, all passing)

| Module / File | Tests | Assessment |
|---|---|---|
| e2ee/senderKeys | ~30 tests | ✅ Good |
| e2ee/keys + x3dh + ratchet | ~20 tests | ✅ Good |
| api.ts | ~12 tests | ✅ Good |
| themes.ts | ~8 tests | ✅ Good |
| keyboard shortcuts | ~10 tests | ✅ Good |
| ProfileCard component | ~7 tests | ✅ Good |
| SearchOverlay component | partial | ⚠️ Partial |
| ws.ts (WebSocket client) | 0 | ❌ None |
| hooks/useVoice | 0 | ❌ None |
| hooks/usePresence | 0 | ❌ None |
| hooks/useReadReceipts | 0 | ❌ None |
| hooks/useTyping | 0 | ❌ None |
| hooks/useBlocking | 0 | ❌ None |
| hooks/useBookmarks | 0 | ❌ None |
| voice/webrtc | 0 | ❌ None |
| voice/relay | 0 | ❌ None |
| RelayManager | 0 | ❌ None |
| FileManager | 0 | ❌ None |
| App.tsx | 0 | ❌ None |
| AuthScreens | 0 | ❌ None |
| ChatArea | 0 | ❌ None |
| e2ee/session (key init flow) | 0 | ❌ None |
| identityStorage | 0 | ❌ None |
| notifications | 0 | ❌ None |
| crypto.ts | 0 | ❌ None |

### Integration / E2E

| Suite | Tests | Assessment |
|---|---|---|
| server/tests/integration_test.rs | 33 Rust async tests | ✅ Good |
| tests/integration/run.sh | shell script (~20 assertions) | ⚠️ Partial (requires running server) |
| desktop/frontend/e2e/full-flow.spec.ts | Playwright (~190 lines) | ⚠️ Partial |
| desktop/frontend/e2e/login.spec.ts | Playwright (mocked) | ⚠️ Partial |
| desktop/frontend/e2e/navigation.spec.ts | Playwright (~190 lines) | ⚠️ Partial |
| desktop/frontend/e2e/setup-wizard.spec.ts | Playwright (~79 lines) | ⚠️ Partial |
| desktop/frontend/e2e/ui-features.spec.ts | Playwright (~167 lines) | ⚠️ Partial |
| tests/load/* | shell load scripts (manual) | ⚠️ Not automated |

---

## Critical Untested Code Paths (Ranked by Risk)

### 🔴 Critical Risk

**1. `server/src/files.rs` — File Upload Business Logic**  
The integration test covers a basic upload/download round-trip, but unit tests are absent for:
- MIME type validation and content sniffing bypass prevention
- File size limit enforcement at the handler level (not just config)
- Filename sanitization and path traversal prevention
- Concurrent upload handling
- Storage quota enforcement per user/node

File handling is a classic attack vector in chat apps and deserves dedicated unit tests independent of the integration harness.

**2. `server/src/handlers.rs` — HTTP Request Handlers (0 unit tests)**  
All route handlers (message send/edit/delete, channel management, user profile, etc.) have zero unit tests. Coverage relies entirely on the integration test suite. This means:
- Input validation edge cases aren't tested at the unit level
- Error path behavior (malformed JSON, missing fields, oversized payloads) is untested
- Authorization logic per-endpoint is only tested by a subset of integration scenarios

**3. `server/src/db/*` — Database Layer (0 unit tests)**  
All of `db/mod.rs`, `db/node_db.rs`, `db/relay.rs`, `db/encryption.rs`, and `db/migration.rs` have zero unit tests. Risks:
- Migration correctness: no tests verify schema upgrades don't corrupt data
- `db/encryption.rs` specifically concerns at-rest encryption; no unit tests verify correctness of encrypt/decrypt cycles, key rotation, or IV reuse prevention
- SQL query correctness depends entirely on integration tests running against a live SQLite instance

**4. `server/src/federation.rs` — Federation Logic (0 tests)**  
Federation is a security boundary — an untrusted remote server communicating with your instance. Currently no unit or integration tests exist for:
- Cross-server auth token validation
- Malformed/malicious federation payloads
- Replay attack prevention in federation messages
- Permission enforcement on federated operations

**5. `server/src/admin.rs` — Admin Endpoints (0 tests)**  
Admin endpoints are high-privilege. Without tests, there's no automated check that:
- Non-admin users can't reach admin routes
- Admin-only operations (ban, wipe, promote) require proper authorization
- Admin tokens can't be forged or replayed

### 🟠 High Risk

**6. `server/src/rate_limit.rs` — Rate Limiting (9 unit tests, but no burst/edge tests)**  
Unit tests exist but they test basic token-bucket behavior. Missing:
- Tests for rate limit bypass via header manipulation (X-Forwarded-For spoofing)
- Behavior when rate limit state resets (post-window exhaustion)
- Per-endpoint limits vs global limits

**7. Frontend `ws.ts` — WebSocket Client (0 tests)**  
The WebSocket layer handles all real-time message delivery, presence, typing indicators, and voice signaling. No unit tests cover:
- Reconnection logic (exponential backoff, max retries)
- Message queuing while disconnected
- Handling of malformed server messages
- Auth token refresh during an active WebSocket session

**8. Frontend `voice/webrtc.ts` + `voice/relay.ts` + `hooks/useVoice.ts` (0 tests)**  
Voice logic is complex and brittle. No tests for:
- ICE candidate negotiation failure handling
- Peer connection teardown on member leave
- SRTP key negotiation errors
- Reconnect on network change (already tested in Rust core, but not in the TS layer)

**9. `core/jni.rs` — Android JNI Bridge (0 tests)**  
The JNI bridge is the interface between Rust core and Android. It has no tests for:
- Null pointer handling from Java side
- Memory safety for byte array passing
- Error propagation across the FFI boundary

**10. Frontend E2E Session Key Initialization (`e2ee/session.ts`)**  
The `session.ts` file orchestrates the full key initialization flow (fetch remote bundle → X3DH → store session). No tests cover:
- What happens when a pre-key bundle is missing or malformed
- Session initialization failure fallback behavior
- Stale session detection and re-initialization

### 🟡 Moderate Risk

**11. `server/src/webhooks.rs` (0 tests)**  
Webhook delivery can leak event data to external URLs if misconfigured. No tests for delivery retry logic, signature verification, or URL validation.

**12. `server/src/batch_handlers.rs` (0 unit tests)**  
Batch endpoints can amplify server load. No tests for batch size limits, partial failure handling, or per-item error isolation.

**13. Frontend `RelayManager.ts` + `FileManager.tsx` (0 tests)**  
Relay selection and file upload from the frontend are complex stateful flows with no test coverage.

**14. `server/src/push.rs` (5 unit tests, but no error path coverage)**  
Push notification delivery to mobile clients has basic tests but no coverage for failed delivery, token expiry, or platform-specific error codes.

**15. `accord-bot-sdk` (0 functional tests)**  
Only compile-check doc-tests exist. No tests for bot authentication, command dispatch, error handling, or reconnection.

---

## Recommendations (Priority Order)

### P1 — Add immediately (security-critical)

1. **`server/src/files.rs` unit tests**: Test filename sanitization, MIME type gating, size limit enforcement, and concurrent upload safety — independent of the integration suite.

2. **`server/src/db/encryption.rs` unit tests**: Verify AES-GCM at-rest encryption roundtrips, key rotation correctness, and that no IV is reused across records.

3. **`server/src/admin.rs` authorization tests**: Assert that every admin route returns 403 for non-admin tokens. Use the existing `AppState` test harness pattern from `state.rs`.

4. **`server/src/federation.rs` unit tests**: Test that malformed federation payloads are rejected, that auth tokens are validated, and that replay protection works.

### P2 — Add next (reliability-critical)

5. **Frontend `ws.ts` reconnection unit tests**: Mock the WebSocket API in jsdom and test reconnect logic, message queuing during disconnect, and token refresh mid-session. Use the existing vitest + jsdom setup.

6. **Frontend `e2ee/session.ts` unit tests**: Test full key initialization flow, missing bundle handling, and session recovery. The existing vitest crypto setup already mocks WebCrypto — extend it.

7. **`server/src/db/migration.rs` schema tests**: Run migrations on a fresh in-memory SQLite and verify the resulting schema matches expectations. This catches breaking migration bugs before deployment.

8. **`server/src/handlers.rs` unit tests for error paths**: Test at minimum: malformed JSON bodies, missing required fields, oversized payloads, and unauthorized access attempts.

### P3 — Improve coverage (quality/robustness)

9. **Frontend voice hooks (`hooks/useVoice.ts`, `voice/webrtc.ts`)**: Even lightweight unit tests for ICE failure handling and peer cleanup on leave would catch common regressions.

10. **`core/jni.rs` FFI null safety**: Add tests similar to `ffi.rs` (which already tests null safety for the C FFI) to cover the Java/Android boundary.

11. **`accord-bot-sdk` functional tests**: Replace the compile-only doc-tests with real unit tests covering auth flow, message dispatch, and reconnection.

12. **Playwright E2E expansion for file uploads**: The existing E2E suite covers login, navigation, and setup wizard but has no file attachment flows. Add at least one test for the file upload path in `ChatArea`.

13. **`server/src/rate_limit.rs` edge cases**: Test rate limit window reset, IP spoofing resistance, and behavior when the same user hits multiple endpoints simultaneously.

14. **`server/src/webhooks.rs` delivery tests**: Test URL validation, retry behavior on failure, and that webhook payloads don't leak sensitive fields.

---

## What's Well-Covered

- **Rust crypto primitives** (double ratchet, X3DH, sender keys, SRTP, metadata crypto): comprehensive unit tests in `accord-core`, covering happy paths, out-of-order messages, session serialization, and key zeroization.
- **WebSocket integration** (connect, auth, messaging, routing): covered by 5 integration tests including invalid token rejection, message routing between two clients, and WS edit/delete.
- **Registration and authentication flows**: covered by both unit tests (`validation.rs`) and integration tests (registration, duplicate key rejection, auth failure).
- **Rate limiting basics**: 9 unit tests in `rate_limit.rs` cover the token bucket algorithm.
- **Frontend E2EE crypto**: `e2ee.test.ts` and `senderKeys.test.ts` provide solid coverage of key generation, X3DH, double ratchet, and channel encryption in the TypeScript layer.
- **Relay mesh**: 31 unit tests across 7 files cover envelope signing, routing, peer management, and transport.
