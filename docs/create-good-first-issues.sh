#!/usr/bin/env bash
# Create "good first issue" GitHub issues for Accord-Privacy/Accord
# Requires: gh CLI authenticated with a PAT that has Issues: Read and write

set -euo pipefail

REPO="Accord-Privacy/Accord"

echo "Creating good first issues for $REPO..."

# ─── Issue 1: accord-bot-sdk unit tests ───────────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add unit tests for accord-bot-sdk: auth flow, message dispatch, and reconnection" \
  --label "good first issue,help wanted" \
  --body "## Summary

The \`accord-bot-sdk\` crate currently has **zero functional unit tests** — only two compile-check doc-tests that verify code compiles but assert no behavior. This is a great first contribution because the crate is self-contained, small, and well-scoped.

## Why This Matters

The bot SDK is the public API for anyone building bots on Accord. If auth, message dispatch, or reconnection logic silently breaks, bot developers have no safety net.

## What Needs to Be Done

Add real unit tests to \`crates/accord-bot-sdk/src/lib.rs\` covering:

1. **Auth flow** — bot authenticates with a valid token; invalid token is rejected with the correct error
2. **Message dispatch** — incoming messages are routed to the correct handler; unknown message types don't panic
3. **Reconnection** — SDK retries on a dropped connection and surfaces an error after max retries
4. **Error propagation** — handler errors surface to the caller, not silently swallowed

## Relevant Files

- \`crates/accord-bot-sdk/src/lib.rs\` — main SDK implementation and current doc-tests
- \`crates/accord-bot-sdk/Cargo.toml\` — add test-only deps here
- \`crates/accord-core/src/double_ratchet.rs\` — example of project test style

## Acceptance Criteria

- [ ] At least 6 new \`#[test]\` functions in \`accord-bot-sdk\`
- [ ] Tests cover: auth success, auth failure, dispatch to handler, unknown message type, reconnect retry, error propagation
- [ ] \`cargo test -p accord-bot-sdk\` passes with no warnings
- [ ] No bare \`unwrap()\` in test code — use \`assert!(result.is_ok())\` or \`matches!\`

## Getting Started

\`\`\`bash
git clone https://github.com/Accord-Privacy/Accord
cd Accord
cargo test -p accord-bot-sdk   # see what currently exists
cat crates/accord-bot-sdk/src/lib.rs
\`\`\`

Feel free to ask questions here — happy to help!"

echo "✓ Issue 1 created"

# ─── Issue 2: useVoice hook unit tests ────────────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add unit tests for useVoice hook: ICE failure handling and peer cleanup" \
  --label "good first issue,help wanted" \
  --body "## Summary

\`desktop/frontend/src/hooks/useVoice.ts\` has **zero unit tests**. This hook manages WebRTC peer connections, ICE negotiation, and cleanup when members leave — complex stateful logic that's easy to break silently.

## Why This Matters

Voice is a core Accord feature. Regressions in peer cleanup or ICE failure handling cause audio to cut out or peers to 'ghost' in voice channels. A few targeted unit tests would catch the most common failure modes.

## What Needs to Be Done

Using the existing **vitest + jsdom** test setup (see \`desktop/frontend/src/__tests__/\`):

1. **ICE failure** — when ICE candidate exchange fails, the hook should emit an error state (not hang indefinitely)
2. **Peer leave cleanup** — when a peer disconnects, their RTCPeerConnection is closed and removed from state
3. **Mute toggle** — \`toggleMute()\` flips the local audio track enabled state correctly
4. **Hook teardown** — on component unmount, all peer connections are closed

Mock \`RTCPeerConnection\` using vitest's mock utilities — no real WebRTC needed.

## Relevant Files

- \`desktop/frontend/src/hooks/useVoice.ts\` — the hook to test
- \`desktop/frontend/src/__tests__/\` — existing test examples to follow
- \`desktop/frontend/src/e2ee/\` — examples of how crypto is mocked in tests

## Acceptance Criteria

- [ ] At least 4 new test cases covering the scenarios above
- [ ] Tests use vitest mocks for \`RTCPeerConnection\` — no real network calls
- [ ] \`npx vitest run\` passes with no new failures
- [ ] Tests run in CI (they're automatically included if placed in \`__tests__/\`)

## Getting Started

\`\`\`bash
cd desktop/frontend
npm install
npx vitest run  # run existing tests to confirm setup works
cat src/hooks/useVoice.ts
ls src/__tests__/  # see existing test examples
\`\`\`"

echo "✓ Issue 2 created"

# ─── Issue 3: core/jni.rs null safety tests ───────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add null-safety tests for core/jni.rs Android JNI bridge" \
  --label "good first issue,help wanted" \
  --body "## Summary

\`crates/accord-core/src/jni.rs\` — the Rust/Java bridge for Android — has **zero tests**. The C FFI layer (\`ffi.rs\`) already has null-safety tests as a model. The JNI bridge needs the same treatment.

## Why This Matters

The JNI bridge is the interface between Rust core and the Android app. Null pointers from the Java side, incorrectly sized byte arrays, or dropped exceptions across the FFI boundary are all possible. Without tests, these bugs only surface on Android devices.

## What Needs to Be Done

Following the pattern in \`crates/accord-core/src/ffi.rs\` (which already tests C FFI null safety):

1. **Null byte array input** — passing null/empty bytes to JNI functions should return an error, not panic
2. **Oversized input** — passing a byte array larger than the expected max should be rejected gracefully
3. **Error propagation** — when an internal Rust error occurs, it is surfaced as a Java exception (not swallowed)
4. **Round-trip** — a JNI encrypt/decrypt round-trip produces the original plaintext

## Relevant Files

- \`crates/accord-core/src/jni.rs\` — code to test
- \`crates/accord-core/src/ffi.rs\` — follow this test style (already has null-safety tests)
- \`crates/accord-core/Cargo.toml\` — add \`jni\` test dep if needed

## Acceptance Criteria

- [ ] At least 4 \`#[test]\` functions in \`jni.rs\` or a sibling \`jni_tests.rs\`
- [ ] Covers: null input, oversized input, error propagation, round-trip
- [ ] \`cargo test -p accord-core jni\` passes
- [ ] No unsafe code added in tests without a safety comment

## Getting Started

\`\`\`bash
cd Accord
cargo test -p accord-core  # confirm existing tests pass
cat crates/accord-core/src/jni.rs
cat crates/accord-core/src/ffi.rs  # use as a template
\`\`\`"

echo "✓ Issue 3 created"

# ─── Issue 4: Playwright E2E file upload test ─────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add Playwright E2E test for file upload in ChatArea" \
  --label "good first issue,help wanted" \
  --body "## Summary

The existing Playwright E2E suite covers login, navigation, setup wizard, and UI features — but **has no test for file attachments**. File upload is a meaningful user flow that touches the server's \`files.rs\` handler, the frontend \`FileManager\`, and the chat rendering pipeline.

## Why This Matters

File upload is a common attack surface in chat apps (path traversal, MIME sniffing, size limits). An E2E test that uploads a file and verifies it appears in the chat confirms the full stack works and acts as a regression guard.

## What Needs to Be Done

Add a new test file \`desktop/frontend/e2e/file-upload.spec.ts\` (or extend \`ui-features.spec.ts\`) that:

1. Logs in as a test user (follow the pattern in \`e2e/login.spec.ts\`)
2. Navigates to a channel
3. Attaches a small test file (e.g., a PNG fixture) via the file picker button
4. Verifies the file appears as an attachment in the message list
5. Verifies the attachment is downloadable (clicking the link returns HTTP 200)

A fixture file for testing can be placed at \`desktop/frontend/e2e/fixtures/test-image.png\`.

## Relevant Files

- \`desktop/frontend/e2e/\` — existing E2E tests to follow
- \`desktop/frontend/e2e/full-flow.spec.ts\` — most complete example
- \`desktop/frontend/src/components/FileManager.tsx\` — frontend file upload component
- \`server/src/files.rs\` — server-side handler (for context)

## Acceptance Criteria

- [ ] New test file added under \`desktop/frontend/e2e/\`
- [ ] Test uploads a file and asserts it appears in the chat message list
- [ ] Test verifies the attachment link is accessible
- [ ] \`npx playwright test\` passes including the new test (in CI or locally)
- [ ] A small test fixture file (PNG or TXT, <10KB) is included

## Getting Started

\`\`\`bash
cd desktop/frontend
npm install
npx playwright install  # install browser binaries
cat e2e/login.spec.ts   # see how auth is set up in E2E tests
cat e2e/ui-features.spec.ts  # see existing UI interaction patterns
\`\`\`"

echo "✓ Issue 4 created"

# ─── Issue 5: rate_limit edge case tests ──────────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add edge-case unit tests for server/src/rate_limit.rs: IP spoofing and window reset" \
  --label "good first issue,help wanted" \
  --body "## Summary

\`server/src/rate_limit.rs\` has 9 unit tests covering basic token-bucket behavior — but is missing tests for the security-relevant edge cases: **IP spoofing via header manipulation** and **rate limit state after a window reset**.

## Why This Matters

Rate limiting is a DDoS defense. If an attacker can bypass it by forging \`X-Forwarded-For\` headers, or if the limiter doesn't properly reset after a window expires, the protection is meaningless. These are exactly the cases that should be explicitly tested.

## What Needs to Be Done

Add tests to \`server/src/rate_limit.rs\` (in the existing \`#[cfg(test)]\` block) covering:

1. **X-Forwarded-For spoofing** — a request with a spoofed \`X-Forwarded-For\` header should NOT bypass the rate limit; the real peer IP should be used (or the header validated against a trusted proxy list)
2. **Window reset** — after a rate limit window expires, the request count resets and the client can make requests again
3. **Multi-endpoint limits** — hitting the limit on endpoint A does not consume quota for endpoint B (if per-endpoint limits exist)
4. **Concurrent requests** — rapid concurrent requests from the same IP are all counted correctly (no TOCTOU race)

## Relevant Files

- \`server/src/rate_limit.rs\` — the file to add tests to (existing \`#[cfg(test)]\` block already present)
- Look at the existing 9 tests in that file as a style guide

## Acceptance Criteria

- [ ] At least 3 new \`#[tokio::test]\` (or \`#[test]\`) functions in \`rate_limit.rs\`
- [ ] Tests cover: spoofed header behavior, window reset, and at least one of multi-endpoint or concurrency
- [ ] \`cargo test -p accord-server rate_limit\` passes
- [ ] Each test has a comment explaining what attack/scenario it guards against

## Getting Started

\`\`\`bash
cd Accord
cargo test -p accord-server rate_limit  # run existing rate limit tests
cat server/src/rate_limit.rs             # read the code + existing tests
\`\`\`"

echo "✓ Issue 5 created"

# ─── Issue 6: CONTRIBUTING.md ─────────────────────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Write a CONTRIBUTING.md guide for new contributors" \
  --label "good first issue,help wanted,documentation" \
  --body "## Summary

Accord has no \`CONTRIBUTING.md\`. New contributors have to guess how to set up their environment, run tests, format code, and submit PRs. A good contributing guide dramatically lowers the barrier to first contribution.

## Why This Matters

Accord is a privacy-focused project — the community and external contributions are important. Without a contributing guide, potential contributors bounce when they hit the first setup hurdle. This is a high-impact, low-code task.

## What Needs to Be Done

Create \`CONTRIBUTING.md\` at the repo root covering:

1. **Development setup** — prerequisites (Rust stable, Node 18+, \`cargo\`, \`npm\`), how to build each component
2. **Running tests** — \`cargo test --workspace\`, \`npx vitest run\`, Playwright setup
3. **Code style** — \`cargo fmt\`, \`cargo clippy\`, ESLint/Prettier for frontend
4. **Pre-push checklist** — mention \`scripts/pre-push-qa.sh\`
5. **PR process** — branch naming, commit message format, what reviewers look for
6. **Issue labels** — brief explanation of \`good first issue\`, \`help wanted\`, \`bug\`, etc.
7. **Security policy** — point to (or briefly summarize) responsible disclosure process

Keep it honest and practical. Contributors will trust a short, accurate guide more than a long, aspirational one.

## Relevant Files

- \`README.md\` — pull in setup steps that are already documented there
- \`scripts/pre-push-qa.sh\` — reference this in the pre-push section
- \`Cargo.toml\` / \`desktop/frontend/package.json\` — for build commands

## Acceptance Criteria

- [ ] \`CONTRIBUTING.md\` exists at repo root
- [ ] Covers all 7 sections listed above
- [ ] A fresh contributor can follow it cold (no assumed knowledge beyond basic git/Rust/Node)
- [ ] Commands in code blocks are copy-paste accurate (tested manually)
- [ ] Links to \`CODE_OF_CONDUCT.md\` if one exists, or notes that one is forthcoming

## Getting Started

Read \`README.md\` first — you can reuse relevant setup instructions. Then follow the sections above. No Rust or TypeScript expertise required; this is a writing task."

echo "✓ Issue 6 created"

# ─── Issue 7: webhooks.rs delivery tests ──────────────────────────────────────
gh issue create --repo "$REPO" \
  --title "Add unit tests for server/src/webhooks.rs: URL validation and delivery retry" \
  --label "good first issue,help wanted" \
  --body "## Summary

\`server/src/webhooks.rs\` has **zero tests**. Webhook delivery can leak event data to external URLs if misconfigured, and retry logic that's wrong can either spam external services or silently drop events.

## Why This Matters

Webhooks are an outbound data path — misconfigured URL validation could allow SSRF (Server-Side Request Forgery) attacks where an attacker registers a webhook pointing to an internal service. Tests here are both a reliability and a security guard.

## What Needs to Be Done

Add unit tests to \`server/src/webhooks.rs\` (or a sibling \`webhooks/tests.rs\`) covering:

1. **URL validation** — webhook URLs pointing to localhost, \`169.254.x.x\` (AWS metadata), or private RFC-1918 ranges should be rejected (SSRF prevention)
2. **Valid URL accepted** — a well-formed public HTTPS URL is accepted
3. **Retry on failure** — when the first delivery attempt returns a 5xx, the delivery is retried (up to the configured max)
4. **No retry on 4xx** — a 400/404 response is a permanent failure; no retry should be attempted
5. **Payload structure** — the webhook payload doesn't include sensitive fields (e.g., raw message keys, tokens)

For HTTP mocking, use \`wiremock\` or \`mockito\` (check \`Cargo.toml\` for what's already available).

## Relevant Files

- \`server/src/webhooks.rs\` — the file to test
- \`server/src/rate_limit.rs\` — example of existing test patterns in the server crate
- \`server/Cargo.toml\` — check available test dependencies

## Acceptance Criteria

- [ ] At least 4 new test functions covering the scenarios above
- [ ] URL validation test explicitly checks at least one private IP range and localhost
- [ ] Retry logic test uses a mock HTTP server (not a real external URL)
- [ ] \`cargo test -p accord-server webhooks\` passes
- [ ] Each test has a comment noting the security scenario it guards

## Getting Started

\`\`\`bash
cd Accord
cargo test -p accord-server  # confirm existing tests pass
cat server/src/webhooks.rs   # read the code
cat server/Cargo.toml        # check available test deps (wiremock, mockito, etc.)
\`\`\`"

echo "✓ Issue 7 created"
echo ""
echo "All 7 good first issues created successfully!"
