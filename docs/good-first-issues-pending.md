# Good First Issues — Pending Creation

**Status:** Ready to run. Blocked on GitHub PAT needing `Issues: Read and write` permission.  
**Token holder:** Schwanky-Dev — regenerate the fine-grained PAT at https://github.com/settings/tokens with Issues read+write.  
**Run with:** `bash docs/create-good-first-issues.sh`

---

## Issue List

1. Add unit tests for `accord-bot-sdk` (auth, dispatch, reconnect)
2. Add unit tests for `hooks/useVoice.ts` (ICE failure, peer cleanup)
3. Add unit tests for `core/jni.rs` (null safety, FFI boundary)
4. Add Playwright E2E test for file upload flow
5. Add unit tests for `server/src/rate_limit.rs` edge cases (IP spoofing, window reset)
6. Write Contributing Guide (`CONTRIBUTING.md`)
7. Add unit tests for `server/src/webhooks.rs` (URL validation, delivery retry)
