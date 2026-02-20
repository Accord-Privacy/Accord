# TODO.md — Accord

## NEXT
- [ ] Split App.tsx (~5200 lines) into modular components
- [ ] TLS by default (in progress — auto-generated self-signed certs)

## High Priority
- [ ] Proper channel E2EE — Sender Keys or MLS (current `channelId + salt` is placeholder)
- [x] ~~Bot API v2 server + frontend~~ (shipped)
- [ ] N+1 member/role API — batch endpoint instead of per-member queries

## Medium Priority
- [ ] Landing page / marketing site
- [ ] App store submissions (blocked: need Apple/Google developer accounts)
- [ ] On-device mobile testing (blocked: need Gage's devices)
- [ ] Frontend build in QA script (npx not in PATH for pre-push-qa.sh)

## Low Priority
- [ ] Remove old bot API v1 code (after v2 implemented)
- [ ] Relay mesh for cross-relay DMs (future)
- [ ] Federation discovery (future)

## Done (recent)
- [x] Full codebase audit — 25 issues found and fixed
- [x] Auth tokens → Authorization headers
- [x] Crypto zero-key fallback fixed
- [x] Stale closure fix (refs pattern)
- [x] Server security fixes (password bypass, WS buffer, rate limiter)
- [x] Input validation + XSS sanitization
- [x] Integration test migration (DirectMessage → ChannelMessage)
- [x] All 27 integration tests passing, CI green
- [x] iOS + Android mobile app scaffolds
