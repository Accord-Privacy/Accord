# TODO.md — Accord

## NEXT
- [ ] Add Accord logo/favicon to frontend (index.html, login screen, sidebar header)
- [ ] Wire frontend to batch API endpoints (in progress)
- [ ] Token refresh mutex — prevent multiple simultaneous 401 re-auth races (audit #12)

## Security — Critical
- [ ] **Proper channel E2EE** — Sender Keys or MLS (current `channelId + salt` is placeholder, server can derive same key) (audit #3)
- [ ] Bot API crypto — implement X25519 key exchange, AES-256-GCM encrypt, Ed25519 sign (6 TODOs in bot_api.rs)
- [ ] CSRF protection — add CSRF tokens or SameSite cookie policy (audit #6)
- [ ] Client-side search for E2EE content — server search returns metadata only, frontend SearchOverlay needs local decryption search (audit #13)

## Security — Medium
- [ ] Message ordering — add monotonic sequence number per channel instead of relying on timestamps (audit #22)
- [ ] File encryption consistency — ensure noble crypto used everywhere, not mixed subtle/noble (audit #23)
- [ ] DER encoding assumes small sizes in crypto.ts (audit #24)
- [ ] Auth tokens reload on server restart — document or fix that in-memory tokens clear on restart (audit #2)
- [ ] Auto-mod on encrypted data — document limitation, consider client-side moderation hooks (audit #4)

## Features
- [ ] Landing page deployed (website/ exists, needs hosting — GitHub Pages?)
- [ ] App store submissions (blocked: need Apple/Google developer accounts)
- [ ] On-device mobile testing (blocked: need Gage's devices)
- [ ] GitHub Pages or Cloudflare Pages for website/
- [ ] cargo audit in CI (audit #25 — install and add to workflow)
- [ ] Message scroll-to on search result click (TODO in App.tsx:1885)
- [ ] Notification sounds / desktop notifications polish
- [ ] Thread/reply support in channels
- [ ] Message reactions (emoji)
- [ ] Typing indicators in DMs (currently only channels)
- [ ] User blocking
- [ ] Channel categories drag-and-drop reorder
- [ ] Rich link previews for shared URLs

## Code Quality
- [ ] Frontend build in QA script verified working (nvm sourcing added, needs CI test)
- [ ] Remove old v1 bot stubs from state.rs (lines 1519-1540) — replaced by bot_api.rs
- [ ] Consolidate crypto path — ensure all encryption uses noble, remove any remaining subtle fallbacks
- [ ] Add frontend unit tests (currently 0 for React components)
- [ ] E2E Playwright tests for critical flows (login, send message, join node)

## Low Priority / Future
- [ ] Relay mesh for cross-relay DMs
- [ ] Federation discovery
- [ ] Custom emoji support
- [ ] Sticker packs
- [ ] Screen sharing in voice channels
- [ ] Video calls
- [ ] Message pinning
- [ ] Scheduled messages

## Done (2026-02-19/20)
- [x] TLS by default with auto-generated self-signed certs
- [x] Bot API v2 — server + frontend (airgapped commands)
- [x] Batch API endpoints (members, channels, overview)
- [x] App.tsx split into modular components (5257 → 3233 lines)
- [x] Landing page created (website/)
- [x] Full codebase audit — 25 issues cataloged
- [x] Auth tokens → Authorization headers (audit #1)
- [x] Crypto zero-key fallback fixed
- [x] Stale closure fix with refs pattern (audit #11)
- [x] Server security fixes (password bypass, WS buffer, rate limiter cleanup) (audit #5, #20, #21)
- [x] Input validation + XSS sanitization (audit #18, #19)
- [x] Integration test migration (DirectMessage → ChannelMessage) (audit #10)
- [x] N+1 member roles → batch endpoint (audit #14)
- [x] Bot API rewritten from stubs to full implementation (audit #15)
- [x] App.tsx split (audit #17)
- [x] QA script nvm fix
- [x] iOS + Android mobile app scaffolds
