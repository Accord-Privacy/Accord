# TODO.md — Accord

## NEXT — Live Testing Bugs (2026-02-22)
- [ ] **Mute/deafen sync** — ChannelSidebar and VoiceChat have independent useState, not synced. Lift to shared context.
- [ ] **Encryption zeros after logout/login** — zeros appearing in encrypted content after logout/re-login cycle
- [ ] **Message indentation bug** — 2nd messages in chat get indented incorrectly
- [ ] **User panel display name** — shows public key hash instead of display name
- [ ] **Password verification on re-login** — copy-pasting exact same password fails with "wrong password" after logout
- [ ] **Channel layout issues** — unspecified layout problems reported during VoIP testing

## Security — Critical
- [ ] **Proper channel E2EE** — Sender Keys or MLS (current `channelId + salt` is placeholder, server can derive same key) (audit #3)
- [ ] Bot API crypto — implement X25519 key exchange, AES-256-GCM encrypt, Ed25519 sign (6 TODOs in bot_api.rs)
- [ ] Client-side search for E2EE content — server search returns metadata only, frontend SearchOverlay needs local decryption search (audit #13)

## Security — Medium
- [ ] File encryption consistency — ensure noble crypto used everywhere, not mixed subtle/noble (audit #23)
- [ ] DER encoding assumes small sizes in crypto.ts (audit #24)
- [ ] Auth tokens reload on server restart — document or fix that in-memory tokens clear on restart (audit #2)
- [ ] Auto-mod on encrypted data — document limitation, consider client-side moderation hooks (audit #4)

## Features
- [ ] Landing page deployed (website/ exists, needs GitHub Pages)
- [ ] App store submissions (blocked: need Apple/Google developer accounts)
- [ ] On-device mobile testing (blocked: need physical devices)
- [ ] cargo audit in CI (audit #25)
- [ ] Message scroll-to on search result click
- [ ] Notification sounds / desktop notifications polish
- [ ] Screen sharing in voice channels
- [ ] Video calls
- [ ] Password reset endpoint (sign challenge with private key to prove ownership)

## Code Quality
- [ ] Remove old v1 bot stubs from state.rs — replaced by bot_api.rs
- [ ] Consolidate crypto path — ensure all encryption uses noble, remove any remaining subtle fallbacks
- [ ] Add frontend unit tests (currently 0 for React components)
- [ ] E2E Playwright tests for critical flows (login, send message, join node)

## Low Priority / Future
- [ ] Relay mesh for cross-relay DMs
- [ ] Federation discovery
- [ ] Sticker packs
- [ ] Scheduled messages

## Done (2026-02-22)
- [x] WebSocket reconnect loop fix
- [x] Display name in invite flow (required)
- [x] Management Node auto-creation + first-joiner admin
- [x] Logo replacement (bird logo, all icon sizes)
- [x] Recovery display name prompt removed
- [x] CSP fix for HTTP servers
- [x] Clipboard/mediaDevices crash guards
- [x] inferScheme fix (port 8443 no longer assumes HTTPS)
- [x] Avatar 404 infinite loop fix (6 files)
- [x] Voice WS envelope format fix
- [x] getUserMedia HTTPS guard
- [x] Voice panel overlap fix (inline rendering)
- [x] Windows Build badge fix

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
- [x] CSRF protection + security headers
- [x] Custom emoji support
- [x] Channel drag-and-drop reorder
- [x] Client-side encrypted search
- [x] Rich link previews
- [x] Thread/reply support
- [x] Message reactions
- [x] Message pinning
- [x] User blocking
