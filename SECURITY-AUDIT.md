# Accord Security Audit

**Date:** 2026-03-06  
**Scope:** Frontend (`desktop/frontend/src/`), Server (`server/src/`)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 4 |
| LOW | 3 |
| INFO | 4 |

---

## Findings

### H1 — Admin Token Exposed in URL Query Parameters
**Severity:** HIGH  
**Location:** `server/src/admin.rs:45`  
**Description:** The admin panel accepts `?admin_token=<TOKEN>` as a query parameter. This means the admin token appears in:
- Browser history
- Server access logs
- Referer headers
- Proxy/CDN logs

The embedded admin HTML also stores the token in `sessionStorage` and sends it via query param in WebSocket/fetch URLs.

**Recommendation:** Remove query parameter authentication for admin endpoints. Only accept `X-Admin-Token` header. Update the embedded admin HTML to use headers for all requests.

**Status:** ⚠️ Fixed below — removed query param auth path from `validate_admin_token`.

---

### M1 — No Content-Security-Policy Header
**Severity:** MEDIUM  
**Location:** `server/src/main.rs` (missing)  
**Description:** No CSP header is set anywhere in the server. This means if an XSS vector is found, there's no defense-in-depth to prevent script execution, data exfiltration, or loading external resources.

**Recommendation:** Add a strict CSP header as middleware:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' wss:; frame-ancestors 'none'
```

---

### M2 — Auth Tokens Stored in localStorage
**Severity:** MEDIUM  
**Location:** `desktop/frontend/src/App.tsx:312`, `desktop/frontend/src/api.ts:1086`  
**Description:** Auth tokens (`accord_auth_token`, `accord_token_<host>`) are stored in localStorage. If any XSS vector exists, tokens can be exfiltrated. In the Tauri desktop app this is less of a concern (no third-party scripts), but the web fallback path is vulnerable.

**Mitigation already in place:** DOMPurify sanitization on all rendered markdown content reduces XSS risk significantly.

**Recommendation:** For the web path, consider httpOnly cookies for session tokens. For Tauri, migrate tokens to the OS keyring (similar to what `identityStorage.ts` does for identity keys).

---

### M3 — Channel Encryption is Not True E2EE
**Severity:** MEDIUM  
**Location:** `desktop/frontend/src/crypto.ts:433-445`  
**Description:** Channel/group message encryption derives the key deterministically from `channelId + fixed salt`. Anyone who knows the channel ID can derive the key. The server stores channel IDs, so the server can decrypt all group messages. This is already documented in code comments as "PLACEHOLDER — NOT real E2EE."

**Recommendation:** This is a known limitation. Implement Sender Keys (Signal protocol) or MLS for real group E2EE. In the meantime, ensure the documentation is clear that only DMs have true E2EE (Double Ratchet).

---

### M4 — Rate Limiting Gaps
**Severity:** MEDIUM  
**Location:** `server/src/handlers.rs`, `server/src/rate_limit.rs`  
**Description:** Rate limiting is only applied to:
- Registration (`/register`) — IP-based
- Authentication (`/auth`) — IP-based

The following sensitive endpoints have **no rate limiting**:
- Message sending (via WebSocket) — the `ActionType::Message` exists but grep shows no `rate_limiter.check()` call for message handlers
- File uploads — `ActionType::FileUpload` exists but may not be enforced
- Invite creation/use
- Profile updates
- Key bundle publishing

**Recommendation:** Add rate limiting checks to WebSocket message handlers and file upload endpoints. The `ActionType` enum and `RateLimiter` infrastructure already exist — just wire them in.

---

### L1 — Private Key Wrapping Passphrase is Weak
**Severity:** LOW  
**Location:** `desktop/frontend/src/crypto.ts:197-201` (`getKeyPassphrase`)  
**Description:** The passphrase used to encrypt private keys in localStorage is `accord-key-wrap:<public_key_hash_or_token>`. The public key hash is… public. An attacker with localStorage access (via XSS) already has both the encrypted key AND the public key hash, so they can derive the wrapping passphrase and decrypt the private key.

**Mitigation:** The password-based storage path (`saveKeyWithPassword`) uses the actual user password, which is stronger. The token-based path is only for session convenience.

**Recommendation:** Document that the session-key wrapping is convenience encryption only, not a security boundary. The real protection is the password-encrypted slot.

---

### L2 — Admin Token Timing Attack
**Severity:** LOW  
**Location:** `server/src/admin.rs:40`  
**Description:** Admin token comparison uses `==` (string equality), which may be vulnerable to timing attacks. An attacker could theoretically determine the token character-by-character.

**Recommendation:** Use constant-time comparison (`subtle::ConstantTimeEq` or equivalent).

---

### L3 — Error Messages Leak Internal Details
**Severity:** LOW  
**Location:** `server/src/handlers.rs` (various)  
**Description:** Several error responses include raw error strings from database operations (e.g., `format!("Failed to get presence: {}", err)`). These could leak internal schema or path information to attackers.

**Recommendation:** Return generic error messages to clients; log detailed errors server-side only.

---

### I1 — XSS Protection: DOMPurify Properly Applied
**Severity:** INFO  
**Location:** `desktop/frontend/src/markdown.ts`  
**Description:** All `dangerouslySetInnerHTML` usage goes through `renderMessageMarkdown()`, which:
1. Parses markdown via `marked`
2. Sanitizes with DOMPurify using an explicit allowlist of tags and attributes
3. Properly escapes text nodes before inserting mention highlights

Both usages in `ChatArea.tsx:431` and `Modals.tsx:412` use this function. ✅

---

### I2 — SQL Injection: Properly Parameterized
**Severity:** INFO  
**Location:** `server/src/db/`  
**Description:** All database queries use sqlx parameterized queries. Dynamic query building (e.g., `db/relay.rs:555`, `db/mod.rs:1860`) only interpolates static column names (`"name = ?"`) — never user input. Values are always bound via `.bind()`. ✅

---

### I3 — Path Traversal: Properly Protected
**Severity:** INFO  
**Location:** `server/src/files.rs:93-107`  
**Description:** `FileHandler` canonicalizes both the storage directory and requested file path, then verifies the file path starts with the storage directory. Tests cover `../../../etc/passwd` traversal attempts. Files are stored by UUID, not user-supplied filenames. ✅

---

### I4 — Auth Enforcement: Comprehensive
**Severity:** INFO  
**Location:** `server/src/handlers.rs`  
**Description:** All state-modifying and data-access endpoints call `extract_user_from_token()`. Unauthenticated endpoints are limited to:
- `health_handler` — public health check (no sensitive data)
- `register_handler` — registration (rate-limited by IP)
- `auth_handler` — login (rate-limited by IP)
- `invite_preview_handler` — shows node name for invite links (no sensitive data)
- `build_info_handler` — version info
- `get_node_icon_handler` / `get_user_avatar_handler` / `get_emoji_image_handler` — public media assets

Admin endpoints use separate `validate_admin_token()` check. ✅

---

## Fixes Applied

### Fix H1: Remove admin token from query parameters

Removed the query parameter path from `validate_admin_token`. Admin authentication now only works via the `X-Admin-Token` header.
