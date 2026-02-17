# Accord Rust Codebase Security Audit

**Date:** 2026-02-17  
**Scope:** All Rust source files across core, server, core-minimal, accord-cli, standalone-demo, desktop  
**Auditor:** Automated code review

---

## Executive Summary

The Accord codebase is an early-stage encrypted communications platform. While the architecture demonstrates good security intent (zero-knowledge server, E2E encryption), several **critical** and **high** severity issues exist that would need resolution before any production deployment. The most severe issues involve authentication bypasses, unsafe code in crypto, and weak cryptographic practices in the demo/minimal crates.

---

## CRITICAL Findings

### C1. Authentication Completely Bypassed for File Endpoints
**Severity:** CRITICAL  
**File:** `server/src/handlers.rs` (line ~1890)  
**Code:**
```rust
async fn extract_user_from_request(_state: &SharedState) -> Result<Uuid, anyhow::Error> {
    // This is a placeholder implementation
    // TODO: Replace with proper authentication
    Ok(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")?)
}
```
**Impact:** All file endpoints (`upload_file_handler`, `download_file_handler`, `list_channel_files_handler`, `delete_file_handler`) use this function, meaning **any unauthenticated request is treated as a hardcoded user**. An attacker can upload, download, list, and delete any file without authentication.

---

### C2. Authentication Bypass — No Password Verification
**Severity:** CRITICAL  
**File:** `server/src/state.rs` (line ~66)  
**Code:**
```rust
pub async fn authenticate_user(
    &self,
    username: String,
    _password: String, // <-- password is completely ignored
) -> Result<AuthToken, String> {
    let user = match self.db.get_user_by_username(&username).await { ... };
    let token = format!("tok_{}", Uuid::new_v4().simple());
    // ... issues token with NO password check
```
**Impact:** Anyone who knows a username can obtain a valid auth token. There is no password, challenge-response, or signature verification whatsoever.

---

### C3. Unsafe Code in Crypto Module — Unsound `array_ref!` Macro
**Severity:** CRITICAL  
**File:** `core/src/crypto.rs` (lines 10-18)  
**Code:**
```rust
macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            unsafe fn as_array<T>(slice: &[T]) -> &[T; $len] {
                &*(slice.as_ptr() as *const [_; $len])
            }
            unsafe { as_array(&$arr[$offset..]) }
        }
    }};
}
```
**Impact:** This macro is **unsound** — it performs a raw pointer cast without verifying the slice length matches `$len`. While the call sites happen to check lengths first, any future misuse could cause undefined behavior. The `arrayref` crate or `TryInto` should be used instead.

---

### C4. `delete_message_handler` REST Endpoint Uses Token as UUID, Not Validated Against State
**Severity:** CRITICAL  
**File:** `server/src/handlers.rs` (line ~1920)  
**Code:**
```rust
fn extract_user_id_from_token(token: &str) -> Result<Uuid, anyhow::Error> {
    // This is a placeholder implementation
    Uuid::parse_str(token).map_err(|e| anyhow::anyhow!("Invalid token format: {}", e))
}
```
**Impact:** The REST `DELETE /messages/:id` endpoint parses the token query parameter directly as a UUID rather than validating it against the token store. An attacker can delete any message by passing any valid user UUID as the token. This is distinct from the WebSocket path which uses proper token validation.

---

### C5. `edit_message_handler` REST Endpoint Accepts User ID from Request Body
**Severity:** CRITICAL  
**File:** `server/src/handlers.rs`, `server/src/models.rs`  
**Code:**
```rust
pub struct EditMessageRequest {
    pub user_id: Uuid,        // <-- client supplies the user ID
    pub encrypted_data: String,
}
```
**Impact:** The edit message REST endpoint trusts the `user_id` from the request body rather than extracting it from a validated auth token. Any client can edit any user's messages by supplying a different `user_id`.

---

## HIGH Findings

### H1. Session Key Derivation Uses Same Material for Both Keys
**Severity:** HIGH  
**File:** `core/src/crypto.rs` (lines ~99-103)  
**Code:**
```rust
// Derive session key and chain key from shared secret
// In production, use HKDF for proper key derivation
session_key.copy_from_slice(&key_material[0..32]);
chain_key.copy_from_slice(&key_material[0..32]); // <-- SAME as session_key
```
**Impact:** Session key and chain key are identical, defeating any ratcheting or forward secrecy mechanism. If one key is compromised, both are compromised.

---

### H2. No Forward Secrecy — Static Session Keys
**Severity:** HIGH  
**File:** `core/src/crypto.rs`  
**Impact:** The `message_number` is incremented on encrypt but the key material never changes. The comment says "advance message number for forward secrecy" but incrementing a counter without ratcheting the key provides zero forward secrecy. Compromise of the session key reveals all past and future messages.

---

### H3. Auth Tokens Not Cleaned Up — Memory Leak / Token Accumulation
**Severity:** HIGH  
**File:** `server/src/state.rs`  
**Impact:** Auth tokens are stored in-memory in a `HashMap` and never removed (the `cleanup_expired_tokens` method in `db.rs` is a no-op returning `Ok(0)`). Over time this leaks memory and old tokens remain valid indefinitely (only the 24h expiry check prevents use, but the entries remain).

---

### H4. Token Passed in Query String — URL Logging Risk
**Severity:** HIGH  
**File:** `server/src/handlers.rs` (all endpoints), `server/src/main.rs`  
**Impact:** All authentication uses `?token=...` in the URL query string. This means tokens appear in server access logs, browser history, proxy logs, and HTTP Referer headers. Tokens should be in the `Authorization` header.

---

### H5. CORS Allows Any Origin
**Severity:** HIGH  
**File:** `server/src/main.rs` (line ~112)  
**Code:**
```rust
CorsLayer::new()
    .allow_methods(Any)
    .allow_headers(Any)
    .allow_origin(Any),
```
**Impact:** Any website can make authenticated requests to the Accord server via the user's browser (combined with token-in-URL, this is particularly dangerous).

---

### H6. Path Traversal Check in `files.rs` May Be Bypassable
**Severity:** HIGH  
**File:** `server/src/files.rs` (lines ~75-78)  
**Code:**
```rust
if !file_path.starts_with(&self.config.storage_dir) {
    return Err(anyhow!("Invalid file path: path traversal detected"));
}
```
**Impact:** `Path::starts_with` does component-based comparison, which is generally safe. However, the `storage_path` stored in `store_file` uses `to_string_lossy()` on a relative path (`./data/files/UUID`). If `read_file` receives an absolute path while `storage_dir` is relative, or vice versa, the check may not match correctly. The path should be canonicalized before comparison.

---

### H7. Voice Encryption Key Not Rotated
**Severity:** HIGH  
**File:** `core/src/voice.rs`, `core/src/crypto.rs`  
**Impact:** `VoiceKey` sequence increments forever but the underlying AES key never changes. A single key compromise exposes all voice data for the entire session. Voice keys should be periodically rotated.

---

## MEDIUM Findings

### M1. `VoiceSpeakingState` Allows Spoofing Other Users
**Severity:** MEDIUM  
**File:** `server/src/handlers.rs` (WS handler for `VoiceSpeakingState`)  
**Code:**
```rust
WsMessageType::VoiceSpeakingState { channel_id, user_id, speaking } => {
    // Broadcasts user_id from the message, not from sender_user_id
    let broadcast = serde_json::json!({ ... "user_id": user_id ... });
```
**Impact:** A malicious client can send `VoiceSpeakingState` with any `user_id`, spoofing another user's speaking state.

---

### M2. `serialize_compressed` Ambiguity — No Format Indicator
**Severity:** MEDIUM  
**File:** `core/src/protocol.rs` (line ~340)  
**Impact:** `serialize_compressed` returns compressed data for large messages and uncompressed for small ones, but there's no flag in the output to indicate which format was used. The deserializer has no way to know whether to decompress.

---

### M3. Duplicate `PROTOCOL_VERSION` Constants
**Severity:** MEDIUM  
**File:** `core/src/lib.rs` (`PROTOCOL_VERSION: u32 = 1`) vs `core/src/protocol.rs` (`PROTOCOL_VERSION: u8 = 1`)  
**Impact:** Two different constants with different types. Changing one won't affect the other, leading to potential version mismatch bugs.

---

### M4. `BotManager` Interactions Vector Grows Unboundedly
**Severity:** MEDIUM  
**File:** `core/src/bots.rs`  
**Impact:** `self.interactions.push(...)` is called on every bot interaction with no cleanup or size limit, leading to unbounded memory growth.

---

### M5. `calculate_energy` Division by Zero on Empty Samples
**Severity:** MEDIUM  
**File:** `core/src/voice.rs` (line ~127)  
**Code:**
```rust
(sum_squares / samples.len() as f64).sqrt() as f32 / i16::MAX as f32
```
**Impact:** If `samples` is empty, `samples.len()` is 0, causing division by zero → `NaN` propagation.

---

### M6. Validation Functions Use `len()` Not Grapheme Cluster Count
**Severity:** MEDIUM  
**File:** `server/src/validation.rs`  
**Impact:** All length checks use byte length (`.len()`), not character or grapheme count. A username with multi-byte UTF-8 chars (e.g., emoji) would hit the byte limit much sooner than expected. For `validate_username` this is fine since it restricts to ASCII, but `validate_bio`, `validate_display_name`, etc. accept any Unicode.

---

### M7. `get_channel_category` Passes `Uuid::nil()` to Find Category
**Severity:** MEDIUM  
**File:** `server/src/state.rs` (line ~270)  
**Code:**
```rust
pub async fn get_channel_category(&self, category_id: Uuid) -> ... {
    let categories = self.db.get_node_categories(Uuid::nil()) // <-- wrong
```
**Impact:** This always queries categories for a nil UUID node, which will never find anything. The function is effectively broken.

---

### M8. `now()` Function Panics on System Clock Before Epoch
**Severity:** MEDIUM  
**File:** `server/src/state.rs`, `server/src/db.rs`  
**Code:**
```rust
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap() // panics if clock is before epoch
        .as_secs()
}
```
**Impact:** Will panic if the system clock is set before the Unix epoch. Unlikely but represents a crash vector.

---

### M9. `unwrap()` Calls in Database Parsing Code
**Severity:** MEDIUM  
**File:** `server/src/db.rs` (multiple locations in `get_channel_messages_paginated`, `get_pinned_messages`, `get_message_thread`, `get_node_categories`, etc.)  
**Code:**
```rust
let message_id = Uuid::parse_str(&row.get::<String, _>("id")).unwrap();
```
**Impact:** Corrupt database data will cause server panics rather than graceful error handling. All `.unwrap()` calls in row parsing should use `?` with proper error propagation.

---

### M10. `delete_channel` Always Returns Error
**Severity:** MEDIUM  
**File:** `server/src/state.rs`  
**Code:**
```rust
pub async fn delete_channel(...) -> Result<(), String> {
    // ...permission checks...
    // TODO: Add actual delete_channel method to database layer
    Err("Channel deletion not yet implemented in database layer".to_string())
}
```
**Impact:** The delete channel endpoint is wired up in the router but always fails. This is dead/incomplete code exposed to users.

---

### M11. `update_node` Always Returns Error
**Severity:** MEDIUM  
**File:** `server/src/state.rs`  
**Code:**
```rust
Err("Node update not yet implemented in database layer".to_string())
```
**Impact:** Same as M10 — exposed but non-functional endpoint.

---

## LOW Findings

### L1. `println!` Used for Production Logging in Bot System
**Severity:** LOW  
**File:** `core/src/bots.rs` (multiple locations)  
**Impact:** Uses `println!()` instead of structured logging via `tracing`/`log`.

---

### L2. `tracing_subscriber::fmt::init()` Called in Library `init()`
**Severity:** LOW  
**File:** `core/src/lib.rs` (line ~19)  
**Impact:** Library code should not initialize the global tracing subscriber — that's the application's responsibility. This will panic if called twice.

---

### L3. XOR "Encryption" in `core-minimal` and `standalone-demo`
**Severity:** LOW (demo code, but worth noting)  
**File:** `core-minimal/src/crypto_minimal.rs`, `standalone-demo/src/main.rs`  
**Impact:** Uses XOR cipher which is trivially breakable. Clearly marked as demo-only, but should have prominent warnings and ideally be feature-gated out of any release build.

---

### L4. `generate_invite_code` Potential Infinite Loop
**Severity:** LOW  
**File:** `core/src/invites.rs` (line ~287)  
**Code:**
```rust
fn generate_invite_code(&self) -> String {
    loop {
        // generate random 8-char code
        if !self.invites.contains_key(&code) {
            return code;
        }
    }
}
```
**Impact:** If the invite map is extremely full (astronomically unlikely with 8 chars from 55-char alphabet), this loops forever. Practically not a concern but violates the principle of bounded execution.

---

### L5. `check_node_permission` Helper Is Defined But Never Called
**Severity:** LOW  
**File:** `server/src/handlers.rs`  
**Impact:** Dead code — permission checks are done inline instead of using this helper, leading to inconsistent patterns.

---

### L6. Broadcast Channel Size of 100 May Drop Messages
**Severity:** LOW  
**File:** `server/src/handlers.rs` (line ~840)  
**Code:**
```rust
let (tx, mut rx) = broadcast::channel::<String>(100);
```
**Impact:** If a client falls behind by 100 messages, subsequent sends will cause `RecvError::Lagged` and messages are silently dropped.

---

### L7. Voice Key Sequence Reuse After Overflow
**Severity:** LOW  
**File:** `core/src/crypto.rs`  
**Impact:** `voice_key.sequence` is `u64` — overflow is practically impossible, but there's no check. After 2^64 packets the nonce would repeat, breaking AES-GCM security.

---

### L8. Rate Limiter Uses `Instant` — Not Testable with Time Mocking
**Severity:** LOW  
**File:** `server/src/rate_limit.rs`  
**Impact:** The sliding window uses `Instant::now()` which cannot be mocked for testing. The test file acknowledges this limitation.

---

### L9. `rate_limit` Module Imported But Not Used in Server Handlers
**Severity:** LOW  
**File:** `server/src/lib.rs` exports `rate_limit`, but no handler applies rate limiting  
**Impact:** Rate limiting is implemented but never applied to any endpoint.

---

### L10. Desktop `build.rs` Is Trivial
**Severity:** LOW  
**File:** `desktop/build.rs`  
**Impact:** Just calls `tauri_build::build()`. Not a bug, just noting it's minimal.

---

### L11. CLI Stores Private Key as Public Key Bytes
**Severity:** LOW  
**File:** `accord-cli/src/main.rs` (line ~195)  
**Code:**
```rust
fn generate_and_save_keypair() -> Result<Vec<u8>> {
    // ...
    save_private_key(&key_pair.public_key)?; // saves public key as "private key"
    Ok(key_pair.public_key)
}
```
**Impact:** The identity key file contains the public key, not the private key. The comment acknowledges `ring` doesn't expose private key bytes, but the function name and file path are misleading.

---

### L12. CLI Chat Uses Deterministic Session Key from Channel ID
**Severity:** LOW (but HIGH if used in production)  
**File:** `accord-cli/src/main.rs`  
**Code:**
```rust
let session_key = accord_core::crypto::SessionKey {
    key_material: {
        let mut key = [0u8; 32];
        let channel_bytes = channel_id.as_bytes();
        for (i, &byte) in channel_bytes.iter().enumerate() {
            if i < 32 { key[i] = byte; }
        }
        key
    },
    chain_key: [42u8; 32], // Fixed chain key
```
**Impact:** Session key is derived from the channel ID string — anyone who knows the channel ID can decrypt all messages. Not a real key exchange.

---

## Suggestions

### S1. Implement Proper Authentication
Replace the placeholder auth with proper challenge-response or signature-based authentication using the user's registered public key. At minimum, add password hashing (argon2/bcrypt).

### S2. Move Tokens to Authorization Header
Use `Authorization: Bearer <token>` instead of query string parameters.

### S3. Use `arrayref` Crate or `TryInto`
Replace the unsafe `array_ref!` macro with safe alternatives.

### S4. Implement Key Ratcheting
Use the Double Ratchet algorithm (or Signal Protocol library) for actual forward secrecy.

### S5. Add Token Expiry Cleanup
Run periodic cleanup of expired auth tokens from the in-memory map.

### S6. Restrict CORS in Production
Configure CORS to only allow specific origins.

### S7. Add Rate Limiting to Endpoints
Wire up the existing `RateLimiter` to the Axum middleware layer.

### S8. Canonicalize File Paths
Use `std::fs::canonicalize()` for path traversal checks in `files.rs`.

### S9. Use Structured Error Types
Replace `String` error types in `state.rs` with proper error enums for better error handling.

### S10. Add Input Validation to Handlers
The `register_handler` does basic empty checks but doesn't call the validation functions from `validation.rs`. Wire them together.
