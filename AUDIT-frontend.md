# Accord Desktop Frontend — Security & Code Audit

**Date:** 2026-02-17  
**Scope:** All frontend source files in `desktop/frontend/`  
**Auditor:** Automated deep audit

---

## Executive Summary

The frontend has **2 CRITICAL**, **8 HIGH**, **12 MEDIUM**, and **10 LOW** findings. The most severe issues are the fundamentally broken encryption scheme (rendering E2EE meaningless) and XSS via `dangerouslySetInnerHTML`. The codebase is early-stage with significant security gaps that must be resolved before any production use.

---

## CRITICAL

### C1. Broken Encryption — Channel Keys Derived from Channel ID Alone (No Actual E2EE)
**File:** `src/crypto.ts`, lines 37–67  
**Severity:** CRITICAL  

The `deriveChannelKey()` function attempts ECDH key derivation but passes the user's **own private key** as the `public` parameter, which will always fail. The catch block falls through to `createChannelKeyFromId()`, which derives the AES key by simply SHA-256 hashing the **channel ID**:

```typescript
async function createChannelKeyFromId(channelId: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const data = encoder.encode(channelId);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  // ...
}
```

**Impact:** Every user derives the **identical** encryption key for a given channel. The server (or any party knowing the channel UUID) can decrypt all messages. This is **not end-to-end encryption** — it's obfuscation. The UI shows "🔐 E2EE" which is actively misleading.

**Fix:** Implement proper ECDH key exchange — derive shared secrets from each pair of users' public/private keys, or implement a group key distribution protocol (e.g., Sender Keys / MLS).

---

### C2. XSS via `dangerouslySetInnerHTML` on User-Controlled Content
**File:** `src/App.tsx`, lines ~2458, ~2920  
**Severity:** CRITICAL  

Message content is rendered via `dangerouslySetInnerHTML`:

```tsx
<div 
  className="message-content"
  dangerouslySetInnerHTML={{ 
    __html: notificationManager.highlightMentions(msg.content) 
  }}
/>
```

The `highlightMentions()` function in `src/notifications.ts` (line ~182) uses regex replacement to inject `<span>` tags but **does not sanitize the input first**:

```typescript
public highlightMentions(content: string): string {
  let highlighted = content;
  const usernameRegex = new RegExp(`(@${username})`, 'gi');
  highlighted = highlighted.replace(usernameRegex, '<span class="mention">$1</span>');
  // ...
  return highlighted;
}
```

A malicious message like `<img src=x onerror=alert(document.cookie)>` will execute arbitrary JavaScript. This also appears in the pinned messages panel (~line 2920).

**Impact:** Full XSS — attackers can steal tokens from `localStorage`, impersonate users, exfiltrate keys.

**Fix:** Sanitize content with DOMPurify or equivalent **before** any HTML interpolation. Better: use React's normal text rendering and wrap mentions in React elements instead of innerHTML.

---

## HIGH

### H1. Auth Token Stored in localStorage and Passed as Query Parameter
**File:** `src/App.tsx` (line ~492), `src/api.ts` (throughout)  
**Severity:** HIGH  

```typescript
localStorage.setItem('accord_token', response.token);
```

All API calls pass the token as a URL query parameter:
```typescript
`/nodes/${nodeId}?token=${encodeURIComponent(token)}`
```

**Impact:** Tokens in query strings are logged in server access logs, browser history, proxy logs, and referrer headers. Combined with the XSS above (C2), localStorage tokens are trivially exfiltrable.

**Fix:** Use `Authorization: Bearer <token>` headers instead of query parameters. Consider `httpOnly` cookies or in-memory token storage for Tauri.

---

### H2. Private Keys Stored in localStorage in Plaintext
**File:** `src/crypto.ts`, lines 170–180  
**Severity:** HIGH  

```typescript
localStorage.setItem(STORAGE_KEYS.PRIVATE_KEY, arrayBufferToBase64(privateKeyData));
```

**Impact:** Any XSS (see C2) immediately exfiltrates the user's private key. Even without XSS, localStorage is accessible to any code running in the same origin.

**Fix:** Use Tauri's secure storage APIs or the Web Crypto API's non-extractable keys. At minimum, encrypt the key with a user-derived passphrase before storage.

---

### H3. Registration Has No Password Field
**File:** `src/App.tsx`, lines ~1512–1560, `src/api.ts` line ~66  
**Severity:** HIGH  

The `RegisterRequest` type only has `username` and `publicKey` — no password. The register API call doesn't send a password:
```typescript
async register(username: string, publicKey: string): Promise<RegisterResponse> {
  const request: RegisterRequest = { username, publicKey };
```

But login requires a password. This means either registration is broken, or the server creates accounts without password authentication.

**Fix:** Add password field to registration flow and ensure server-side password hashing.

---

### H4. CSP Allows All HTTP/WS Origins
**File:** `desktop/tauri.conf.json`  
**Severity:** HIGH  

```json
"csp": "default-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' http: https: ws: wss:"
```

`connect-src http: https: ws: wss:` allows connections to **any** origin. Combined with XSS, this enables data exfiltration to attacker-controlled servers.

**Fix:** Restrict `connect-src` to the specific Accord server domain(s). Remove wildcard protocols.

---

### H5. `unsafe-inline` in CSP for Styles
**File:** `desktop/tauri.conf.json`  
**Severity:** HIGH  

`style-src 'self' 'unsafe-inline'` allows CSS injection which can be used for data exfiltration (e.g., attribute selectors leaking token characters).

**Fix:** Use nonce-based or hash-based CSP for styles instead of `unsafe-inline`.

---

### H6. WebSocket Token in URL
**File:** `src/ws.ts`, line ~88  
**Severity:** HIGH  

```typescript
const wsUrl = `${this.baseUrl}/ws?token=${encodeURIComponent(this.token)}`;
```

**Impact:** Token appears in WebSocket upgrade request URL, logged by proxies/servers.

**Fix:** Send token after connection via an auth message, or use cookies.

---

### H7. Voice Chat Sends Raw Audio Without Encryption
**File:** `src/VoiceChat.tsx`, lines ~100–115  
**Severity:** HIGH  

Voice data is base64-encoded and sent as plaintext JSON:
```typescript
ws.send(JSON.stringify({
  type: 'voice_packet',
  channel_id: channelId,
  user_id: currentUserId,
  data: base64Data
}));
```

**Impact:** No encryption on voice packets — server and network observers can reconstruct audio.

**Fix:** Encrypt voice packets with channel keys before sending, or use WebRTC with SRTP for peer-to-peer voice.

---

### H8. `scrollToMessage` Uses Unsanitized ID in CSS Selector
**File:** `src/App.tsx`, line ~664  
**Severity:** HIGH  

```typescript
const scrollToMessage = (messageId: string) => {
  const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
```

If `messageId` contains `"]`, an attacker can break out of the attribute selector and inject arbitrary CSS selectors. While limited in direct XSS impact, it can cause unexpected DOM selection.

**Fix:** Use `document.getElementById()` or escape the value properly.

---

## MEDIUM

### M1. `Math.random()` Used for Message IDs
**File:** `src/App.tsx` (multiple locations), `src/ws.ts` line ~180  
**Severity:** MEDIUM  

```typescript
id: Math.random().toString(),
// and in ws.ts:
return Math.random().toString(36).substr(2, 9);
```

**Impact:** `Math.random()` is not cryptographically secure — IDs are predictable and could collide.

**Fix:** Use `crypto.randomUUID()` for message IDs.

---

### M2. Missing Dependency Arrays in useCallback/useEffect (Stale Closures)
**File:** `src/App.tsx`  
**Severity:** MEDIUM  

`setupWebSocketHandlers` (line ~148) has `[encryptionEnabled, keyPair]` as deps but references `dmChannels`, `nodes`, `channels` from outer scope — these won't update when the callback is created, causing stale data in WebSocket handlers.

Similarly, `loadDmChannels` is called inside `setupWebSocketHandlers` but isn't in the dep array.

**Fix:** Add missing dependencies or use refs for values that change frequently.

---

### M3. Race Condition in `openDmWithUser`
**File:** `src/App.tsx`, lines ~357–367  
**Severity:** MEDIUM  

```typescript
const openDmWithUser = useCallback(async (user: User) => {
  const dmChannel = await createDmChannel(user.id);
  if (dmChannel) {
    await loadDmChannels(); // Refresh
    const dmChannelWithInfo = dmChannels.find(dm => dm.id === dmChannel.id);
```

After `loadDmChannels()`, the code reads `dmChannels` from the closure — but `setDmChannels` is async and the state won't have updated yet.

**Fix:** Use the return value from `loadDmChannels()` or use a ref.

---

### M4. Deprecated `ScriptProcessorNode` in Voice Chat
**File:** `src/VoiceChat.tsx`, line ~66  
**Severity:** MEDIUM  

`createScriptProcessor` is deprecated and runs on the main thread, causing audio glitches.

**Fix:** Use `AudioWorkletNode` instead.

---

### M5. Typing Timeouts Stored in State (Memory Leak Pattern)
**File:** `src/App.tsx`, typing indicator section  
**Severity:** MEDIUM  

`setTypingTimeouts` stores `setTimeout` IDs in React state. Each state update creates a new Map, and the cleanup effect `[typingTimeouts]` re-runs on every change, potentially clearing timeouts prematurely.

**Fix:** Use a `useRef` for timeout tracking instead of state.

---

### M6. No Input Validation on Channel Names, Node Names
**File:** `src/App.tsx`, `src/NodeDiscovery.tsx`  
**Severity:** MEDIUM  

Channel and node names are sent directly to the API without sanitization. While server should validate, defense-in-depth requires client-side validation too.

**Fix:** Validate allowed characters, length limits, and trim whitespace.

---

### M7. `document.execCommand('copy')` Deprecated Fallback
**File:** `src/App.tsx` (~line 2700), `src/NodeSettings.tsx`  
**Severity:** MEDIUM  

Uses deprecated `document.execCommand('copy')` as clipboard fallback. This also creates and immediately removes a `textarea` element in the DOM.

**Fix:** Use only `navigator.clipboard.writeText()` — in Tauri, the clipboard API is always available.

---

### M8. `highlightMentions` Regex Injection
**File:** `src/notifications.ts`, line ~182  
**Severity:** MEDIUM  

```typescript
const usernameRegex = new RegExp(`(@${username})`, 'gi');
```

If username contains regex special characters (e.g., `user.+*`), the regex breaks or matches unintended content.

**Fix:** Escape the username with a regex escape function before interpolation.

---

### M9. Notification Content Leaked in Desktop Notifications
**File:** `src/notifications.ts`, lines ~215–225  
**Severity:** MEDIUM  

```typescript
const body = message.content.length > 100 ? 
  message.content.substring(0, 100) + '...' : 
  message.content;
new Notification(title, { body, ... });
```

Decrypted message content is shown in OS-level notifications, which may be visible on lock screens.

**Fix:** Offer option to hide message content in notifications (show "New message" instead).

---

### M10. `about` Section Says "Electron" but App Uses Tauri
**File:** `src/Settings.tsx`, about section  
**Severity:** MEDIUM  

```tsx
<strong>Platform:</strong> Desktop (Electron)
```

This is a Tauri app, not Electron. Misleading for users.

**Fix:** Change to "Desktop (Tauri)".

---

### M11. No CSRF/Origin Checking on API Requests
**File:** `src/api.ts`  
**Severity:** MEDIUM  

REST API uses token-in-query-string auth with no additional CSRF protection. In a Tauri webview this is lower risk, but if the API is also accessible via browser, it's exploitable.

**Fix:** Use `Authorization` headers and validate `Origin` on the server.

---

### M12. `index.html` Missing CSP Meta Tag
**File:** `index.html`  
**Severity:** MEDIUM  

The HTML file has no CSP meta tag. The CSP is only set in `tauri.conf.json`, meaning if the frontend is served outside Tauri (e.g., `vite dev`), there's no CSP at all.

**Fix:** Add a `<meta http-equiv="Content-Security-Policy">` tag to `index.html` as a fallback.

---

## LOW

### L1. Excessive `console.log` Statements
**Files:** `src/App.tsx`, `src/ws.ts`, `src/VoiceChat.tsx`, `src/crypto.ts`  
**Severity:** LOW  

Dozens of `console.log` and `console.warn` calls remain, including logging of WebSocket messages which may contain sensitive data:
```typescript
console.log('WebSocket message:', msg);
console.log('Received WebSocket message:', message);
```

**Fix:** Remove or gate behind a debug flag.

---

### L2. Mock Data Shipped in Production
**File:** `src/App.tsx`, lines 20–30  
**Severity:** LOW  

`MOCK_SERVERS`, `MOCK_CHANNELS`, `MOCK_USERS`, `MOCK_MESSAGES` are hardcoded and used as fallback when server is unavailable. These pollute the production bundle.

**Fix:** Move to a separate dev/test module or remove entirely.

---

### L3. Stub Functions for Editing State
**File:** `src/App.tsx`, lines ~72–77  
**Severity:** LOW  

```typescript
const setEditingMessageId = (_: string | null) => {}; // stub
const setEditingContent = (_: string) => {}; // stub  
```

These stubs make the edit UI non-functional while still rendering edit buttons. This is confusing to users.

**Fix:** Either implement editing or remove the UI elements.

---

### L4. `NotificationSettings` Imports Unused `notificationManager`
**File:** `src/NotificationSettings.tsx`, line 2  
**Severity:** LOW  

`notificationManager` is imported but only used in `testSound` and `clearAllUnreads` via type-unsafe casts:
```typescript
(notificationManager as any).playNotificationSound();
```

**Fix:** Expose `playNotificationSound` publicly or remove the cast.

---

### L5. VoiceChat Auto-Connects on Mount Without User Confirmation
**File:** `src/VoiceChat.tsx`, lines ~275–279  
**Severity:** LOW  

```typescript
useEffect(() => {
  connectToVoice();
  return () => { disconnectFromVoice(); };
}, []);
```

Empty dependency array means this runs once on mount but `connectToVoice` and `disconnectFromVoice` are not in deps (React lint warning). Also auto-requesting microphone without explicit user action may fail in some browsers.

**Fix:** Add proper deps and require explicit user action before requesting mic access.

---

### L6. `forceUpdate` Anti-Pattern
**File:** `src/App.tsx`  
**Severity:** LOW  

```typescript
const [forceUpdate, setForceUpdate] = useState(0);
setForceUpdate(prev => prev + 1); // Trigger re-render
```

Used to force re-renders for notification badge updates. This is a code smell.

**Fix:** Derive notification state reactively or use a proper state management solution.

---

### L7. No Rate Limiting on Client-Side API Calls
**File:** `src/api.ts`  
**Severity:** LOW  

No client-side throttling/debouncing on API calls (except search). Rapid clicking could flood the server.

**Fix:** Add debouncing to mutation operations.

---

### L8. `loadFiles` Effect Missing Proper Dependencies
**File:** `src/FileManager.tsx`, line ~182  
**Severity:** LOW  

```typescript
useEffect(() => {
  loadFiles();
}, [channelId, isVisible]);
```

`loadFiles` is not in the dependency array and references `isVisible` from closure.

**Fix:** Add `loadFiles` to deps or use `useCallback` with proper deps.

---

### L9. No Error Boundary
**Files:** All components  
**Severity:** LOW  

No React Error Boundary exists. An unhandled error in any component will crash the entire app.

**Fix:** Add a top-level `ErrorBoundary` component.

---

### L10. Package.json — Minimal Dependencies (Positive Note, Minor Issue)
**File:** `package.json`  
**Severity:** LOW  

Dependency footprint is excellent (only React + Vite). However, there are no security-related dependencies that should be present (e.g., DOMPurify for the XSS issue in C2).

**Fix:** Add `dompurify` (or `isomorphic-dompurify`) as a dependency for HTML sanitization.

---

## Summary Table

| ID | Severity | Category | File | Issue |
|----|----------|----------|------|-------|
| C1 | CRITICAL | Security/Crypto | crypto.ts | Fake E2EE — key derived from channel ID |
| C2 | CRITICAL | Security/XSS | App.tsx, notifications.ts | dangerouslySetInnerHTML on user content |
| H1 | HIGH | Security | api.ts, App.tsx | Token in query params + localStorage |
| H2 | HIGH | Security/Crypto | crypto.ts | Private keys in localStorage plaintext |
| H3 | HIGH | Security | App.tsx, api.ts | Registration has no password |
| H4 | HIGH | Security | tauri.conf.json | CSP allows all origins for connect-src |
| H5 | HIGH | Security | tauri.conf.json | unsafe-inline in style CSP |
| H6 | HIGH | Security | ws.ts | WebSocket token in URL |
| H7 | HIGH | Security | VoiceChat.tsx | Voice packets unencrypted |
| H8 | HIGH | Security | App.tsx | CSS selector injection in scrollToMessage |
| M1 | MEDIUM | Security | App.tsx, ws.ts | Math.random() for IDs |
| M2 | MEDIUM | Bug | App.tsx | Stale closures in WS handlers |
| M3 | MEDIUM | Bug | App.tsx | Race condition in openDmWithUser |
| M4 | MEDIUM | Deprecation | VoiceChat.tsx | ScriptProcessorNode deprecated |
| M5 | MEDIUM | Bug | App.tsx | Typing timeouts in state |
| M6 | MEDIUM | Security | App.tsx, NodeDiscovery.tsx | No input validation |
| M7 | MEDIUM | Deprecation | App.tsx, NodeSettings.tsx | execCommand('copy') deprecated |
| M8 | MEDIUM | Security | notifications.ts | Regex injection in username |
| M9 | MEDIUM | Privacy | notifications.ts | Decrypted content in OS notifications |
| M10 | MEDIUM | Bug | Settings.tsx | Says "Electron" not "Tauri" |
| M11 | MEDIUM | Security | api.ts | No CSRF protection |
| M12 | MEDIUM | Security | index.html | No CSP meta tag |
| L1 | LOW | Practice | Multiple | Excessive console.log |
| L2 | LOW | Practice | App.tsx | Mock data in production |
| L3 | LOW | Bug | App.tsx | Stub editing functions |
| L4 | LOW | Practice | NotificationSettings.tsx | Unsafe cast on notificationManager |
| L5 | LOW | Bug | VoiceChat.tsx | Auto-connect without user action |
| L6 | LOW | Practice | App.tsx | forceUpdate anti-pattern |
| L7 | LOW | Practice | api.ts | No client-side rate limiting |
| L8 | LOW | Bug | FileManager.tsx | Missing useEffect deps |
| L9 | LOW | Practice | All | No Error Boundary |
| L10 | LOW | Practice | package.json | Missing DOMPurify dependency |

---

## Recommendations (Priority Order)

1. **Fix encryption immediately** (C1) — implement real key exchange or remove E2EE claims
2. **Fix XSS** (C2) — add DOMPurify, stop using dangerouslySetInnerHTML for user content
3. **Move tokens to headers** (H1, H6) — stop using query parameters for auth
4. **Secure key storage** (H2) — use Tauri secure storage or non-extractable CryptoKeys
5. **Tighten CSP** (H4, H5) — restrict connect-src, remove unsafe-inline
6. **Encrypt voice** (H7) — or use WebRTC
7. **Add Error Boundary** (L9) — prevent full app crashes
8. **Remove console.log** (L1) — or use a proper logging library with levels
9. **Fix stale closures** (M2) — audit all useCallback/useEffect deps
10. **Add registration password** (H3) — align with login flow
