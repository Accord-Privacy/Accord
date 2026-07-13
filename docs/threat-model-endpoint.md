# Endpoint Threat Model — the Compromised / Seized Device

Accord's E2EE guarantees that the relay (and any network observer) cannot read
message content or sensitive metadata. This document is about the *other* end of
that guarantee: what happens when the **decrypting device itself** is the target
— seized at a border, stolen, imaged by forensic tooling, or subject to a legal
order compelling the vendor to ship a modified client (client-side scanning).

E2EE is definitionally unable to protect a fully compromised endpoint: whoever
controls the device controls the plaintext at the moment it is decrypted. The
engineering goal is therefore not "make compromise impossible" (impossible) but:

1. **Shrink what a compromise yields** — minimize plaintext at rest and how long
   it survives.
2. **Limit blast radius** — one compromise should not equal total history.
3. **Resist *mandated* compromise** — make covert, vendor-compelled scanning
   structurally hard to impose without detection.

Status legend: ✅ shipped · 🔶 designed, not built · 💭 option under consideration.

---

## 1. What is already true

- ✅ **Relay is a dumb pipe** (architecture invariant #1). Even under legal
  compulsion the server has no plaintext to hand over and no place to run a
  scanner over content.
- ✅ **Two-factor at-rest keys** (`f8ff2e5`, audit L1). Local encrypted stores
  derive their key from `HKDF(password, salt = OS-keyring Storage Master Key)`.
  Recovering anything at rest requires **both** the password (knowledge) and the
  device's keyring secret (possession). A locked, seized device cannot yield
  history without the password; a coerced/leaked password is useless without the
  device's keyring. See `desktop/frontend/src/e2ee/storageKey.ts`.
- ✅ **Identity private key** wrapped with PBKDF2 (100k, random salt); **Double
  Ratchet** session state keyed off the identity key (high-entropy).
- ✅ **Forward secrecy for DMs**: Double Ratchet makes old ciphertext
  undecryptable once the ratchet advances. (The local plaintext cache that backs
  history is now behind the two-factor at-rest key, above.)
- ✅ **Reproducible builds** (`REPRODUCIBLE-BUILDS.md`) + **relay build-hash
  attestation allowlist** — the raw material for scanning-resistance (§5).
- ✅ **Microphone scoped** (`3fc1377`): capture is granted only while in a voice
  call; camera always denied. Shrinks the "silent surveillance" surface.

---

## 2. Shrink what's on the device

### 2.1 Disappearing messages (per-node / per-channel) — 🔶

**Requirement (from product):** must NOT be forced globally — "not all chats need
to be secure." Configurable at **node** level with **per-channel override**.

Design:

- **Where the TTL lives.** A channel's retention is metadata. Since the relay is
  a dumb pipe and metadata privacy (NMK) is a goal, the TTL is a *channel
  setting* propagated to members, not a relay policy. Proposed: an optional
  `retention_seconds` on the channel config (encrypted into the NMK metadata
  bundle so the relay doesn't learn per-channel retention), with a node-level
  default that a channel inherits unless overridden.
- **Enforcement is client-side and total.** On receipt and on load, any message
  older than its channel's TTL is dropped from **every** local store, not just
  the message list:
  - the messages DB / in-memory list,
  - the own-message + DM plaintext cache (`ownMessagesRef` / `saveOwnMessages`),
  - the search index,
  - notification history.
  This is the single most important property: *a seized device cannot yield what
  no longer exists.* A disappearing-messages feature that forgets the caches is
  security theater.
- **Relay-side sweep (defense in depth).** The relay also deletes ciphertext
  past a channel's retention so it can't hoard blobs, using `secure_delete` +
  periodic `VACUUM` so deletion is not forensically recoverable.
- **Sender authority + clock.** TTL starts at send time (message timestamp).
  Clients enforce on their own clock; a lying peer can only affect their own
  copy. No reliance on synchronized clocks for correctness, only approximate
  expiry.
- **UX:** node setting "Default message retention: Off / 24h / 7d / 30d",
  channel setting "Inherit / Off / custom". A visible indicator on channels with
  retention on, so users know a channel is ephemeral.

Open question for you: should enabling retention on a channel **retroactively**
expire existing older messages, or only apply going forward? (Recommend
retroactive — otherwise "turn on disappearing" leaves a silent backlog.)

### 2.2 Secure deletion & at-rest lock — 🔶

- SQLite `PRAGMA secure_delete = ON` + periodic `VACUUM`.
- Zeroize key material in memory and lock the encrypted stores on screen-lock /
  idle timeout (re-derive on unlock). Ties into the SMK: drop the cached SMK on
  lock so nothing is decryptable while locked.
- Move long-term key custody from the JS heap into the Rust core where memory can
  actually be zeroized (JS cannot). Larger lift; real payoff.

---

## 3. Limit blast radius

- ✅ Per-conversation key compartmentalization already holds cryptographically
  (sender keys per channel, DR sessions per peer). 🔶 Make the *local stores*
  match, so partial compromise ≠ full history.
- 🔶 **Device revocation that rotates.** Revoking a device should trigger
  sender-key + NMK rotation everywhere (same as a kick), so a revoked/seized
  device stops being able to decrypt new traffic. Kick-rotation exists;
  NMK-on-kick and device-revocation rotation are the gaps.

---

## 4. Duress features — 💭 (decision needed)

The user asked to see these. They have real value for high-risk users and real
ways to go subtly wrong; they are opt-in, never default.

### 4.1 Panic-wipe — recommended, lowest risk
A shortcut / action that immediately destroys local key material and encrypted
stores: logout + `destroyStorageMasterKey(userId)` (already implemented — deletes
the keyring SMK, after which every at-rest store is unreadable even before the
blobs are erased) + erase the encrypted blobs + `secure_delete` vacuum. Because
wiping the SMK alone renders all stores undecryptable, this is fast and robust.
No deception surface. **Recommend building this first.**

### 4.2 Decoy / duress password — powerful, higher risk
A second password unlocks a *decoy* identity showing innocuous content; the real
profile stays hidden. Caveats that make this dangerous if done naively:

- **Deniability must be real.** If the real encrypted blob is still present on
  disk, a forensic examiner sees two ciphertext stores and infers a hidden one —
  the decoy provides no plausible deniability and may *increase* suspicion.
  Doing this properly needs hidden-volume-style indistinguishability (all
  storage looks like one blob; the duress key decrypts a subset). That is a
  significant cryptographic design, not a UI toggle.
- **Coercion dynamics.** Decoys can escalate risk if an adversary knows the app
  offers them ("show me the real one"). This is a documented critique of the
  feature class; Signal deliberately does not ship it.

Recommendation: **panic-wipe now**; treat decoy/duress-password as a separate
design spike with its own review, only if the target user population needs it.

---

## 5. Resisting *mandated* compromise (the legislation angle)

This is where Accord is structurally, not just cryptographically, well placed.
Client-side-scanning mandates work by compelling a vendor to ship a modified
client that scans plaintext on-device before encryption. Accord's defenses:

- ✅ **Reproducible builds + build-hash attestation.** Anyone can verify the
  shipped binary matches the public source — i.e. contains no scanner. A covert
  scanning mandate requires shipping a *modified* client quietly; reproducibility
  makes "quietly" detectable. The relay already maintains a build-hash allowlist;
  a public, append-only transparency log of released build hashes (💭) would let
  users detect a targeted malicious build.
- ✅ **AGPLv3 + no single distribution channel.** If a jurisdiction compels a
  store build, users can build from source or sideload, and forks are legal by
  license. There is no single lever that covers all clients.
- ✅ **Dumb relay.** Nothing to scan server-side even under compulsion.
- 💭 **Warrant canary** in the repo/releases.

**Action:** document reproducible-builds-as-scanning-resistance explicitly in
`SECURITY.md` — it is the concrete answer to "what if we're ordered to scan," and
most of the machinery already exists.

---

## 6. Screenshot / screen-capture protection — 🔶

Scope and honest limits up front: on desktop this deters casual capture (the OS
screenshot tool, screen-share, some screen recorders) but **cannot** stop a
determined adversary — a photo of the screen, a compromised OS, or an
accessibility/where-supported gap defeats it. It is a friction feature, not a
security boundary; it must be documented as such so users don't over-trust it.

Approach:

- **Desktop (Tauri/WebKitGTK):** set the OS "content protection" / exclude-from-
  capture flag on the window where the platform supports it
  (`set_content_protected` on macOS/Windows via the window handle; on Linux/X11
  and Wayland support is partial-to-absent — must degrade honestly and tell the
  user it's unavailable rather than imply protection).
- **Per-node / per-channel policy:** like disappearing messages, a node/channel
  can *request* screenshot protection; the client enforces where the OS allows.
  Surface a clear "screenshots blocked where your OS supports it" indicator, and
  never claim protection on platforms that can't deliver it.
- 💭 **Screenshot-attempt notification** (like Signal/Snapchat "X took a
  screenshot") is only possible where the OS emits an event (macOS does; most
  Linux does not), so it can only ever be best-effort and must be labeled so.

---

## 7. Recommended sequencing

1. ✅ At-rest two-factor keys (done) · ✅ mic scoping (done).
2. **Panic-wipe** (small, high value, no deception surface).
3. **Disappearing messages** (per-node default + per-channel override) with
   cache-aware, total local deletion — the biggest "shrink what's on the device"
   win.
4. **Screenshot protection** (desktop content-protection flag, honestly scoped).
5. **Device-revocation rotation** + secure-delete/at-rest-lock.
6. Document scanning-resistance in `SECURITY.md`; consider a build-hash
   transparency log.
7. Decoy/duress-password only as a separate, reviewed design spike.

Mobile parity for all of the above is deferred with the rest of mobile.
