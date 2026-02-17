# Device Fingerprinting — Full Transparency Document

## Purpose

Device fingerprinting in Accord exists for **one purpose only**: ban enforcement. When a Node admin bans a user, the fingerprint hash prevents that user from circumventing the ban by simply creating a new keypair.

## What Signals Are Collected

The following signals are collected from your device:

| # | Signal | Example | Why |
|---|--------|---------|-----|
| 1 | **Device ID** | Android ID, Windows MachineGuid | Unique device identifier |
| 2 | **Screen Resolution** | `1920x1080` | Hardware characteristic |
| 3 | **Timezone** | `America/New_York` | Environment signal |
| 4 | **GPU Renderer** | `NVIDIA GeForce RTX 3080` | Hardware characteristic |
| 5 | **OS Version** | `Windows 11 23H2` | Environment signal |
| 6 | **Locale** | `en-US` | Environment signal |

## How They're Combined

1. All six signals are concatenated with null byte (`\0`) separators to prevent ambiguity
2. The concatenated string is hashed using **SHA-256**
3. The result is a 64-character hexadecimal string

```
SHA-256( device_id + \0 + screen_resolution + \0 + timezone + \0 + gpu_renderer + \0 + os_version + \0 + locale )
```

## What Leaves Your Device

**Only the 64-character hex hash string.** The raw signal values (your screen resolution, GPU name, timezone, etc.) are **never transmitted** to any server. The hash is a one-way function — the original signals cannot be recovered from it.

## How It's Stored

- The fingerprint hash is stored **encrypted** with the Node's metadata key
- Only the Node admin can decrypt and access it
- The relay server stores it as an opaque encrypted blob
- It is associated with your Node membership record

## What It's Used For

- **Ban enforcement only** — when you are banned from a Node, your fingerprint hash is recorded alongside the ban
- When someone attempts to join a Node, their fingerprint hash is checked against the ban list
- It is **NOT** used for:
  - Tracking
  - Analytics
  - Advertising
  - Cross-Node identification
  - Any purpose other than ban enforcement

## Scope

- Fingerprint hashes are **strictly per-Node**
- There is **no global fingerprint database**
- Fingerprint hashes are **NOT shared between Nodes**
- If you are banned from Node A, Node B has no knowledge of your fingerprint from Node A
- There is **no federation of bans** — each Node's ban list is completely independent

## Node Admin Choice

- Node admins can choose whether to **require** fingerprinting for membership
- If a Node does not require fingerprinting, you can join without providing a fingerprint hash
- The fingerprint hash field is nullable — it's always optional at the protocol level

## Open Source Audit

The fingerprinting code is fully open source. You can audit the exact function that computes your fingerprint hash:

- **Source file:** `core/src/device_fingerprint.rs`
- **Function:** `DeviceFingerprint::compute_fingerprint_hash()`
- **Disclosure function:** `DeviceFingerprint::fingerprint_disclosure()` — returns a human-readable explanation shown to users before fingerprinting

The code is licensed under AGPL-3.0-or-later. Anyone can verify exactly what signals are collected and how they are processed.
