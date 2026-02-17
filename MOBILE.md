# Accord Mobile Architecture

## Overview

The iOS app uses the same `accord-core` Rust crate as the desktop (Tauri) app, compiled as a static library and bridged to Swift via C FFI.

```
┌─────────────────────────────────────────────┐
│  Swift UI (SwiftUI)                         │
├─────────────────────────────────────────────┤
│  AccordCore.swift  (safe Swift wrapper)     │
├─────────────────────────────────────────────┤
│  AccordCoreFFI     (C module map)           │
├─────────────────────────────────────────────┤
│  accord-core       (Rust static library)    │
│  - X3DH key agreement                       │
│  - Double Ratchet sessions                  │
│  - AES-256-GCM encryption                   │
│  - Session management                       │
└─────────────────────────────────────────────┘
```

## Directory Structure

```
mobile/ios/
├── Package.swift              # SPM package definition
├── build-rust.sh              # Cross-compile script
├── Accord/
│   └── AccordCore.swift       # Swift wrapper (KeyMaterial, SessionManager)
└── AccordCore/
    ├── module.modulemap       # Clang module for C FFI
    └── include/
        └── accord_core.h     # C header (mirrors core/src/ffi.rs)
```

## FFI Design

### Memory Management
- **Opaque pointers**: `AccordKeyMaterial*`, `AccordSessionManager*` — created/destroyed via `_generate`/`_new` and `_free` functions
- **AccordBuffer**: Owned byte buffer returned across FFI. Caller MUST call `accord_buffer_free()`. The Swift wrapper handles this in `consumeBuffer()` with `defer`.
- **No leaks**: Every `_generate`/`_new` has a corresponding `_free`. Every `AccordBuffer` is freed after consumption.

### Data Serialization
- Complex types (PreKeyBundle, DoubleRatchetMessage, X3DHInitialMessage) cross the FFI as bincode-serialized bytes
- Simple keys are raw 32-byte arrays

### Null Safety
- All FFI functions handle null pointers gracefully (return null or error codes)
- Swift wrapper throws `AccordError` on null returns

## Building

### Prerequisites
```bash
# Install iOS targets
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

### Build
```bash
cd mobile/ios
./build-rust.sh release    # or debug
```

This produces:
- `build/aarch64-apple-ios/libaccord_core.a` — device
- `build/aarch64-apple-ios-sim/libaccord_core.a` — simulator
- `build/AccordCore.xcframework` — universal XCFramework

### Xcode Integration
1. Add `AccordCore.xcframework` to your Xcode project
2. The SPM package in `mobile/ios/` can be used as a local package dependency
3. `import AccordCoreFFI` for raw C access, or use the `AccordCore` Swift module

## Usage (Swift)

```swift
import AccordCore

// Generate keys
let keys = KeyMaterial(oneTimePrekeys: 10)
let identityKey = try keys.identityKey  // Data (32 bytes)
let bundle = try keys.publishableBundle // Data (upload to server)

// Establish session (Alice side)
let session = SessionManager()
let initialMsg = try session.initiateSession(
    keyMaterial: keys,
    peerUserId: "bob",
    channelId: "general",
    theirBundle: bobBundleData,
    firstMessage: "Hello Bob!".data(using: .utf8)!
)
// Send initialMsg to Bob...

// Encrypt subsequent messages
let encrypted = try session.encrypt(
    peerUserId: "bob",
    channelId: "general",
    plaintext: "How are you?".data(using: .utf8)!
)

// Decrypt received messages
let plaintext = try session.decrypt(
    peerUserId: "bob",
    channelId: "general",
    ciphertext: receivedData
)
```

## Security Notes

- All key material is zeroized on drop (Rust side uses `zeroize` crate)
- Session keys use the Double Ratchet protocol for forward secrecy
- X3DH provides deniable authentication
- AES-256-GCM with associated data (message headers bound to ciphertext)
- One-time prekeys are consumed and cannot be reused
