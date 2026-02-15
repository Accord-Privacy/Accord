# Accord Architecture Overview

## 🎯 **Core Philosophy: Discord + Signal**

Accord combines Discord's rich community features with Signal's uncompromising privacy model:

- **Discord functionality**: Servers, channels, voice chat, bots, rich messaging
- **Signal security**: End-to-end encryption, zero-knowledge server, forward secrecy
- **Open source**: Fully auditable, community-controlled

## 🏗️ **System Architecture**

```
[Client Apps] <---> [Relay Server] <---> [Client Apps]
     ^                    ^                     ^
  E2E Crypto         Encrypted Blobs      E2E Crypto
  Full Features      Routing Only         Full Features
```

### **Zero-Knowledge Server Design**
- Server **never has keys** to decrypt user content
- Server only routes encrypted messages between clients
- All encryption/decryption happens **client-side**
- Server stores only encrypted blobs and routing metadata

## 📁 **Core Library Structure**

### **`core/` - Cryptography & Protocol**
- **`crypto.rs`** - End-to-end encryption (AES-256-GCM, X25519 key agreement)
- **`voice.rs`** - Real-time encrypted voice with low latency
- **`channels.rs`** - Hybrid lobby/private channel system
- **`bots.rs`** - Privacy-preserving bot integration
- **`invites.rs`** - Private invite system with quality controls
- **`protocol.rs`** - Network message formats and validation

### **`server/` - Relay Infrastructure** 
- Message routing without content access
- User authentication and session management
- Voice packet relay for group calls
- File upload/download coordination
- Bot command routing

### **`desktop/` - Tauri Application**
- Rust backend + TypeScript frontend
- Native system integration
- Cross-platform (Windows, macOS, Linux)
- Auto-updater for security patches

### **`mobile/` - Native Applications**
- iOS: Swift + Rust core (FFI)
- Android: Kotlin + Rust core (JNI)
- Platform-specific audio/notification integration
- Background voice support

## 🔒 **Security Architecture**

### **Text Message Encryption**
1. **Key Agreement**: X25519 ECDH between clients
2. **Message Encryption**: AES-256-GCM with unique nonce
3. **Forward Secrecy**: Keys rotate with each message
4. **Authentication**: Message signatures prevent tampering

### **Voice Encryption**
1. **Session Keys**: Generated per voice channel session
2. **Real-Time Encryption**: AES-256-GCM for each voice packet
3. **Sequence Numbers**: Prevent replay attacks
4. **Key Rotation**: New keys every 30 seconds or 10,000 packets

### **Identity Verification**
- **Safety Numbers**: Like Signal, for out-of-band verification
- **QR Code Verification**: Visual key fingerprint comparison
- **Device Trust**: Manage trusted devices per user

## 🎙️ **Voice System Design**

### **Hybrid Voice Architecture**
- **Small Groups (≤4)**: Direct P2P encrypted connections
- **Large Groups (5+)**: Server-relayed encrypted packets
- **Server Mixing**: Optional server-side mixing (server can't decrypt individual streams)

### **Audio Processing Pipeline**
```
[Microphone] → [Noise Reduction] → [Opus Encode] → [AES Encrypt] → [Network]
[Speakers] ← [Audio Mixing] ← [Opus Decode] ← [AES Decrypt] ← [Network]
```

### **Voice Activity Detection**
- Client-side VAD to minimize network usage
- Configurable sensitivity and hangover
- Speaking state synchronization

## 🤖 **Bot Privacy System**

### **Command-Only Visibility**
- Bots **never see regular messages**
- Only see messages starting with their command prefixes
- Command arguments encrypted specifically for the bot
- Server routes commands without decrypting content

### **Interactive Elements**
- Bots can respond with buttons, menus, forms
- All interactions happen through encrypted channels
- Embedded elements validated for safety

### **Example Bot Flow**
```
User: "/weather San Francisco"
         ↓
Server: Detects "/weather" prefix → Routes to Weather Bot
         ↓
Weather Bot: Receives encrypted command → Responds with forecast
         ↓
Server: Routes encrypted response → User sees weather embed
```

## 🏰 **Channel System**

### **Hybrid Access Model**
- **Lobby Channels**: Open join/leave (like Discord voice channels)
- **Private Channels**: Permission-based access
- **Entry Request System**: Lobby users can request private access
- **Visibility Toggle**: Private channels can be hidden from lists

### **Permission System**
- **Role-Based**: Traditional Discord-like roles
- **Cryptographic Permissions**: Backed by encryption keys
- **Approval Workflow**: Members can approve/deny entry requests

## 📨 **Invite System**

### **No Public Discovery**
- **No server lists** or public directories
- **Direct invites only** - like Signal groups
- **Expiration Controls**: Time limits and usage limits
- **Quality Gates**: Account age, verification requirements

### **Invite Configuration**
```rust
InviteConfig {
    expiry_duration: Some(Duration::days(7)),
    max_uses: Some(10),
    quality_gates: QualityGates {
        min_account_age_days: Some(30),
        require_verification: true,
        require_approval: true,
    }
}
```

## 🌐 **Network Protocol**

### **Message Types**
- **Text Messages**: Encrypted content with metadata
- **Voice Packets**: Real-time encrypted audio
- **Channel Events**: Join/leave, permissions, updates
- **Bot Commands**: Command routing and responses
- **File Transfers**: Chunked encrypted file sharing

### **Protocol Features**
- **Message Ordering**: Sequence validation
- **Compression**: For large messages (>1KB)
- **Heartbeat**: Connection monitoring
- **Error Handling**: Structured error responses

## 🔄 **Federation Support (Future)**

### **Server-to-Server Communication**
- Cross-server messaging with maintained encryption
- Identity verification across servers
- Distributed user discovery
- Independent server operation

## 📊 **Performance Targets**

### **Voice Quality**
- **Latency**: <150ms end-to-end
- **Quality**: Opus 48kHz, 64kbps (voice) / 128kbps (music)
- **CPU Usage**: <10% on modern hardware
- **Packet Loss**: Graceful degradation up to 5%

### **Scalability**
- **Concurrent Users**: 10,000+ per server instance
- **Voice Channels**: 100+ simultaneous channels
- **Message Throughput**: 1,000+ messages/second
- **File Size**: 100MB max (chunked transfer)

### **Security Standards**
- **Encryption**: AES-256-GCM, X25519, Ed25519
- **Key Rotation**: Per-message (text), 30s (voice)
- **Perfect Forward Secrecy**: Always enabled
- **Zero-Knowledge**: Server never has decryption keys

## 🚀 **Development Phases**

1. **Phase 1**: Core cryptography + basic messaging
2. **Phase 2**: Real-time encrypted voice
3. **Phase 3**: Desktop application (Tauri)
4. **Phase 4**: Channel management + bots
5. **Phase 5**: Mobile applications
6. **Phase 6**: Security audit + beta release

---

## 🎯 **Key Differentiators**

**vs Discord:**
- ✅ End-to-end encryption
- ✅ Zero-knowledge server
- ✅ Open source
- ✅ No data mining
- ✅ User-controlled

**vs Signal:**
- ✅ Community features (servers, channels)
- ✅ Voice channels
- ✅ Bot ecosystem
- ✅ Rich messaging features
- ✅ Desktop-first design

**vs Matrix/Element:**
- ✅ Better voice quality
- ✅ Discord-like UX
- ✅ Privacy-preserving bots
- ✅ Simpler architecture
- ✅ Mobile-optimized

Accord is the **missing piece** in secure communications - the privacy of Signal with the community features people actually want to use.