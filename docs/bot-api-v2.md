# Accord Bot API v2 — Airgapped Command Architecture

## Philosophy

Bots in Accord are **airgapped** from Node content. They never see messages, member lists, or encrypted data. They are stateless command processors that register capabilities and respond to invocations.

This is fundamentally different from Discord/Slack bots that receive every message and have broad API access.

## How It Works

### 1. Bot Registration

A bot registers with a Node by declaring its **command manifest** — a list of commands it supports:

```json
{
  "bot_id": "weather-bot",
  "name": "Weather",
  "icon": "🌤️",
  "description": "Get weather forecasts",
  "commands": [
    {
      "name": "forecast",
      "description": "Get weather forecast for a location",
      "params": [
        { "name": "location", "type": "string", "required": true, "description": "City or ZIP code" },
        { "name": "days", "type": "integer", "required": false, "default": 3, "description": "Number of days" }
      ]
    },
    {
      "name": "alerts",
      "description": "Check active weather alerts",
      "params": [
        { "name": "region", "type": "string", "required": true }
      ]
    }
  ]
}
```

The Node stores this manifest. The bot has **no access** to anything else in the Node.

### 2. User Interaction

Users see available bot commands in the UI (slash commands, command palette, or bot panel). When a user runs a command, the **Node** sends the bot:

```json
{
  "type": "command_invocation",
  "command": "forecast",
  "invoker_display_name": "Gage",
  "params": {
    "location": "Grand Rapids, MN",
    "days": 5
  },
  "invocation_id": "abc123",
  "channel_id": "general"
}
```

**What the bot receives:**
- Command name
- User's display name (NOT user ID, NOT public key)
- Command parameters
- An invocation ID for responding
- Channel ID (so it knows where to post the response)

**What the bot does NOT receive:**
- Message history
- Member list
- Encryption keys
- User identities beyond display name
- Any Node metadata

### 3. Bot Responses

Bots respond with structured content that the **Node renders**:

#### Simple text response:
```json
{
  "type": "command_response",
  "invocation_id": "abc123",
  "content": {
    "type": "text",
    "text": "Weather in Grand Rapids, MN: 28°F, partly cloudy"
  }
}
```

#### Embedded interactive page:
```json
{
  "type": "command_response",
  "invocation_id": "abc123",
  "content": {
    "type": "embed",
    "title": "5-Day Forecast — Grand Rapids, MN",
    "sections": [
      {
        "type": "text",
        "text": "Current: 28°F, partly cloudy"
      },
      {
        "type": "grid",
        "columns": ["Day", "High", "Low", "Conditions"],
        "rows": [
          ["Thu", "30°F", "18°F", "Cloudy"],
          ["Fri", "25°F", "12°F", "Snow"],
          ["Sat", "22°F", "8°F", "Clear"],
          ["Sun", "28°F", "15°F", "Partly cloudy"],
          ["Mon", "32°F", "20°F", "Rain/Snow"]
        ]
      },
      {
        "type": "actions",
        "buttons": [
          { "label": "🔄 Refresh", "command": "forecast", "params": { "location": "Grand Rapids, MN", "days": 5 } },
          { "label": "⚠️ Alerts", "command": "alerts", "params": { "region": "MN" } },
          { "label": "📍 Change Location", "command": "forecast", "params_prompt": ["location"] }
        ]
      }
    ]
  }
}
```

### 4. Interactive Elements Are Commands

Every interactive element in an embed is just a linked command:

- **Buttons** → invoke a command with pre-filled params
- **Text links** → invoke a command (like `[Click here](cmd:forecast?location=NYC)`)
- **Image links** → same pattern
- **Dropdowns/selects** → the selected value becomes a command param
- **`params_prompt`** → tells the Node to prompt the user for specific params before invoking

The **Node processes all interactions**. The bot never sees clicks/taps directly — it only receives command invocations.

### 5. Embed Content Types

Embeds support these section types (all rendered by the Node):

| Type | Description |
|------|-------------|
| `text` | Markdown text |
| `grid` | Table with columns and rows |
| `image` | URL to an image (Node proxies/caches) |
| `actions` | Row of buttons, each linked to a command |
| `divider` | Horizontal separator |
| `fields` | Key-value pairs (like Discord embed fields) |
| `progress` | Progress bar with label |
| `code` | Code block with language |
| `input` | Form field that feeds into a command param |

### 6. Security Model

```
┌──────────────────────────────────────────────────────┐
│                                                      │
│  User ◄──E2EE (Double Ratchet)──► Node ◄──E2EE──► Bot│
│                                    │                 │
│  Relay sees: opaque blobs only     │                 │
│                                    ▼                 │
│                             WALL: Bot never sees     │
│                             messages, members,       │
│                             encryption keys,         │
│                             or user identities       │
└──────────────────────────────────────────────────────┘
```

- Bots run **outside** the Node's trust boundary
- **Every hop is E2EE** — user↔Node (Double Ratchet), Node↔bot (X25519 + AES-256-GCM)
- Bots authenticate with a bot token (scoped to command invocation only)
- Bot tokens grant NO read access to any Node data
- Bots cannot enumerate members, read messages, or access any E2EE content
- Node admins can install/remove bots and restrict which channels they operate in
- Users can see exactly what data each command sends to the bot (transparency)
- Relay is a dumb pipe — sees only encrypted blobs for all traffic

### 7. Bot ↔ Node Encryption

All communication between a bot and a Node is end-to-end encrypted:

#### Key Exchange (on bot install)
1. Bot generates an X25519 keypair and publishes its public key
2. Node generates a per-bot X25519 keypair
3. Both derive a shared secret via X25519 ECDH + HKDF-SHA256
4. Shared secret used for AES-256-GCM encryption of all command traffic

#### Encrypt-Then-Sign
All messages use encrypt-then-sign:
1. Sender encrypts payload with AES-256-GCM (shared key, random 12-byte IV)
2. Sender signs the encrypted blob with Ed25519 (their identity key)
3. Receiver verifies signature first (reject if invalid)
4. Receiver decrypts payload

This provides:
- **Confidentiality**: Only bot and Node can read command/response content
- **Authenticity**: Signatures prove who sent each message
- **Integrity**: AES-GCM tag + Ed25519 signature = double tamper protection
- **Non-repudiation**: Bot can't deny sending a response (signature proves it)

#### Key Rotation
- Shared key rotates every 24 hours or 1000 invocations (whichever first)
- Node can force rotation at any time (e.g., after compromise suspicion)
- Old keys are zeroized after rotation

#### Client-Side Verification
- Bot signs each response with its Ed25519 key
- The **user's client** can independently verify the bot's signature
- If the Node tampers with a bot response, the signature check fails
- UI shows: ✅ "Verified bot response" or ⚠️ "Response signature invalid"

#### Transparency
- Before sending a command, client shows the user exactly what data will leave the Node boundary
- User can inspect: command name, parameters, display name being shared
- "📋 Sent to bot" disclosure log available in channel

### 8. Bot Hosting

Bots are external services that communicate via encrypted webhooks:

- **Node → Bot**: POST encrypted command invocation to bot's registered endpoint
- **Bot → Node**: POST encrypted response to Node's bot-response endpoint
- All payloads are E2EE (AES-256-GCM) + signed (Ed25519)
- TLS on transport layer as defense-in-depth (but E2EE means TLS compromise is not fatal)
- Bots can be self-hosted or third-party

### 9. Bot Key Pinning

- On first install, bot's Ed25519 public key is pinned by the Node
- If the bot's key changes, Node admin sees a warning (like Signal safety numbers)
- Users can inspect the bot's key fingerprint at any time
- Prevents silent bot replacement or key compromise going unnoticed

### 10. Permissions

Node admins control:
- Which bots are installed
- Which channels each bot can respond in
- Whether bot responses are visible to all or just the invoker ("ephemeral")
- Rate limits per bot
- Whether to show "data sent to bot" transparency notices to users

### 11. Comparison with v1 (Discord-style)

| Feature | v1 (removed) | v2 (airgapped) |
|---------|-------------|-----------------|
| Message access | Full read access | None |
| Member access | Full list | Display name only (on invocation) |
| Event model | Stream all events | Command invocations only |
| UI | Bot sends raw messages | Structured embeds rendered by Node |
| Interactivity | Message reactions/buttons | Commands linked to embed elements |
| Privacy | Bot sees everything | Bot sees only command params |
| Trust model | Bot is inside Node | Bot is outside Node |
