# Accord Bot API

Build bots for the Accord encrypted communications platform.

> ⚠️ **Critical Privacy Notice**: Bots break end-to-end encryption in channels they participate in. When a bot is added to a channel, all members are notified and a permanent warning indicator is displayed. Bots only see messages in channels they are explicitly invited to. See [Privacy Considerations](#privacy-considerations) for details.

## Table of Contents

- [Authentication](#authentication)
- [REST API Reference](#rest-api-reference)
- [WebSocket Events](#websocket-events)
- [Webhook Delivery](#webhook-delivery)
- [Permission Scopes](#permission-scopes)
- [Rate Limits](#rate-limits)
- [Privacy Considerations](#privacy-considerations)
- [Code Examples](#code-examples)
- [Best Practices](#best-practices)

---

## Authentication

### Bot API Tokens

Bots authenticate using API tokens issued during registration. Tokens are prefixed with `accord_bot_` for easy identification.

**Token format:** `accord_bot_<base64url-encoded-random-bytes>`

Pass the token as a query parameter:

```
GET /channels/{channel_id}/messages?bot_token=accord_bot_xxxxx
```

Or in the `Authorization` header:

```
Authorization: Bot accord_bot_xxxxx
```

### Registering a Bot

Only authenticated users can register bots. The registering user becomes the bot owner.

```http
POST /bots?token=<user_auth_token>
Content-Type: application/json

{
  "name": "My Bot",
  "description": "A helpful bot for my community",
  "scopes": ["read_messages", "send_messages"],
  "event_subscriptions": ["message_create", "reaction_add"],
  "webhook_url": "https://my-server.example.com/webhook"
}
```

**Response:**
```json
{
  "bot_id": "550e8400-e29b-41d4-a716-446655440000",
  "api_token": "accord_bot_dGhpcyBpcyBhIHRlc3Q...",
  "webhook_secret": "xYz123AbC...",
  "message": "Bot registered successfully. Store the API token securely — it cannot be retrieved later.",
  "privacy_warning": "⚠️ PRIVACY NOTICE: Bots receive plaintext messages..."
}
```

> **Important:** Store the `api_token` immediately. It is shown only once and cannot be retrieved. If lost, use the regenerate endpoint.

### Token Regeneration

```http
POST /bots/{bot_id}/regenerate-token?token=<owner_auth_token>
```

This invalidates the old token immediately.

---

## REST API Reference

### Bot Management

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/bots` | Register a new bot | User token |
| `GET` | `/bots/{id}` | Get bot info (public) | User token |
| `PATCH` | `/bots/{id}` | Update bot settings | Owner token |
| `DELETE` | `/bots/{id}` | Delete a bot | Owner token |
| `POST` | `/bots/{id}/regenerate-token` | Regenerate API token | Owner token |

### Channel Operations

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/bots/invite` | Invite bot to a channel | User token (admin/mod) |
| `DELETE` | `/bots/{bot_id}/channels/{channel_id}` | Remove bot from channel | User token (admin/mod) |
| `GET` | `/channels/{id}/bots` | List bots in a channel | User token |

### Bot Actions

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| `POST` | `/bot/channels/{channel_id}/messages` | Send a message | Bot token |

### Send a Message

```http
POST /bot/channels/{channel_id}/messages?bot_token=accord_bot_xxxxx
Content-Type: application/json

{
  "content": "Hello from my bot! 🤖"
}
```

**Response:**
```json
{
  "message_id": "...",
  "channel_id": "...",
  "timestamp": 1708185600
}
```

### Invite a Bot to a Channel

Requires `ManageChannels` permission in the node.

```http
POST /bots/invite?token=<user_auth_token>
Content-Type: application/json

{
  "bot_id": "550e8400-...",
  "channel_id": "660e8400-..."
}
```

**Response includes a privacy warning that should be shown to the user:**
```json
{
  "status": "invited",
  "bot_id": "...",
  "channel_id": "...",
  "privacy_warning": "⚠️ PRIVACY NOTICE: Bots receive plaintext messages..."
}
```

### Update Bot Settings

```http
PATCH /bots/{id}?token=<owner_auth_token>
Content-Type: application/json

{
  "name": "Updated Bot Name",
  "description": "New description",
  "scopes": ["read_messages", "send_messages", "read_reactions"],
  "webhook_url": "https://new-url.example.com/webhook"
}
```

---

## WebSocket Events

Bots can connect to the WebSocket endpoint to receive real-time events:

```
wss://your-server.example.com/ws?bot_token=accord_bot_xxxxx
```

### Event Types

| Event | Description | Required Scope |
|-------|-------------|----------------|
| `message_create` | New message in a bot's channel | `read_messages` |
| `message_edit` | Message edited | `read_messages` |
| `message_delete` | Message deleted | `read_messages` |
| `member_join` | User joined a channel | `read_members` |
| `member_leave` | User left a channel | `read_members` |
| `reaction_add` | Reaction added to a message | `read_reactions` |
| `reaction_remove` | Reaction removed | `read_reactions` |
| `channel_create` | New channel created in node | `read_channels` |
| `channel_delete` | Channel deleted | `read_channels` |
| `typing_start` | User started typing | `read_messages` |

### Event Payload Format

```json
{
  "event_id": "uuid",
  "event_type": "message_create",
  "bot_id": "your-bot-id",
  "channel_id": "channel-uuid",
  "node_id": "node-uuid",
  "data": {
    "message_id": "uuid",
    "sender_id": "uuid",
    "sender_username": "alice",
    "content": "Hello everyone!",
    "timestamp": 1708185600
  },
  "timestamp": 1708185600
}
```

---

## Webhook Delivery

Instead of (or in addition to) WebSocket, bots can receive events via HTTP webhooks.

### Setup

Provide a `webhook_url` during bot registration. Accord will POST events to this URL.

### Payload

```http
POST https://your-server.example.com/webhook
Content-Type: application/json
X-Accord-Signature: sha256=<hmac-hex-digest>
X-Accord-Event: message_create
X-Accord-Bot-Id: <bot-uuid>

{
  "event": { ... },
  "signature": "<hmac-sha256-hex>"
}
```

### Verifying Signatures

The `X-Accord-Signature` header contains an HMAC-SHA256 of the request body using your `webhook_secret`.

**Python:**
```python
import hmac, hashlib

def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

### Retry Policy

- Failed deliveries (non-2xx response) are retried up to 3 times
- Retry intervals: 5s, 30s, 300s (exponential backoff)
- After all retries fail, the event is dropped and logged

---

## Permission Scopes

| Scope | Description |
|-------|-------------|
| `read_messages` | Read messages in channels the bot is invited to |
| `send_messages` | Send messages in those channels |
| `read_channels` | Read channel metadata (name, topic, members) |
| `manage_channels` | Create/delete/rename channels (requires node admin approval) |
| `read_members` | Read member list and profiles |
| `manage_reactions` | Add/remove reactions |
| `read_reactions` | Read message reactions |
| `manage_files` | Upload and manage files |

**Principle of least privilege:** Only request scopes your bot actually needs. Users and admins can see what scopes a bot has before approving it.

---

## Rate Limits

Bots have stricter rate limits than regular users:

| Action | Limit |
|--------|-------|
| Messages | 20 per minute per channel |
| API calls | 60 per minute total |
| File uploads | 5 per minute |
| Reactions | 15 per minute |
| Webhook retries | 3 per event |

### Rate Limit Headers

Rate-limited responses return HTTP 429 with:

```
Retry-After: <seconds>
X-RateLimit-Remaining: 0
X-RateLimit-Reset: <unix-timestamp>
```

---

## Privacy Considerations

### The E2E Encryption Tradeoff

Accord uses end-to-end encryption (E2E) for all user-to-user communication. **Bots fundamentally break this guarantee** because they need plaintext access to function.

When a bot is added to a channel:

1. **All channel members are notified** with a system message:
   > "🤖 Bot `BotName` has been added to this channel by @admin. This bot can read all messages in this channel. E2E encryption is NOT active for bot-visible messages."

2. **A permanent indicator** (🤖) is shown in the channel header

3. **The channel's encryption status changes** from "E2E Encrypted" to "Bot Present — Messages visible to bot"

### What Bots Can Access

- ✅ Messages in channels they're invited to (plaintext)
- ✅ Channel metadata (name, topic)
- ✅ Member list and profiles (if scoped)
- ✅ Reactions on messages (if scoped)
- ❌ Messages in channels they're NOT in
- ❌ Direct messages (DMs are never bot-accessible)
- ❌ User private keys or encryption keys
- ❌ Messages sent before the bot joined (unless they have `read_messages` scope and message history access is enabled by the admin)

### What Bot Owners Must Do

- Clearly document what data your bot collects and why
- Do not store message content beyond what's necessary
- Provide a privacy policy URL in the bot description
- Respond to data deletion requests from channel admins

### Channel Admin Controls

- Admins can invite/remove bots at any time
- Removing a bot immediately revokes its access
- Admins can audit bot activity via the node audit log
- Admins can restrict which scopes a bot is allowed to use in their node

---

## Code Examples

### Python

```python
import requests
import json
import websocket
import threading

BOT_TOKEN = "accord_bot_xxxxx"
BASE_URL = "https://your-server.example.com"

# Send a message
def send_message(channel_id: str, content: str):
    resp = requests.post(
        f"{BASE_URL}/bot/channels/{channel_id}/messages",
        params={"bot_token": BOT_TOKEN},
        json={"content": content},
    )
    resp.raise_for_status()
    return resp.json()

# Listen for events via WebSocket
def on_message(ws, message):
    event = json.loads(message)
    if event.get("event_type") == "message_create":
        data = event["data"]
        print(f"[{data['sender_username']}]: {data['content']}")

        # Echo bot example
        if data["content"].startswith("!echo "):
            reply = data["content"][6:]
            send_message(event["channel_id"], f"Echo: {reply}")

def start_bot():
    ws = websocket.WebSocketApp(
        f"wss://your-server.example.com/ws?bot_token={BOT_TOKEN}",
        on_message=on_message,
    )
    ws.run_forever()

if __name__ == "__main__":
    start_bot()
```

### JavaScript (Node.js)

```javascript
const WebSocket = require('ws');
const fetch = require('node-fetch');

const BOT_TOKEN = 'accord_bot_xxxxx';
const BASE_URL = 'https://your-server.example.com';

// Send a message
async function sendMessage(channelId, content) {
  const resp = await fetch(
    `${BASE_URL}/bot/channels/${channelId}/messages?bot_token=${BOT_TOKEN}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    }
  );
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// Listen for events
const ws = new WebSocket(
  `wss://your-server.example.com/ws?bot_token=${BOT_TOKEN}`
);

ws.on('message', async (raw) => {
  const event = JSON.parse(raw);

  if (event.event_type === 'message_create') {
    const { sender_username, content } = event.data;
    console.log(`[${sender_username}]: ${content}`);

    // Ping-pong example
    if (content === '!ping') {
      await sendMessage(event.channel_id, 'Pong! 🏓');
    }
  }
});

ws.on('open', () => console.log('Bot connected!'));
ws.on('error', (err) => console.error('WebSocket error:', err));
```

### Rust

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::StreamExt;

const BOT_TOKEN: &str = "accord_bot_xxxxx";
const BASE_URL: &str = "https://your-server.example.com";

#[derive(Serialize)]
struct SendMessageRequest {
    content: String,
}

#[derive(Deserialize)]
struct BotEvent {
    event_type: String,
    channel_id: String,
    data: serde_json::Value,
}

async fn send_message(client: &Client, channel_id: &str, content: &str) -> anyhow::Result<()> {
    client
        .post(format!(
            "{}/bot/channels/{}/messages?bot_token={}",
            BASE_URL, channel_id, BOT_TOKEN
        ))
        .json(&SendMessageRequest {
            content: content.to_string(),
        })
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::new();
    let url = format!(
        "wss://your-server.example.com/ws?bot_token={}",
        BOT_TOKEN
    );

    let (mut ws_stream, _) = connect_async(&url).await?;
    println!("Bot connected!");

    while let Some(msg) = ws_stream.next().await {
        if let Ok(Message::Text(text)) = msg {
            if let Ok(event) = serde_json::from_str::<BotEvent>(&text) {
                if event.event_type == "message_create" {
                    let content = event.data["content"].as_str().unwrap_or("");
                    let sender = event.data["sender_username"].as_str().unwrap_or("unknown");
                    println!("[{}]: {}", sender, content);

                    if content == "!ping" {
                        send_message(&client, &event.channel_id, "Pong! 🏓").await?;
                    }
                }
            }
        }
    }

    Ok(())
}
```

---

## Best Practices

1. **Store tokens securely** — Use environment variables or a secrets manager. Never commit tokens to version control.

2. **Request minimal scopes** — Only request the permissions your bot actually needs.

3. **Handle rate limits gracefully** — Implement exponential backoff when you receive 429 responses.

4. **Verify webhook signatures** — Always validate the HMAC signature before processing webhook events.

5. **Be transparent** — Document what your bot does with message data in its description.

6. **Respect privacy** — Don't log or store message content unless absolutely necessary for your bot's function.

7. **Handle disconnections** — Implement automatic WebSocket reconnection with backoff.

8. **Idempotency** — Use `event_id` to deduplicate events (webhooks may retry).

9. **Graceful degradation** — If your bot can't reach the Accord server, queue actions and retry.

10. **Test with a private channel first** — Before deploying to production channels, test thoroughly in a controlled environment.
