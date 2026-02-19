# Accord Bot SDK

A Rust SDK for building bots on the [Accord](https://accord.chat) privacy-first chat platform.

## Features

- WebSocket-based real-time event handling
- REST API for sending messages and reactions
- Async/await with Tokio
- Type-safe message and event models

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
accord-bot-sdk = { path = "../bot-sdk" }
tokio = { version = "1", features = ["full"] }
```

### Echo Bot

```rust
use accord_bot_sdk::AccordBot;
use std::sync::Arc;

#[tokio::main]
async fn main() -> accord_bot_sdk::Result<()> {
    let mut bot = AccordBot::new("ws://localhost:8080", "your-bot-token");
    bot.connect().await?;
    bot.join_channel("channel-id").await?;

    let bot = Arc::new(bot);
    let bot_clone = bot.clone();

    bot.on_message(move |msg| {
        let bot = bot_clone.clone();
        async move {
            if let Some(content) = &msg.content {
                let _ = bot.send_message(&msg.channel_id, &format!("Echo: {}", content)).await;
            }
        }
    }).await;

    bot.run().await
}
```

## API

### `AccordBot::new(relay_url, token)` — Create a new bot client
### `bot.connect()` — Connect to the relay via WebSocket
### `bot.join_channel(channel_id)` — Subscribe to channel events
### `bot.send_message(channel_id, content)` — Send a message
### `bot.reply(channel_id, message_id, content)` — Reply to a message
### `bot.add_reaction(message_id, emoji)` — React to a message
### `bot.on_message(callback)` — Register a message handler
### `bot.on_reaction(callback)` — Register a reaction handler
### `bot.run()` — Start the event loop

## Registering a Bot

Use the Accord REST API to register your bot:

```bash
curl -X POST "http://localhost:8080/bots?token=YOUR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "MyBot", "scopes": ["read_messages", "send_messages"]}'
```

The response includes `bot_id` and `api_token` — use the `api_token` as your bot token.

## Examples

- `examples/echo_bot.rs` — Echoes received messages
- `examples/moderation_bot.rs` — Handles `!kick`, `!ban`, `!help` commands

Run with:
```bash
RELAY_URL=ws://localhost:8080 BOT_TOKEN=your-token CHANNEL_ID=uuid cargo run --example echo_bot
```

## License

AGPL-3.0-or-later
