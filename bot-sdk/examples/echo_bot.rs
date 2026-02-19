//! Simple echo bot that repeats every message it receives.
//!
//! Usage:
//!   RELAY_URL=ws://localhost:8080 BOT_TOKEN=your-token CHANNEL_ID=channel-uuid cargo run --example echo_bot

use accord_bot_sdk::AccordBot;
use std::sync::Arc;

#[tokio::main]
async fn main() -> accord_bot_sdk::Result<()> {
    let relay_url = std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:8080".into());
    let token = std::env::var("BOT_TOKEN").expect("BOT_TOKEN env var required");
    let channel_id = std::env::var("CHANNEL_ID").expect("CHANNEL_ID env var required");

    let mut bot = AccordBot::new(&relay_url, &token);
    bot.connect().await?;
    bot.join_channel(&channel_id).await?;

    let bot = Arc::new(bot);
    let bot_clone = bot.clone();

    bot.on_message(move |msg| {
        let bot = bot_clone.clone();
        async move {
            // Don't echo our own messages
            if let Some(content) = &msg.content {
                let reply = format!("Echo: {}", content);
                if let Err(e) = bot.send_message(&msg.channel_id, &reply).await {
                    eprintln!("Failed to send echo: {}", e);
                }
            }
        }
    })
    .await;

    println!("Echo bot running! Listening on channel {}", channel_id);
    bot.run().await
}
