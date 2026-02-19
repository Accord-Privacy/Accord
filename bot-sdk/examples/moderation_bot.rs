//! Moderation bot that responds to !kick and !ban commands.
//!
//! Usage:
//!   RELAY_URL=ws://localhost:8080 BOT_TOKEN=your-token CHANNEL_ID=channel-uuid NODE_ID=node-uuid cargo run --example moderation_bot

use accord_bot_sdk::AccordBot;
use std::sync::Arc;

#[tokio::main]
async fn main() -> accord_bot_sdk::Result<()> {
    let relay_url = std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:8080".into());
    let token = std::env::var("BOT_TOKEN").expect("BOT_TOKEN env var required");
    let channel_id = std::env::var("CHANNEL_ID").expect("CHANNEL_ID env var required");
    let node_id = std::env::var("NODE_ID").expect("NODE_ID env var required");

    let mut bot = AccordBot::new(&relay_url, &token);
    bot.connect().await?;
    bot.join_channel(&channel_id).await?;

    let bot = Arc::new(bot);
    let bot_clone = bot.clone();
    let token_clone = token.clone();
    let relay_for_http = relay_url
        .replace("ws://", "http://")
        .replace("wss://", "https://");

    bot.on_message(move |msg| {
        let bot = bot_clone.clone();
        let node_id = node_id.clone();
        let token = token_clone.clone();
        let http_base = relay_for_http.clone();
        async move {
            let content = match &msg.content {
                Some(c) => c.clone(),
                None => return,
            };

            let parts: Vec<&str> = content.splitn(3, ' ').collect();
            match parts.first().copied() {
                Some("!kick") => {
                    if parts.len() < 2 {
                        let _ = bot.send_message(&msg.channel_id, "Usage: !kick <user_id>").await;
                        return;
                    }
                    let target = parts[1];
                    let url = format!(
                        "{}/nodes/{}/members/{}?token={}",
                        http_base, node_id, target, token
                    );
                    let client = reqwest::Client::new();
                    match client.delete(&url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("✅ Kicked user {}", target),
                            ).await;
                        }
                        Ok(resp) => {
                            let status = resp.status();
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("❌ Failed to kick: HTTP {}", status),
                            ).await;
                        }
                        Err(e) => {
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("❌ Kick error: {}", e),
                            ).await;
                        }
                    }
                }
                Some("!ban") => {
                    if parts.len() < 2 {
                        let _ = bot.send_message(&msg.channel_id, "Usage: !ban <public_key_hash>").await;
                        return;
                    }
                    let target_hash = parts[1];
                    let url = format!(
                        "{}/nodes/{}/bans?token={}",
                        http_base, node_id, token
                    );
                    let client = reqwest::Client::new();
                    let body = serde_json::json!({ "public_key_hash": target_hash });
                    match client.post(&url).json(&body).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("🔨 Banned key hash {}", target_hash),
                            ).await;
                        }
                        Ok(resp) => {
                            let status = resp.status();
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("❌ Failed to ban: HTTP {}", status),
                            ).await;
                        }
                        Err(e) => {
                            let _ = bot.send_message(
                                &msg.channel_id,
                                &format!("❌ Ban error: {}", e),
                            ).await;
                        }
                    }
                }
                Some("!help") => {
                    let _ = bot.send_message(
                        &msg.channel_id,
                        "🤖 Moderation Bot Commands:\n• !kick <user_id> — Kick a user\n• !ban <public_key_hash> — Ban a user\n• !help — Show this message",
                    ).await;
                }
                _ => {}
            }
        }
    })
    .await;

    println!("Moderation bot running! Listening on channel {}", channel_id);
    bot.run().await
}
