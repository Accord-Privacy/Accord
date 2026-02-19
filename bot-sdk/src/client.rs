use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use crate::error::{BotError, Result};
use crate::models::{Event, Message};

type MessageHandler =
    Arc<dyn Fn(Message) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;
type ReactionHandler = Arc<
    dyn Fn(String, String, String, String) -> futures_util::future::BoxFuture<'static, ()>
        + Send
        + Sync,
>;

/// The main bot client for interacting with an Accord relay server.
///
/// # Example
/// ```no_run
/// use accord_bot_sdk::AccordBot;
///
/// #[tokio::main]
/// async fn main() {
///     let mut bot = AccordBot::new("ws://localhost:8080", "my-bot-token");
///     bot.connect().await.unwrap();
///     bot.send_message("channel-id", "Hello!").await.unwrap();
/// }
/// ```
#[allow(clippy::type_complexity)]
pub struct AccordBot {
    relay_url: String,
    token: String,
    http_base: String,
    http: reqwest::Client,
    ws_sink: Option<
        Arc<
            Mutex<
                futures_util::stream::SplitSink<
                    tokio_tungstenite::WebSocketStream<
                        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                    >,
                    WsMessage,
                >,
            >,
        >,
    >,
    ws_stream: Option<
        Arc<
            Mutex<
                futures_util::stream::SplitStream<
                    tokio_tungstenite::WebSocketStream<
                        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
                    >,
                >,
            >,
        >,
    >,
    message_handlers: Arc<RwLock<Vec<MessageHandler>>>,
    reaction_handlers: Arc<RwLock<Vec<ReactionHandler>>>,
    user_id: Arc<RwLock<Option<String>>>,
}

impl AccordBot {
    /// Create a new bot client.
    ///
    /// - `relay_url`: WebSocket URL of the relay (e.g. `ws://localhost:8080`)
    /// - `token`: Bot API token from `/bots` registration
    pub fn new(relay_url: &str, token: &str) -> Self {
        let relay_url = relay_url.trim_end_matches('/').to_string();
        let http_base = relay_url
            .replace("ws://", "http://")
            .replace("wss://", "https://");

        Self {
            relay_url,
            token: token.to_string(),
            http_base,
            http: reqwest::Client::new(),
            ws_sink: None,
            ws_stream: None,
            message_handlers: Arc::new(RwLock::new(Vec::new())),
            reaction_handlers: Arc::new(RwLock::new(Vec::new())),
            user_id: Arc::new(RwLock::new(None)),
        }
    }

    /// Establish a WebSocket connection and authenticate.
    pub async fn connect(&mut self) -> Result<()> {
        let ws_url = format!("{}/ws", self.relay_url);
        let (ws_stream, _) = connect_async(&ws_url).await?;
        let (sink, stream) = ws_stream.split();

        let sink = Arc::new(Mutex::new(sink));
        let stream = Arc::new(Mutex::new(stream));

        // Send authentication message
        let auth_msg = json!({ "Authenticate": { "token": self.token } });
        sink.lock()
            .await
            .send(WsMessage::Text(auth_msg.to_string()))
            .await?;

        // Wait for authentication response
        let mut stream_guard = stream.lock().await;
        while let Some(msg) = stream_guard.next().await {
            let msg = msg?;
            if let WsMessage::Text(text) = msg {
                let val: Value = serde_json::from_str(&text)?;
                if val.get("type").and_then(|t| t.as_str()) == Some("authenticated") {
                    if let Some(uid) = val.get("user_id").and_then(|u| u.as_str()) {
                        *self.user_id.write().await = Some(uid.to_string());
                    }
                    tracing::info!("Authenticated successfully");
                    break;
                } else if val.get("type").and_then(|t| t.as_str()) == Some("error") {
                    let err_msg = val
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error")
                        .to_string();
                    return Err(BotError::AuthFailed(err_msg));
                }
            }
        }
        drop(stream_guard);

        self.ws_sink = Some(sink);
        self.ws_stream = Some(stream);
        Ok(())
    }

    /// Send a message to a channel.
    pub async fn send_message(&self, channel_id: &str, content: &str) -> Result<()> {
        let url = format!(
            "{}/bot/channels/{}/messages?token={}",
            self.http_base, channel_id, self.token
        );
        let resp = self
            .http
            .post(&url)
            .json(&json!({ "encrypted_data": content }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BotError::Api {
                code: status,
                message: body,
            });
        }
        Ok(())
    }

    /// Reply to a specific message in a channel.
    pub async fn reply(&self, channel_id: &str, message_id: &str, content: &str) -> Result<()> {
        let sink = self.ws_sink.as_ref().ok_or(BotError::NotConnected)?;
        let msg = json!({
            "message_type": {
                "ChannelMessage": {
                    "channel_id": channel_id,
                    "encrypted_data": content,
                    "reply_to": message_id
                }
            },
            "message_id": uuid_v4(),
            "timestamp": now_epoch()
        });
        sink.lock()
            .await
            .send(WsMessage::Text(msg.to_string()))
            .await?;
        Ok(())
    }

    /// Add a reaction to a message.
    pub async fn add_reaction(&self, message_id: &str, emoji: &str) -> Result<()> {
        let url = format!(
            "{}/messages/{}/reactions/{}?token={}",
            self.http_base, message_id, emoji, self.token
        );
        let resp = self.http.put(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BotError::Api {
                code: status,
                message: body,
            });
        }
        Ok(())
    }

    /// Register a handler for incoming messages.
    ///
    /// The callback receives a [`Message`] and should return a boxed future.
    pub async fn on_message<F, Fut>(&self, handler: F)
    where
        F: Fn(Message) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(
            move |msg: Message| -> futures_util::future::BoxFuture<'static, ()> {
                Box::pin(handler(msg))
            },
        );
        self.message_handlers.write().await.push(handler);
    }

    /// Register a handler for reaction events.
    ///
    /// The callback receives `(message_id, channel_id, user_id, emoji)`.
    pub async fn on_reaction<F, Fut>(&self, handler: F)
    where
        F: Fn(String, String, String, String) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(
            move |msg_id: String,
                  chan_id: String,
                  user_id: String,
                  emoji: String|
                  -> futures_util::future::BoxFuture<'static, ()> {
                Box::pin(handler(msg_id, chan_id, user_id, emoji))
            },
        );
        self.reaction_handlers.write().await.push(handler);
    }

    /// Join a channel to receive messages from it.
    pub async fn join_channel(&self, channel_id: &str) -> Result<()> {
        let sink = self.ws_sink.as_ref().ok_or(BotError::NotConnected)?;
        let msg = json!({
            "message_type": { "JoinChannel": { "channel_id": channel_id } },
            "message_id": uuid_v4(),
            "timestamp": now_epoch()
        });
        sink.lock()
            .await
            .send(WsMessage::Text(msg.to_string()))
            .await?;
        Ok(())
    }

    /// Get the authenticated bot's user ID.
    pub async fn user_id(&self) -> Option<String> {
        self.user_id.read().await.clone()
    }

    /// Run the event loop, dispatching to registered handlers.
    ///
    /// This blocks until the WebSocket connection is closed.
    pub async fn run(&self) -> Result<()> {
        let stream = self.ws_stream.as_ref().ok_or(BotError::NotConnected)?;
        let mut stream_guard = stream.lock().await;

        while let Some(msg) = stream_guard.next().await {
            let msg = msg?;
            match msg {
                WsMessage::Text(text) => {
                    if let Ok(val) = serde_json::from_str::<Value>(&text) {
                        if let Some(event) = parse_event(&val) {
                            self.dispatch(event).await;
                        }
                    }
                }
                WsMessage::Ping(data) => {
                    if let Some(sink) = &self.ws_sink {
                        let _ = sink.lock().await.send(WsMessage::Pong(data)).await;
                    }
                }
                WsMessage::Close(_) => {
                    tracing::info!("WebSocket closed");
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn dispatch(&self, event: Event) {
        match event {
            Event::MessageCreate(msg) => {
                let handlers = self.message_handlers.read().await;
                for handler in handlers.iter() {
                    let handler = handler.clone();
                    let msg = msg.clone();
                    tokio::spawn(async move { handler(msg).await });
                }
            }
            Event::ReactionAdd {
                message_id,
                channel_id,
                user_id,
                emoji,
            } => {
                let handlers = self.reaction_handlers.read().await;
                for handler in handlers.iter() {
                    let handler = handler.clone();
                    let (mid, cid, uid, e) = (
                        message_id.clone(),
                        channel_id.clone(),
                        user_id.clone(),
                        emoji.clone(),
                    );
                    tokio::spawn(async move { handler(mid, cid, uid, e).await });
                }
            }
            _ => {}
        }
    }
}

fn parse_event(val: &Value) -> Option<Event> {
    let event_type = val.get("type")?.as_str()?;
    match event_type {
        "channel_message" => {
            let msg = Message {
                id: val.get("message_id")?.as_str()?.to_string(),
                channel_id: val.get("channel_id")?.as_str()?.to_string(),
                sender_id: val.get("from")?.as_str()?.to_string(),
                sender_public_key_hash: None,
                content: val
                    .get("encrypted_data")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                encrypted_payload: None,
                display_name: val
                    .get("sender_display_name")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                created_at: val.get("timestamp").and_then(|v| v.as_u64()),
                edited_at: None,
                reply_to: val
                    .get("reply_to")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };
            Some(Event::MessageCreate(msg))
        }
        "reaction_add" => Some(Event::ReactionAdd {
            message_id: val.get("message_id")?.as_str()?.to_string(),
            channel_id: val.get("channel_id")?.as_str()?.to_string(),
            user_id: val.get("user_id")?.as_str()?.to_string(),
            emoji: val.get("emoji")?.as_str()?.to_string(),
        }),
        "reaction_remove" => Some(Event::ReactionRemove {
            message_id: val.get("message_id")?.as_str()?.to_string(),
            channel_id: val.get("channel_id")?.as_str()?.to_string(),
            user_id: val.get("user_id")?.as_str()?.to_string(),
            emoji: val.get("emoji")?.as_str()?.to_string(),
        }),
        "message_edit" => Some(Event::MessageEdit {
            message_id: val.get("message_id")?.as_str()?.to_string(),
            channel_id: val.get("channel_id")?.as_str()?.to_string(),
            content: val.get("encrypted_data")?.as_str()?.to_string(),
            edited_at: val.get("edited_at")?.as_u64()?,
        }),
        "message_delete" => Some(Event::MessageDelete {
            message_id: val.get("message_id")?.as_str()?.to_string(),
            channel_id: val.get("channel_id")?.as_str()?.to_string(),
        }),
        "typing_start" => Some(Event::TypingStart {
            channel_id: val.get("channel_id")?.as_str()?.to_string(),
            user_id: val.get("user_id")?.as_str()?.to_string(),
        }),
        _ => Some(Event::Unknown(val.clone())),
    }
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // Simple pseudo-UUID for message IDs (not cryptographically secure)
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (ts >> 96) as u32,
        (ts >> 80) as u16,
        (ts >> 64) as u16 & 0xfff,
        ((ts >> 48) as u16 & 0x3fff) | 0x8000,
        ts as u64 & 0xffff_ffff_ffff
    )
}

fn now_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
