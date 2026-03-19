use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use crate::error::{BotError, Result};
use crate::models::{Event, MemberJoin, MemberLeave, Message, Role};

type MessageHandler =
    Arc<dyn Fn(Message) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;
type ReactionHandler = Arc<
    dyn Fn(String, String, String, String) -> futures_util::future::BoxFuture<'static, ()>
        + Send
        + Sync,
>;
type MemberJoinHandler =
    Arc<dyn Fn(MemberJoin) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;
type MemberLeaveHandler =
    Arc<dyn Fn(MemberLeave) -> futures_util::future::BoxFuture<'static, ()> + Send + Sync>;

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
    member_join_handlers: Arc<RwLock<Vec<MemberJoinHandler>>>,
    member_leave_handlers: Arc<RwLock<Vec<MemberLeaveHandler>>>,
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
            member_join_handlers: Arc::new(RwLock::new(Vec::new())),
            member_leave_handlers: Arc::new(RwLock::new(Vec::new())),
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

    /// Add a reaction emoji to a message.
    ///
    /// # Arguments
    /// - `channel_id`: The channel containing the message (used for membership validation).
    /// - `message_id`: The ID of the message to react to.
    /// - `emoji`: The emoji string to add as a reaction (e.g. `"👍"` or `"thumbsup"`).
    ///
    /// # Errors
    /// Returns [`BotError::Api`] if the server rejects the request (e.g. the bot is not a
    /// member of the channel, or the message does not exist).
    pub async fn add_reaction(
        &self,
        channel_id: &str,
        message_id: &str,
        emoji: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/messages/{}/reactions/{}?token={}&channel_id={}",
            self.http_base, message_id, emoji, self.token, channel_id
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

    /// Fetch message history for a channel.
    ///
    /// Returns messages in reverse-chronological order (newest first), matching the
    /// server's default pagination behaviour.
    ///
    /// # Arguments
    /// - `channel_id`: The channel to fetch messages from.
    /// - `limit`: Maximum number of messages to return (server caps at 100; default 50).
    /// - `before`: An optional message ID cursor — only messages older than this ID are
    ///   returned, enabling backwards pagination.
    ///
    /// # Errors
    /// Returns [`BotError::Api`] if the server rejects the request (e.g. the bot lacks
    /// channel access).
    pub async fn fetch_messages(
        &self,
        channel_id: &str,
        limit: Option<u32>,
        before: Option<&str>,
    ) -> Result<Vec<Message>> {
        let mut url = format!(
            "{}/channels/{}/messages?token={}",
            self.http_base, channel_id, self.token
        );
        if let Some(lim) = limit {
            url.push_str(&format!("&limit={}", lim));
        }
        if let Some(cursor) = before {
            url.push_str(&format!("&before={}", cursor));
        }

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BotError::Api {
                code: status,
                message: body,
            });
        }

        let body: serde_json::Value = resp.json().await?;
        let messages = body
            .get("messages")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();

        let mut result = Vec::with_capacity(messages.len());
        for raw in messages {
            let msg = Message {
                id: raw
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                channel_id: raw
                    .get("channel_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(channel_id)
                    .to_string(),
                sender_id: raw
                    .get("sender_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                sender_public_key_hash: raw
                    .get("sender_public_key_hash")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                content: raw
                    .get("encrypted_data")
                    .or_else(|| raw.get("content"))
                    .and_then(|v| v.as_str())
                    .map(String::from),
                encrypted_payload: raw
                    .get("encrypted_payload")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                display_name: raw
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                created_at: raw.get("created_at").and_then(|v| v.as_u64()),
                edited_at: raw.get("edited_at").and_then(|v| v.as_u64()),
                reply_to: raw
                    .get("reply_to")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            };
            result.push(msg);
        }
        Ok(result)
    }

    // ── Role Management ──────────────────────────────────────────────────────

    /// List all roles defined in a node.
    ///
    /// Returns every role for `node_id` in position order (ascending).
    /// The built-in `@everyone` role (position `0`) is included.
    ///
    /// Requires the bot to be a member of the node; no special permission needed
    /// beyond membership.
    ///
    /// # Errors
    /// Returns [`BotError::Api`] if the server returns a non-2xx status (e.g. the
    /// node does not exist or the bot is not a member).
    ///
    /// # Example
    /// ```no_run
    /// # use accord_bot_sdk::AccordBot;
    /// # async fn example(bot: &AccordBot) {
    /// let roles = bot.list_roles("node-uuid-here").await.unwrap();
    /// for role in &roles {
    ///     println!("{}: {} (pos {})", role.id, role.name, role.position);
    /// }
    /// # }
    /// ```
    pub async fn list_roles(&self, node_id: &str) -> Result<Vec<Role>> {
        let url = format!(
            "{}/nodes/{}/roles?token={}",
            self.http_base, node_id, self.token
        );
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(BotError::Api {
                code: status,
                message: body,
            });
        }

        let body: serde_json::Value = resp.json().await?;
        let roles_raw = body
            .get("roles")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();

        let mut roles = Vec::with_capacity(roles_raw.len());
        for raw in roles_raw {
            let role: Role = serde_json::from_value(raw)?;
            roles.push(role);
        }
        Ok(roles)
    }

    /// Assign a role to a node member.
    ///
    /// Uses `PUT /nodes/{node_id}/members/{user_id}/roles/{role_id}`.
    /// This is idempotent — assigning a role the member already has is a no-op.
    ///
    /// Requires the `MANAGE_ROLES` permission in the target node.
    ///
    /// # Arguments
    /// - `node_id`: The node that owns both the member and the role.
    /// - `user_id`: The member to assign the role to.
    /// - `role_id`: The role to assign.
    ///
    /// # Errors
    /// Returns [`BotError::Api`] on:
    /// - `403` — bot lacks `MANAGE_ROLES` permission.
    /// - `404` — role or user not found in the node.
    ///
    /// # Example
    /// ```no_run
    /// # use accord_bot_sdk::AccordBot;
    /// # async fn example(bot: &AccordBot) {
    /// bot.assign_role("node-id", "user-id", "role-id").await.unwrap();
    /// # }
    /// ```
    pub async fn assign_role(&self, node_id: &str, user_id: &str, role_id: &str) -> Result<()> {
        let url = format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            self.http_base, node_id, user_id, role_id, self.token
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

    /// Remove a role from a node member.
    ///
    /// Uses `DELETE /nodes/{node_id}/members/{user_id}/roles/{role_id}`.
    /// This is idempotent — removing a role the member does not have is a no-op.
    ///
    /// Requires the `MANAGE_ROLES` permission in the target node.
    ///
    /// # Arguments
    /// - `node_id`: The node that owns both the member and the role.
    /// - `user_id`: The member to remove the role from.
    /// - `role_id`: The role to remove.
    ///
    /// # Errors
    /// Returns [`BotError::Api`] on:
    /// - `403` — bot lacks `MANAGE_ROLES` permission.
    /// - `404` — role or user not found in the node.
    ///
    /// # Example
    /// ```no_run
    /// # use accord_bot_sdk::AccordBot;
    /// # async fn example(bot: &AccordBot) {
    /// bot.remove_role("node-id", "user-id", "role-id").await.unwrap();
    /// # }
    /// ```
    pub async fn remove_role(&self, node_id: &str, user_id: &str, role_id: &str) -> Result<()> {
        let url = format!(
            "{}/nodes/{}/members/{}/roles/{}?token={}",
            self.http_base, node_id, user_id, role_id, self.token
        );
        let resp = self.http.delete(&url).send().await?;
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

    /// Register a handler for member-join events.
    ///
    /// The callback receives a [`MemberJoin`] describing who joined and which node.
    ///
    /// # Example
    /// ```no_run
    /// # use accord_bot_sdk::AccordBot;
    /// # async fn example(bot: &AccordBot) {
    /// bot.on_member_join(|ev| async move {
    ///     println!("{} joined node {}", ev.user_id, ev.node_id);
    /// }).await;
    /// # }
    /// ```
    pub async fn on_member_join<F, Fut>(&self, handler: F)
    where
        F: Fn(MemberJoin) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(
            move |ev: MemberJoin| -> futures_util::future::BoxFuture<'static, ()> {
                Box::pin(handler(ev))
            },
        );
        self.member_join_handlers.write().await.push(handler);
    }

    /// Register a handler for member-leave events.
    ///
    /// The callback receives a [`MemberLeave`] describing who left and which node.
    ///
    /// # Example
    /// ```no_run
    /// # use accord_bot_sdk::AccordBot;
    /// # async fn example(bot: &AccordBot) {
    /// bot.on_member_leave(|ev| async move {
    ///     println!("{} left node {}", ev.user_id, ev.node_id);
    /// }).await;
    /// # }
    /// ```
    pub async fn on_member_leave<F, Fut>(&self, handler: F)
    where
        F: Fn(MemberLeave) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(
            move |ev: MemberLeave| -> futures_util::future::BoxFuture<'static, ()> {
                Box::pin(handler(ev))
            },
        );
        self.member_leave_handlers.write().await.push(handler);
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
            Event::MemberJoin(ev) => {
                let handlers = self.member_join_handlers.read().await;
                for handler in handlers.iter() {
                    let handler = handler.clone();
                    let ev = ev.clone();
                    tokio::spawn(async move { handler(ev).await });
                }
            }
            Event::MemberLeave(ev) => {
                let handlers = self.member_leave_handlers.read().await;
                for handler in handlers.iter() {
                    let handler = handler.clone();
                    let ev = ev.clone();
                    tokio::spawn(async move { handler(ev).await });
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
        // Server broadcasts "member_joined" when a user joins a node.
        // Also accept "member_join" for webhook-style naming consistency.
        "member_joined" | "member_join" => Some(Event::MemberJoin(crate::models::MemberJoin {
            node_id: val.get("node_id")?.as_str()?.to_string(),
            user_id: val.get("user_id")?.as_str()?.to_string(),
            display_name: val
                .get("display_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            timestamp: val.get("timestamp").and_then(|v| v.as_u64()),
        })),
        // "member_left" / "member_leave" for when a user leaves a node.
        "member_left" | "member_leave" => Some(Event::MemberLeave(crate::models::MemberLeave {
            node_id: val.get("node_id")?.as_str()?.to_string(),
            user_id: val.get("user_id")?.as_str()?.to_string(),
            display_name: val
                .get("display_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            timestamp: val.get("timestamp").and_then(|v| v.as_u64()),
        })),
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

#[cfg(test)]
mod http_tests {
    use super::*;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a bot client that points at the given mock server base URL.
    fn make_bot(base_url: &str) -> AccordBot {
        // Replace the protocol prefix so the http_base derivation in `new()` works.
        // MockServer listens on http://, but AccordBot::new() expects a ws:// URL and
        // internally converts it to http://.
        let ws_url = base_url.replacen("http://", "ws://", 1);
        AccordBot::new(&ws_url, "test-token")
    }

    // -------------------------------------------------------------------------
    // add_reaction tests
    // -------------------------------------------------------------------------

    /// Happy path: server returns 200, method returns Ok(()).
    #[tokio::test]
    async fn add_reaction_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path_regex(r"^/messages/[^/]+/reactions/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "emoji": "👍",
                "count": 1
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot
            .add_reaction("chan-111", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "👍")
            .await;

        assert!(result.is_ok(), "expected Ok but got {:?}", result);
    }

    /// Server returns 403 → BotError::Api with code 403.
    #[tokio::test]
    async fn add_reaction_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path_regex(r"^/messages/[^/]+/reactions/.+$"))
            .respond_with(
                ResponseTemplate::new(403)
                    .set_body_string("You must be a member of this channel to add reactions"),
            )
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.add_reaction("chan-111", "msg-222", "👎").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Api(403) error, got {:?}", other),
        }
    }

    /// Server returns 404 for unknown message → BotError::Api with code 404.
    #[tokio::test]
    async fn add_reaction_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path_regex(r"^/messages/[^/]+/reactions/.+$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Message not found"))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.add_reaction("chan-111", "no-such-msg", "❤️").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 404),
            other => panic!("expected Api(404) error, got {:?}", other),
        }
    }

    // -------------------------------------------------------------------------
    // fetch_messages tests
    // -------------------------------------------------------------------------

    /// Happy path: server returns a list of messages, they are deserialised correctly.
    #[tokio::test]
    async fn fetch_messages_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/channels/chan-abc/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [
                    {
                        "id": "msg-001",
                        "channel_id": "chan-abc",
                        "sender_id": "user-xyz",
                        "sender_public_key_hash": "deadbeef",
                        "encrypted_payload": "base64data",
                        "display_name": "Alice",
                        "created_at": 1700000000_u64,
                        "edited_at": null,
                        "reply_to": null
                    },
                    {
                        "id": "msg-002",
                        "channel_id": "chan-abc",
                        "sender_id": "user-abc",
                        "sender_public_key_hash": "cafebabe",
                        "encrypted_payload": "morebase64",
                        "display_name": null,
                        "created_at": 1700000100_u64,
                        "edited_at": null,
                        "reply_to": null
                    }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let messages = bot
            .fetch_messages("chan-abc", Some(50), None)
            .await
            .expect("fetch_messages should succeed");

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].id, "msg-001");
        assert_eq!(messages[0].sender_id, "user-xyz");
        assert_eq!(messages[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(messages[1].id, "msg-002");
        assert_eq!(messages[1].display_name, None);
    }

    /// Empty channel — server returns an empty messages array.
    #[tokio::test]
    async fn fetch_messages_empty_channel() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/channels/empty-chan/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let messages = bot
            .fetch_messages("empty-chan", None, None)
            .await
            .expect("fetch_messages should succeed");

        assert!(messages.is_empty());
    }

    /// Pagination: passing `before` cursor is forwarded as a query parameter.
    #[tokio::test]
    async fn fetch_messages_with_before_cursor() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/channels/chan-paged/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [
                    {
                        "id": "msg-old",
                        "channel_id": "chan-paged",
                        "sender_id": "user-1",
                        "sender_public_key_hash": "abc",
                        "encrypted_payload": "x",
                        "created_at": 1699999000_u64
                    }
                ],
                "has_more": false,
                "next_cursor": null
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let messages = bot
            .fetch_messages("chan-paged", Some(25), Some("cursor-msg-id"))
            .await
            .expect("fetch_messages with cursor should succeed");

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].id, "msg-old");
    }

    /// Server returns 403 → BotError::Api with code 403.
    #[tokio::test]
    async fn fetch_messages_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/channels/secret-chan/messages"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Access denied"))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.fetch_messages("secret-chan", None, None).await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Api(403) error, got {:?}", other),
        }
    }

    // ── parse_event helpers ──

    fn parse_ws(json: &str) -> Option<Event> {
        let val: Value = serde_json::from_str(json).unwrap();
        parse_event(&val)
    }

    // ── parse_event: MemberJoin ──

    #[test]
    fn test_parse_member_joined_event() {
        let json = r#"{
            "type": "member_joined",
            "node_id": "node-abc",
            "user_id": "user-123",
            "display_name": "Alice",
            "timestamp": 1700000000
        }"#;
        let event = parse_ws(json).expect("should parse");
        match event {
            Event::MemberJoin(ev) => {
                assert_eq!(ev.node_id, "node-abc");
                assert_eq!(ev.user_id, "user-123");
                assert_eq!(ev.display_name, Some("Alice".to_string()));
                assert_eq!(ev.timestamp, Some(1700000000));
            }
            other => panic!("expected MemberJoin, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_member_join_alias_event() {
        // webhook-style name "member_join" also accepted
        let json = r#"{
            "type": "member_join",
            "node_id": "node-abc",
            "user_id": "user-123"
        }"#;
        let event = parse_ws(json).expect("should parse");
        assert!(matches!(event, Event::MemberJoin(_)));
    }

    #[test]
    fn test_parse_member_joined_missing_required_field() {
        // Missing user_id → parse_event returns None
        let json = r#"{"type": "member_joined", "node_id": "node-abc"}"#;
        let event = parse_ws(json);
        // user_id is required (uses `?`), so should return None
        assert!(event.is_none());
    }

    // ── parse_event: MemberLeave ──

    #[test]
    fn test_parse_member_left_event() {
        let json = r#"{
            "type": "member_left",
            "node_id": "node-xyz",
            "user_id": "user-456",
            "display_name": "Bob",
            "timestamp": 1700000001
        }"#;
        let event = parse_ws(json).expect("should parse");
        match event {
            Event::MemberLeave(ev) => {
                assert_eq!(ev.node_id, "node-xyz");
                assert_eq!(ev.user_id, "user-456");
                assert_eq!(ev.display_name, Some("Bob".to_string()));
                assert_eq!(ev.timestamp, Some(1700000001));
            }
            other => panic!("expected MemberLeave, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_member_leave_alias_event() {
        let json = r#"{
            "type": "member_leave",
            "node_id": "node-xyz",
            "user_id": "user-456"
        }"#;
        let event = parse_ws(json).expect("should parse");
        assert!(matches!(event, Event::MemberLeave(_)));
    }

    #[test]
    fn test_parse_member_left_optional_fields() {
        // timestamp and display_name are optional
        let json = r#"{
            "type": "member_left",
            "node_id": "node-xyz",
            "user_id": "user-456"
        }"#;
        let event = parse_ws(json).expect("should parse");
        match event {
            Event::MemberLeave(ev) => {
                assert!(ev.display_name.is_none());
                assert!(ev.timestamp.is_none());
            }
            other => panic!("expected MemberLeave, got {:?}", other),
        }
    }

    // ── dispatch: MemberJoin ──

    #[tokio::test]
    async fn test_dispatch_member_join_calls_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let bot = AccordBot::new("ws://localhost:9999", "test-token");
        bot.on_member_join(move |ev: MemberJoin| {
            let c = counter_clone.clone();
            async move {
                assert_eq!(ev.user_id, "user-123");
                assert_eq!(ev.node_id, "node-abc");
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;

        let ev = MemberJoin {
            node_id: "node-abc".to_string(),
            user_id: "user-123".to_string(),
            display_name: Some("Alice".to_string()),
            timestamp: None,
        };
        bot.dispatch(Event::MemberJoin(ev)).await;

        // Give the spawned task a moment to run
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    // ── dispatch: MemberLeave ──

    #[tokio::test]
    async fn test_dispatch_member_leave_calls_handler() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc as StdArc;

        let counter = StdArc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let bot = AccordBot::new("ws://localhost:9999", "test-token");
        bot.on_member_leave(move |ev: MemberLeave| {
            let c = counter_clone.clone();
            async move {
                assert_eq!(ev.user_id, "user-456");
                assert_eq!(ev.node_id, "node-xyz");
                c.fetch_add(1, Ordering::SeqCst);
            }
        })
        .await;

        let ev = MemberLeave {
            node_id: "node-xyz".to_string(),
            user_id: "user-456".to_string(),
            display_name: None,
            timestamp: Some(42),
        };
        bot.dispatch(Event::MemberLeave(ev)).await;

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_dispatch_member_join_no_handlers_is_noop() {
        let bot = AccordBot::new("ws://localhost:9999", "test-token");
        let ev = MemberJoin {
            node_id: "n".to_string(),
            user_id: "u".to_string(),
            display_name: None,
            timestamp: None,
        };
        // Should not panic
        bot.dispatch(Event::MemberJoin(ev)).await;
    }

    #[tokio::test]
    async fn test_dispatch_member_leave_no_handlers_is_noop() {
        let bot = AccordBot::new("ws://localhost:9999", "test-token");
        let ev = MemberLeave {
            node_id: "n".to_string(),
            user_id: "u".to_string(),
            display_name: None,
            timestamp: None,
        };
        bot.dispatch(Event::MemberLeave(ev)).await;
    }

    // ── list_roles tests ──────────────────────────────────────────────────────

    fn make_role_json(id: &str, name: &str, position: i32) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "node_id": "node-abc",
            "name": name,
            "color": 0,
            "permissions": 0,
            "position": position,
            "hoist": false,
            "mentionable": false,
            "icon_emoji": null,
            "created_at": 1700000000_u64
        })
    }

    /// Happy path: server returns two roles, they are deserialized correctly.
    #[tokio::test]
    async fn list_roles_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/nodes/node-abc/roles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "roles": [
                    make_role_json("role-001", "@everyone", 0),
                    make_role_json("role-002", "Moderator", 1),
                ]
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let roles = bot
            .list_roles("node-abc")
            .await
            .expect("list_roles should succeed");

        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].id, "role-001");
        assert_eq!(roles[0].name, "@everyone");
        assert_eq!(roles[0].position, 0);
        assert_eq!(roles[1].id, "role-002");
        assert_eq!(roles[1].name, "Moderator");
        assert_eq!(roles[1].position, 1);
    }

    /// Empty node — server returns an empty roles array.
    #[tokio::test]
    async fn list_roles_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/nodes/node-empty/roles"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "roles": []
            })))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let roles = bot
            .list_roles("node-empty")
            .await
            .expect("list_roles should succeed");
        assert!(roles.is_empty());
    }

    /// Non-member → server returns 403 → BotError::Api with code 403.
    #[tokio::test]
    async fn list_roles_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/nodes/node-secret/roles"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Not a member of this node"))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.list_roles("node-secret").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Api(403), got {:?}", other),
        }
    }

    // ── assign_role tests ─────────────────────────────────────────────────────

    /// Happy path: server returns 204 No Content → Ok(()).
    #[tokio::test]
    async fn assign_role_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/nodes/node-abc/members/user-123/roles/role-mod"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.assign_role("node-abc", "user-123", "role-mod").await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    /// Bot lacks MANAGE_ROLES → server returns 403.
    #[tokio::test]
    async fn assign_role_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/nodes/node-abc/members/user-123/roles/role-mod"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("Missing permission: MANAGE_ROLES"),
            )
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.assign_role("node-abc", "user-123", "role-mod").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Api(403), got {:?}", other),
        }
    }

    /// Role not found in node → server returns 404.
    #[tokio::test]
    async fn assign_role_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/nodes/node-abc/members/user-123/roles/no-such-role"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Role not found"))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot
            .assign_role("node-abc", "user-123", "no-such-role")
            .await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 404),
            other => panic!("expected Api(404), got {:?}", other),
        }
    }

    // ── remove_role tests ─────────────────────────────────────────────────────

    /// Happy path: server returns 204 No Content → Ok(()).
    #[tokio::test]
    async fn remove_role_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/nodes/node-abc/members/user-123/roles/role-mod"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.remove_role("node-abc", "user-123", "role-mod").await;
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    /// Bot lacks MANAGE_ROLES → server returns 403.
    #[tokio::test]
    async fn remove_role_forbidden() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/nodes/node-abc/members/user-123/roles/role-mod"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string("Missing permission: MANAGE_ROLES"),
            )
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.remove_role("node-abc", "user-123", "role-mod").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Api(403), got {:?}", other),
        }
    }

    /// User not a member of the node → server returns 404.
    #[tokio::test]
    async fn remove_role_user_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/nodes/node-abc/members/ghost-user/roles/role-mod"))
            .respond_with(
                ResponseTemplate::new(404).set_body_string("User is not a member of this node"),
            )
            .mount(&mock_server)
            .await;

        let bot = make_bot(&mock_server.uri());
        let result = bot.remove_role("node-abc", "ghost-user", "role-mod").await;

        match result {
            Err(BotError::Api { code, .. }) => assert_eq!(code, 404),
            other => panic!("expected Api(404), got {:?}", other),
        }
    }
}
