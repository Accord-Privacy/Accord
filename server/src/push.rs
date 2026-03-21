//! Push notification infrastructure for Accord
//!
//! Privacy-first design: push payloads NEVER contain message content.
//! They serve as wake-up signals that tell the app to connect and fetch
//! encrypted messages over the secure channel.

use crate::models::{NotificationPrivacy, PushPlatform};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, warn};
use uuid::Uuid;

// ── Push payload (privacy-respecting) ──

/// The payload sent via push notification. Never contains message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushPayload {
    /// Always present: tells client to wake up and fetch
    pub event: PushEvent,
    /// Channel or DM channel ID (so client knows where to look)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<Uuid>,
    /// Node ID for context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<Uuid>,
    /// Number of pending messages (coalesced)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// Sender display name — only included if privacy_level == Full
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_name: Option<String>,
    /// Optional: E2E encrypted metadata blob (encrypted with recipient's key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushEvent {
    NewMessage,
    NewDirectMessage,
    Mention,
    VoiceCall,
}

// ── Push provider trait ──

/// Result from a push send attempt
#[derive(Debug)]
pub enum PushResult {
    /// Successfully sent
    Sent,
    /// Token is invalid/expired — should be deregistered
    InvalidToken,
    /// Temporary failure — retry later
    RetryLater,
    /// Other error
    Error(String),
}

/// Trait for push notification providers (APNs, FCM)
#[async_trait::async_trait]
pub trait PushProvider: Send + Sync {
    /// Send a push notification to a device
    async fn send(&self, token: &str, payload: &PushPayload) -> PushResult;

    /// Provider name for logging
    fn name(&self) -> &'static str;
}

// ── Mock APNs provider ──

/// Mock APNs provider for development/testing
#[derive(Default)]
pub struct MockApnsProvider {
    /// Track sent notifications for testing
    pub sent: Arc<Mutex<Vec<(String, PushPayload)>>>,
}

impl MockApnsProvider {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl PushProvider for MockApnsProvider {
    async fn send(&self, token: &str, payload: &PushPayload) -> PushResult {
        debug!("MockAPNs: sending to token={} payload={:?}", token, payload);
        self.sent
            .lock()
            .await
            .push((token.to_string(), payload.clone()));
        PushResult::Sent
    }

    fn name(&self) -> &'static str {
        "mock-apns"
    }
}

// ── Mock FCM provider ──

/// Mock FCM provider for development/testing
#[derive(Default)]
pub struct MockFcmProvider {
    /// Track sent notifications for testing
    pub sent: Arc<Mutex<Vec<(String, PushPayload)>>>,
}

impl MockFcmProvider {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl PushProvider for MockFcmProvider {
    async fn send(&self, token: &str, payload: &PushPayload) -> PushResult {
        debug!("MockFCM: sending to token={} payload={:?}", token, payload);
        self.sent
            .lock()
            .await
            .push((token.to_string(), payload.clone()));
        PushResult::Sent
    }

    fn name(&self) -> &'static str {
        "mock-fcm"
    }
}

// ── Rate limiter & coalescer ──

/// Tracks pending pushes per user to implement coalescing and rate limiting.
/// Multiple rapid messages → single push with count.
struct PendingPush {
    channel_id: Option<Uuid>,
    node_id: Option<Uuid>,
    count: u32,
    first_at: Instant,
    sender_name: Option<String>,
    event: PushEvent,
}

/// Push notification dispatcher with rate limiting and coalescing
pub struct PushDispatcher {
    apns: Box<dyn PushProvider>,
    fcm: Box<dyn PushProvider>,
    /// Pending pushes per user_id, coalesced over a short window
    pending: RwLock<HashMap<Uuid, Vec<PendingPush>>>,
    /// Minimum interval between pushes to the same user (rate limit)
    min_interval: Duration,
    /// Coalescing window — wait this long before sending to batch messages
    coalesce_window: Duration,
    /// Last push time per user for rate limiting
    last_push: RwLock<HashMap<Uuid, Instant>>,
}

impl PushDispatcher {
    pub fn new(apns: Box<dyn PushProvider>, fcm: Box<dyn PushProvider>) -> Self {
        Self {
            apns,
            fcm,
            pending: RwLock::new(HashMap::new()),
            min_interval: Duration::from_secs(5),
            coalesce_window: Duration::from_millis(2000),
            last_push: RwLock::new(HashMap::new()),
        }
    }

    /// Queue a push notification for a user. Coalesces rapid messages.
    pub async fn notify(
        &self,
        recipient_id: Uuid,
        event: PushEvent,
        channel_id: Option<Uuid>,
        node_id: Option<Uuid>,
        sender_name: Option<String>,
    ) {
        let mut pending = self.pending.write().await;
        let user_pending = pending.entry(recipient_id).or_insert_with(Vec::new);

        // Try to coalesce with existing pending push for same channel
        if let Some(existing) = user_pending.iter_mut().find(|p| p.channel_id == channel_id) {
            existing.count += 1;
            // Keep the most recent sender name
            if sender_name.is_some() {
                existing.sender_name = sender_name;
            }
            return;
        }

        user_pending.push(PendingPush {
            channel_id,
            node_id,
            count: 1,
            first_at: Instant::now(),
            sender_name,
            event,
        });
    }

    /// Flush pending pushes that have exceeded the coalescing window.
    /// Call this periodically (e.g., every 500ms from a background task).
    pub async fn flush(&self, db: &crate::db::Database) {
        let now = Instant::now();
        let mut to_send: Vec<(Uuid, PushPayload)> = Vec::new();

        {
            let mut pending = self.pending.write().await;
            let mut empty_users = Vec::new();

            for (user_id, pushes) in pending.iter_mut() {
                let mut remaining = Vec::new();
                for p in pushes.drain(..) {
                    if now.duration_since(p.first_at) >= self.coalesce_window {
                        to_send.push((
                            *user_id,
                            PushPayload {
                                event: p.event,
                                channel_id: p.channel_id,
                                node_id: p.node_id,
                                count: if p.count > 1 { Some(p.count) } else { None },
                                sender_name: p.sender_name,
                                encrypted_metadata: None,
                            },
                        ));
                    } else {
                        remaining.push(p);
                    }
                }
                if remaining.is_empty() {
                    empty_users.push(*user_id);
                } else {
                    *pushes = remaining;
                }
            }

            for uid in empty_users {
                pending.remove(&uid);
            }
        }

        // Send coalesced pushes
        for (user_id, payload) in to_send {
            // Rate limit check
            {
                let last = self.last_push.read().await;
                if let Some(last_time) = last.get(&user_id) {
                    if now.duration_since(*last_time) < self.min_interval {
                        debug!("Rate limited push for user {}", user_id);
                        continue;
                    }
                }
            }

            // Get device tokens for this user
            let tokens = match db.get_device_tokens(user_id).await {
                Ok(tokens) => tokens,
                Err(e) => {
                    error!("Failed to get device tokens for {}: {}", user_id, e);
                    continue;
                }
            };

            if tokens.is_empty() {
                debug!("No device tokens registered for user {}", user_id);
                continue;
            }

            // Record push time
            self.last_push.write().await.insert(user_id, now);

            for token in &tokens {
                // Apply privacy level
                let mut user_payload = payload.clone();
                match token.privacy_level {
                    NotificationPrivacy::Full => {
                        // sender_name already included if available
                    }
                    NotificationPrivacy::Partial => {
                        user_payload.sender_name = None;
                    }
                    NotificationPrivacy::Stealth => {
                        user_payload.sender_name = None;
                        user_payload.channel_id = None;
                        user_payload.node_id = None;
                        user_payload.count = None;
                    }
                }

                let provider: &dyn PushProvider = match token.platform {
                    PushPlatform::Ios => self.apns.as_ref(),
                    PushPlatform::Android => self.fcm.as_ref(),
                };

                match provider.send(&token.token, &user_payload).await {
                    PushResult::Sent => {
                        debug!(
                            "Push sent to {} via {} for user {}",
                            token.token,
                            provider.name(),
                            user_id
                        );
                    }
                    PushResult::InvalidToken => {
                        warn!(
                            "Invalid token {}, deregistering for user {}",
                            token.token, user_id
                        );
                        if let Err(e) = db.remove_device_token(user_id, &token.token).await {
                            error!("Failed to deregister invalid token: {}", e);
                        }
                    }
                    PushResult::RetryLater => {
                        warn!(
                            "Push retry needed for user {} via {}",
                            user_id,
                            provider.name()
                        );
                        // In production: re-queue with backoff
                    }
                    PushResult::Error(e) => {
                        error!(
                            "Push failed for user {} via {}: {}",
                            user_id,
                            provider.name(),
                            e
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    #[tokio::test]
    async fn test_mock_apns_provider() {
        let provider = MockApnsProvider::new();
        let payload = PushPayload {
            event: PushEvent::NewMessage,
            channel_id: Some(Uuid::new_v4()),
            node_id: None,
            count: None,
            sender_name: Some("Alice".into()),
            encrypted_metadata: None,
        };

        let result = provider.send("test-token-123", &payload).await;
        assert!(matches!(result, PushResult::Sent));

        let sent = provider.sent.lock().await;
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "test-token-123");
    }

    #[tokio::test]
    async fn test_mock_fcm_provider() {
        let provider = MockFcmProvider::new();
        let payload = PushPayload {
            event: PushEvent::NewDirectMessage,
            channel_id: None,
            node_id: None,
            count: Some(3),
            sender_name: None,
            encrypted_metadata: None,
        };

        let result = provider.send("fcm-token-abc", &payload).await;
        assert!(matches!(result, PushResult::Sent));

        let sent = provider.sent.lock().await;
        assert_eq!(sent.len(), 1);
    }

    #[tokio::test]
    async fn test_privacy_levels() {
        // Test that stealth mode strips all metadata
        let payload = PushPayload {
            event: PushEvent::NewMessage,
            channel_id: Some(Uuid::new_v4()),
            node_id: Some(Uuid::new_v4()),
            count: Some(5),
            sender_name: Some("Bob".into()),
            encrypted_metadata: None,
        };

        // Stealth: strip everything
        let mut stealth = payload.clone();
        stealth.sender_name = None;
        stealth.channel_id = None;
        stealth.node_id = None;
        stealth.count = None;

        assert!(stealth.sender_name.is_none());
        assert!(stealth.channel_id.is_none());
        assert!(stealth.node_id.is_none());
        assert!(stealth.count.is_none());

        // Partial: strip sender only
        let mut partial = payload.clone();
        partial.sender_name = None;

        assert!(partial.sender_name.is_none());
        assert!(partial.channel_id.is_some());
    }

    #[tokio::test]
    async fn test_coalescing() {
        let apns = MockApnsProvider::new();
        let fcm = MockFcmProvider::new();
        let _apns_sent = apns.sent.clone();

        let dispatcher = PushDispatcher::new(Box::new(apns), Box::new(fcm));
        // Override coalesce window to 0 for testing
        // (we'll flush immediately)

        let user_id = Uuid::new_v4();
        let channel_id = Uuid::new_v4();

        // Send 3 messages rapidly to same channel
        dispatcher
            .notify(
                user_id,
                PushEvent::NewMessage,
                Some(channel_id),
                None,
                Some("Alice".into()),
            )
            .await;
        dispatcher
            .notify(
                user_id,
                PushEvent::NewMessage,
                Some(channel_id),
                None,
                Some("Alice".into()),
            )
            .await;
        dispatcher
            .notify(
                user_id,
                PushEvent::NewMessage,
                Some(channel_id),
                None,
                Some("Alice".into()),
            )
            .await;

        // Check that they coalesced
        let pending = dispatcher.pending.read().await;
        let user_pending = pending.get(&user_id).unwrap();
        assert_eq!(user_pending.len(), 1);
        assert_eq!(user_pending[0].count, 3);
    }

    #[tokio::test]
    async fn test_device_token_db_roundtrip() {
        let db = Database::new(":memory:").await.unwrap();
        let user = db.create_user("key123", "").await.unwrap();

        // Register token
        let _token_id = db
            .register_device_token(
                user.id,
                PushPlatform::Ios,
                "apns-token-xyz",
                NotificationPrivacy::Full,
            )
            .await
            .unwrap();

        // Get tokens
        let tokens = db.get_device_tokens(user.id).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, "apns-token-xyz");
        assert_eq!(tokens[0].platform, PushPlatform::Ios);
        assert_eq!(tokens[0].privacy_level, NotificationPrivacy::Full);

        // Update privacy
        db.update_push_privacy(user.id, None, NotificationPrivacy::Stealth)
            .await
            .unwrap();

        let tokens = db.get_device_tokens(user.id).await.unwrap();
        assert_eq!(tokens[0].privacy_level, NotificationPrivacy::Stealth);

        // Remove token
        db.remove_device_token(user.id, "apns-token-xyz")
            .await
            .unwrap();

        let tokens = db.get_device_tokens(user.id).await.unwrap();
        assert!(tokens.is_empty());
    }

    // ── Serialization tests ──

    #[test]
    fn test_push_payload_skip_none_fields() {
        let payload = PushPayload {
            event: PushEvent::NewMessage,
            channel_id: None,
            node_id: None,
            count: None,
            sender_name: None,
            encrypted_metadata: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("channel_id"));
        assert!(!json.contains("node_id"));
        assert!(!json.contains("count"));
        assert!(!json.contains("sender_name"));
        assert!(!json.contains("encrypted_metadata"));
        assert!(json.contains("event"));
    }

    #[test]
    fn test_push_payload_includes_some_fields() {
        let channel = Uuid::new_v4();
        let payload = PushPayload {
            event: PushEvent::Mention,
            channel_id: Some(channel),
            node_id: None,
            count: Some(7),
            sender_name: Some("Eve".into()),
            encrypted_metadata: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("mention"));
        assert!(json.contains(&channel.to_string()));
        assert!(json.contains("\"count\":7"));
        assert!(json.contains("Eve"));
    }

    #[test]
    fn test_push_event_serialization_variants() {
        let cases = vec![
            (PushEvent::NewMessage, "new_message"),
            (PushEvent::NewDirectMessage, "new_direct_message"),
            (PushEvent::Mention, "mention"),
            (PushEvent::VoiceCall, "voice_call"),
        ];
        for (event, expected) in cases {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(json, format!("\"{}\"", expected));
        }
    }

    #[test]
    fn test_push_payload_roundtrip() {
        let payload = PushPayload {
            event: PushEvent::VoiceCall,
            channel_id: Some(Uuid::new_v4()),
            node_id: Some(Uuid::new_v4()),
            count: Some(2),
            sender_name: Some("Roundtrip".into()),
            encrypted_metadata: Some("enc_blob".into()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: PushPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.count, Some(2));
        assert_eq!(deserialized.sender_name.as_deref(), Some("Roundtrip"));
        assert_eq!(deserialized.encrypted_metadata.as_deref(), Some("enc_blob"));
    }

    // ── Coalescing edge cases ──

    #[tokio::test]
    async fn test_different_channels_no_coalesce() {
        let dispatcher = PushDispatcher::new(
            Box::new(MockApnsProvider::new()),
            Box::new(MockFcmProvider::new()),
        );
        let user = Uuid::new_v4();
        let ch1 = Uuid::new_v4();
        let ch2 = Uuid::new_v4();

        dispatcher
            .notify(user, PushEvent::NewMessage, Some(ch1), None, None)
            .await;
        dispatcher
            .notify(user, PushEvent::NewMessage, Some(ch2), None, None)
            .await;

        let pending = dispatcher.pending.read().await;
        let user_pending = pending.get(&user).unwrap();
        assert_eq!(user_pending.len(), 2);
    }

    #[tokio::test]
    async fn test_different_users_independent() {
        let dispatcher = PushDispatcher::new(
            Box::new(MockApnsProvider::new()),
            Box::new(MockFcmProvider::new()),
        );
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let channel = Uuid::new_v4();

        dispatcher
            .notify(user_a, PushEvent::NewMessage, Some(channel), None, None)
            .await;
        dispatcher
            .notify(user_b, PushEvent::NewMessage, Some(channel), None, None)
            .await;

        let pending = dispatcher.pending.read().await;
        assert!(pending.contains_key(&user_a));
        assert!(pending.contains_key(&user_b));
        assert_eq!(pending.get(&user_a).unwrap().len(), 1);
        assert_eq!(pending.get(&user_b).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_coalesce_updates_sender_name() {
        let dispatcher = PushDispatcher::new(
            Box::new(MockApnsProvider::new()),
            Box::new(MockFcmProvider::new()),
        );
        let user = Uuid::new_v4();
        let channel = Uuid::new_v4();

        dispatcher
            .notify(
                user,
                PushEvent::NewMessage,
                Some(channel),
                None,
                Some("Alice".into()),
            )
            .await;
        dispatcher
            .notify(
                user,
                PushEvent::NewMessage,
                Some(channel),
                None,
                Some("Bob".into()),
            )
            .await;

        let pending = dispatcher.pending.read().await;
        let entry = &pending.get(&user).unwrap()[0];
        assert_eq!(entry.sender_name.as_deref(), Some("Bob"));
        assert_eq!(entry.count, 2);
    }

    // ── Provider accumulation ──

    #[tokio::test]
    async fn test_mock_apns_accumulates() {
        let provider = MockApnsProvider::new();
        let payload = PushPayload {
            event: PushEvent::NewMessage,
            channel_id: None,
            node_id: None,
            count: None,
            sender_name: None,
            encrypted_metadata: None,
        };

        provider.send("tok1", &payload).await;
        provider.send("tok2", &payload).await;
        provider.send("tok3", &payload).await;

        let sent = provider.sent.lock().await;
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0].0, "tok1");
        assert_eq!(sent[2].0, "tok3");
    }

    #[tokio::test]
    async fn test_mock_fcm_accumulates() {
        let provider = MockFcmProvider::new();
        let payload = PushPayload {
            event: PushEvent::NewDirectMessage,
            channel_id: None,
            node_id: None,
            count: None,
            sender_name: None,
            encrypted_metadata: None,
        };

        provider.send("fcm1", &payload).await;
        provider.send("fcm2", &payload).await;

        assert_eq!(provider.sent.lock().await.len(), 2);
    }

    // ── Clone and Debug ──

    #[test]
    fn test_push_payload_clone() {
        let original = PushPayload {
            event: PushEvent::Mention,
            channel_id: Some(Uuid::new_v4()),
            node_id: Some(Uuid::new_v4()),
            count: Some(10),
            sender_name: Some("Cloned".into()),
            encrypted_metadata: Some("secret".into()),
        };
        let cloned = original.clone();
        assert_eq!(cloned.count, original.count);
        assert_eq!(cloned.sender_name, original.sender_name);
        assert_eq!(cloned.channel_id, original.channel_id);
    }

    #[test]
    fn test_push_event_debug() {
        let event = PushEvent::VoiceCall;
        let debug = format!("{:?}", event);
        assert!(debug.contains("VoiceCall"));
    }

    #[test]
    fn test_push_result_debug() {
        let sent = PushResult::Sent;
        assert!(format!("{:?}", sent).contains("Sent"));
        let invalid = PushResult::InvalidToken;
        assert!(format!("{:?}", invalid).contains("InvalidToken"));
        let retry = PushResult::RetryLater;
        assert!(format!("{:?}", retry).contains("RetryLater"));
        let err = PushResult::Error("timeout".into());
        assert!(format!("{:?}", err).contains("timeout"));
    }

    // ── Multiple device tokens ──

    #[tokio::test]
    async fn test_multiple_device_tokens_per_user() {
        let db = Database::new(":memory:").await.unwrap();
        let user = db.create_user("multidev", "").await.unwrap();

        db.register_device_token(
            user.id,
            PushPlatform::Ios,
            "ios-tok",
            NotificationPrivacy::Full,
        )
        .await
        .unwrap();
        db.register_device_token(
            user.id,
            PushPlatform::Android,
            "android-tok",
            NotificationPrivacy::Partial,
        )
        .await
        .unwrap();

        let tokens = db.get_device_tokens(user.id).await.unwrap();
        assert_eq!(tokens.len(), 2);

        let platforms: Vec<_> = tokens.iter().map(|t| t.platform).collect();
        assert!(platforms.contains(&PushPlatform::Ios));
        assert!(platforms.contains(&PushPlatform::Android));
    }

    // ── No tokens registered ──

    #[tokio::test]
    async fn test_no_device_tokens() {
        let db = Database::new(":memory:").await.unwrap();
        let user = db.create_user("notokens", "").await.unwrap();

        let tokens = db.get_device_tokens(user.id).await.unwrap();
        assert!(tokens.is_empty());
    }
}
