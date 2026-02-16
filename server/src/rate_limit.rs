//! Rate limiting module for Accord server
//!
//! Implements sliding window rate limiting per user and action type

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Types of actions that can be rate limited
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionType {
    Message,
    DirectMessage,
    FileUpload,
    Reaction,
    ProfileUpdate,
}

impl ActionType {
    /// Get the default rate limit for this action type (requests per minute)
    pub fn default_limit(&self) -> usize {
        match self {
            ActionType::Message => 30,
            ActionType::DirectMessage => 30,
            ActionType::FileUpload => 5,
            ActionType::Reaction => 20,
            ActionType::ProfileUpdate => 5,
        }
    }

    /// Get the time window for this action type
    pub fn window_duration(&self) -> Duration {
        Duration::from_secs(60) // 1 minute window for all actions
    }
}

/// Error returned when rate limit is exceeded
#[derive(Debug)]
pub struct RateLimitError {
    pub message: String,
    pub retry_after_secs: u64,
    pub remaining: usize,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rate limit exceeded: {}", self.message)
    }
}

impl std::error::Error for RateLimitError {}

/// Rate limiter using sliding window algorithm
#[derive(Debug)]
pub struct RateLimiter {
    /// Tracks timestamps of actions per (user_id, action_type)
    windows: Arc<RwLock<HashMap<(Uuid, ActionType), VecDeque<Instant>>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an action is allowed for a user
    pub async fn check(&self, user_id: Uuid, action: ActionType) -> Result<(), RateLimitError> {
        let mut windows = self.windows.write().await;
        let now = Instant::now();
        let window_duration = action.window_duration();
        let limit = action.default_limit();

        // Get or create the window for this user+action combination
        let window = windows
            .entry((user_id, action))
            .or_insert_with(VecDeque::new);

        // Remove entries older than the window duration
        while let Some(&front_time) = window.front() {
            if now.duration_since(front_time) > window_duration {
                window.pop_front();
            } else {
                break;
            }
        }

        // Check if adding this action would exceed the limit
        if window.len() >= limit {
            let oldest = window.front().copied().unwrap_or(now);
            let retry_after = window_duration
                .saturating_sub(now.duration_since(oldest))
                .as_secs();

            return Err(RateLimitError {
                message: format!(
                    "{:?} rate limit exceeded. Limit: {} per minute",
                    action, limit
                ),
                retry_after_secs: retry_after,
                remaining: 0,
            });
        }

        // Add the current action to the window
        window.push_back(now);

        Ok(())
    }

    /// Get the current usage and remaining capacity for a user+action
    pub async fn get_status(&self, user_id: Uuid, action: ActionType) -> (usize, usize) {
        let mut windows = self.windows.write().await;
        let now = Instant::now();
        let window_duration = action.window_duration();
        let limit = action.default_limit();

        let window = windows
            .entry((user_id, action))
            .or_insert_with(VecDeque::new);

        // Clean up old entries
        while let Some(&front_time) = window.front() {
            if now.duration_since(front_time) > window_duration {
                window.pop_front();
            } else {
                break;
            }
        }

        let current = window.len();
        let remaining = limit.saturating_sub(current);

        (current, remaining)
    }

    /// Clear all rate limiting data (useful for testing)
    pub async fn clear(&self) {
        let mut windows = self.windows.write().await;
        windows.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_action_type_defaults() {
        assert_eq!(ActionType::Message.default_limit(), 30);
        assert_eq!(ActionType::DirectMessage.default_limit(), 30);
        assert_eq!(ActionType::FileUpload.default_limit(), 5);
        assert_eq!(ActionType::Reaction.default_limit(), 20);
        assert_eq!(ActionType::ProfileUpdate.default_limit(), 5);
    }

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Should allow the first message
        assert!(limiter.check(user_id, ActionType::Message).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_exceeds_limit() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Add messages up to the limit (30 for Message)
        for _ in 0..30 {
            limiter
                .check(user_id, ActionType::Message)
                .await
                .expect("Should be under limit");
        }

        // The next message should be rate limited
        let result = limiter.check(user_id, ActionType::Message).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.remaining, 0);
        assert!(err.message.contains("Message rate limit exceeded"));
    }

    #[tokio::test]
    async fn test_different_action_types_independent() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Fill up Message limit
        for _ in 0..30 {
            limiter
                .check(user_id, ActionType::Message)
                .await
                .expect("Should be under limit");
        }

        // Message should be rate limited
        assert!(limiter.check(user_id, ActionType::Message).await.is_err());

        // But Reaction should still work (different limit)
        assert!(limiter.check(user_id, ActionType::Reaction).await.is_ok());
    }

    #[tokio::test]
    async fn test_different_users_independent() {
        let limiter = RateLimiter::new();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        // Fill up user1's limit
        for _ in 0..5 {
            limiter
                .check(user1, ActionType::FileUpload)
                .await
                .expect("Should be under limit");
        }

        // user1 should be rate limited
        assert!(limiter.check(user1, ActionType::FileUpload).await.is_err());

        // user2 should still be able to upload
        assert!(limiter.check(user2, ActionType::FileUpload).await.is_ok());
    }

    #[tokio::test]
    async fn test_get_status() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Initial status should be (0, 5) for FileUpload
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 0);
        assert_eq!(remaining, 5);

        // After one upload
        limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .expect("Should be allowed");

        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 1);
        assert_eq!(remaining, 4);
    }

    #[tokio::test]
    async fn test_clear() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Add some actions
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::FileUpload)
                .await
                .expect("Should be under limit");
        }

        // Should be at limit
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 5);
        assert_eq!(remaining, 0);

        // Clear and check again
        limiter.clear().await;
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 0);
        assert_eq!(remaining, 5);
    }

    #[tokio::test]
    async fn test_sliding_window_cleanup() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // This test would require manipulating time to properly test the sliding window
        // For now, we test that the basic structure works
        assert!(limiter
            .check(user_id, ActionType::ProfileUpdate)
            .await
            .is_ok());

        let (current, remaining) = limiter.get_status(user_id, ActionType::ProfileUpdate).await;
        assert_eq!(current, 1);
        assert_eq!(remaining, 4);
    }

    #[tokio::test]
    async fn test_rate_limit_error_details() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Fill up the ProfileUpdate limit (5)
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should be under limit");
        }

        // Next one should fail with proper error details
        let result = limiter.check(user_id, ActionType::ProfileUpdate).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.remaining, 0);
        assert!(err.message.contains("ProfileUpdate"));
        assert!(err.message.contains("5 per minute"));
        assert!(err.retry_after_secs <= 60); // Should be within the window duration
    }
}
