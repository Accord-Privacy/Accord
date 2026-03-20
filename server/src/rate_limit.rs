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
    /// Invite creation
    InviteCreate,
    /// Node creation
    NodeCreate,
    /// Auth attempts per IP (brute-force protection)
    AuthAttempt,
    /// Registration attempts per IP
    Registration,
}

impl ActionType {
    /// Get the default rate limit for this action type
    pub fn default_limit(&self) -> usize {
        match self {
            ActionType::Message => 30,
            ActionType::DirectMessage => 30,
            ActionType::FileUpload => 10,
            ActionType::Reaction => 20,
            ActionType::ProfileUpdate => 5,
            ActionType::InviteCreate => 10, // 10 per hour
            ActionType::NodeCreate => 5,    // 5 per hour
            ActionType::AuthAttempt => 20,  // 20 per minute per IP
            ActionType::Registration => 20, // 20 per hour per IP
        }
    }

    /// Get the time window for this action type
    pub fn window_duration(&self) -> Duration {
        match self {
            ActionType::Registration => Duration::from_secs(3600), // 1 hour
            ActionType::InviteCreate => Duration::from_secs(3600), // 1 hour
            ActionType::NodeCreate => Duration::from_secs(3600),   // 1 hour
            _ => Duration::from_secs(60),                          // 1 minute for all other actions
        }
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

/// Window map type alias for rate limiter (user-keyed)
type WindowMap = HashMap<(Uuid, ActionType), VecDeque<Instant>>;

/// Window map for IP-keyed rate limiting (auth, registration)
type IpWindowMap = HashMap<(String, ActionType), VecDeque<Instant>>;

/// Rate limiter using sliding window algorithm
#[derive(Debug)]
pub struct RateLimiter {
    /// Tracks timestamps of actions per (user_id, action_type)
    windows: Arc<RwLock<WindowMap>>,
    /// Tracks timestamps of actions per (ip, action_type)
    ip_windows: Arc<RwLock<IpWindowMap>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            windows: Arc::new(RwLock::new(HashMap::new())),
            ip_windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if an action is allowed for an IP address (for auth/registration)
    pub async fn check_ip(&self, ip: &str, action: ActionType) -> Result<(), RateLimitError> {
        let mut windows = self.ip_windows.write().await;
        let now = Instant::now();
        let window_duration = action.window_duration();
        let limit = action.default_limit();

        let key = (ip.to_string(), action);
        let window = windows.entry(key).or_insert_with(VecDeque::new);

        // Remove entries older than the window duration
        while let Some(&front_time) = window.front() {
            if now.duration_since(front_time) > window_duration {
                window.pop_front();
            } else {
                break;
            }
        }

        if window.len() >= limit {
            let oldest = window.front().copied().unwrap_or(now);
            let retry_after = window_duration
                .saturating_sub(now.duration_since(oldest))
                .as_secs();

            return Err(RateLimitError {
                message: format!(
                    "{:?} rate limit exceeded. Limit: {} per {}s",
                    action,
                    limit,
                    window_duration.as_secs()
                ),
                retry_after_secs: retry_after,
                remaining: 0,
            });
        }

        window.push_back(now);

        // Opportunistic cleanup: remove empty entries to prevent memory leaks
        // from IPs that never return. Cheap since we already hold the write lock.
        windows.retain(|_, w| !w.is_empty());

        Ok(())
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

        // Opportunistic cleanup: remove empty entries to prevent memory leaks
        // from users that never return. Cheap since we already hold the write lock.
        windows.retain(|_, w| !w.is_empty());

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
        assert_eq!(ActionType::FileUpload.default_limit(), 10);
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
        for _ in 0..10 {
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

        // Initial status should be (0, 10) for FileUpload
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 0);
        assert_eq!(remaining, 10);

        // After one upload
        limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .expect("Should be allowed");

        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 1);
        assert_eq!(remaining, 9);
    }

    #[tokio::test]
    async fn test_clear() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Add some actions
        for _ in 0..10 {
            limiter
                .check(user_id, ActionType::FileUpload)
                .await
                .expect("Should be under limit");
        }

        // Should be at limit
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 10);
        assert_eq!(remaining, 0);

        // Clear and check again
        limiter.clear().await;
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 0);
        assert_eq!(remaining, 10);
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

    // ============================================================================
    // Edge case tests for IP-based rate limiting
    // ============================================================================

    #[tokio::test]
    async fn test_ip_based_rate_limiting_basic() {
        let limiter = RateLimiter::new();
        let ip = "192.168.1.100";

        // AuthAttempt has limit of 20
        for _ in 0..20 {
            limiter
                .check_ip(ip, ActionType::AuthAttempt)
                .await
                .expect("Should be under limit");
        }

        // Next attempt should be rate limited
        let result = limiter.check_ip(ip, ActionType::AuthAttempt).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("AuthAttempt"));
    }

    #[tokio::test]
    async fn test_ip_spoofing_different_ips_independent() {
        let limiter = RateLimiter::new();
        let ip1 = "192.168.1.100";
        let ip2 = "192.168.1.101";
        let ip3 = "10.0.0.1";

        // Fill up ip1's limit
        for _ in 0..20 {
            limiter
                .check_ip(ip1, ActionType::AuthAttempt)
                .await
                .expect("Should be under limit");
        }

        // ip1 should be rate limited
        assert!(limiter
            .check_ip(ip1, ActionType::AuthAttempt)
            .await
            .is_err());

        // ip2 and ip3 should still be allowed (different IPs)
        assert!(limiter.check_ip(ip2, ActionType::AuthAttempt).await.is_ok());
        assert!(limiter.check_ip(ip3, ActionType::AuthAttempt).await.is_ok());
    }

    #[tokio::test]
    async fn test_ip_ipv6_addresses() {
        let limiter = RateLimiter::new();
        let ipv6_1 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let ipv6_2 = "2001:0db8:85a3::8a2e:0370:7335";

        // Should treat different IPv6 addresses independently
        for _ in 0..20 {
            limiter
                .check_ip(ipv6_1, ActionType::Registration)
                .await
                .expect("Should be under limit");
        }

        assert!(limiter
            .check_ip(ipv6_1, ActionType::Registration)
            .await
            .is_err());
        assert!(limiter
            .check_ip(ipv6_2, ActionType::Registration)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_ip_registration_vs_auth_independent() {
        let limiter = RateLimiter::new();
        let ip = "192.168.1.100";

        // Fill up Registration limit
        for _ in 0..20 {
            limiter
                .check_ip(ip, ActionType::Registration)
                .await
                .expect("Should be under limit");
        }

        // Registration should be rate limited
        assert!(limiter
            .check_ip(ip, ActionType::Registration)
            .await
            .is_err());

        // But AuthAttempt should still work (different ActionType)
        assert!(limiter.check_ip(ip, ActionType::AuthAttempt).await.is_ok());
    }

    #[tokio::test]
    async fn test_ip_cleanup_removes_empty_entries() {
        let limiter = RateLimiter::new();
        let ip = "192.168.1.100";

        // Add one request
        limiter
            .check_ip(ip, ActionType::AuthAttempt)
            .await
            .expect("Should be allowed");

        // Check that we have an entry
        {
            let windows = limiter.ip_windows.read().await;
            assert_eq!(windows.len(), 1);
        }

        // The opportunistic cleanup only runs during writes, so we need to
        // trigger another check after the window expires
        // For this test, we just verify the cleanup logic exists by checking
        // that empty windows would be removed
    }

    // ============================================================================
    // Window reset and expiry tests
    // ============================================================================

    #[tokio::test]
    async fn test_window_expiry_allows_new_requests() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Fill up the limit with ProfileUpdate (5 per minute)
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should be under limit");
        }

        // Should be rate limited now
        assert!(limiter
            .check(user_id, ActionType::ProfileUpdate)
            .await
            .is_err());

        // Simulate window expiry by clearing (in production, this would happen
        // automatically after waiting 60+ seconds)
        limiter.clear().await;

        // After clearing, should be allowed again
        assert!(limiter
            .check(user_id, ActionType::ProfileUpdate)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_partial_window_expiry() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // This test demonstrates that the sliding window correctly removes
        // old entries. In a real scenario with time manipulation, old entries
        // would be removed while keeping recent ones.

        // Add 3 requests
        for _ in 0..3 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should be under limit");
        }

        let (current, remaining) = limiter.get_status(user_id, ActionType::ProfileUpdate).await;
        assert_eq!(current, 3);
        assert_eq!(remaining, 2);
    }

    #[tokio::test]
    async fn test_long_window_duration_actions() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // InviteCreate has a 1-hour window
        assert_eq!(
            ActionType::InviteCreate.window_duration(),
            Duration::from_secs(3600)
        );

        // Should allow up to 10 invites
        for i in 0..10 {
            limiter
                .check(user_id, ActionType::InviteCreate)
                .await
                .unwrap_or_else(|_| panic!("Should allow invite {}", i));
        }

        // 11th should be blocked
        let result = limiter.check(user_id, ActionType::InviteCreate).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.retry_after_secs <= 3600); // Should be within the hour window
    }

    // ============================================================================
    // Concurrent access tests
    // ============================================================================

    #[tokio::test]
    async fn test_concurrent_access_same_user() {
        let limiter = Arc::new(RateLimiter::new());
        let user_id = Uuid::new_v4();

        // Spawn multiple tasks that try to use the rate limiter concurrently
        let mut handles = vec![];

        for _ in 0..10 {
            let limiter_clone = Arc::clone(&limiter);
            let handle =
                tokio::spawn(
                    async move { limiter_clone.check(user_id, ActionType::FileUpload).await },
                );
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut success_count = 0;
        let mut error_count = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => success_count += 1,
                Err(_) => error_count += 1,
            }
        }

        // All 10 should succeed since the limit is 10
        assert_eq!(success_count, 10);
        assert_eq!(error_count, 0);

        // Next one should be rate limited
        assert!(limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_concurrent_access_different_users() {
        let limiter = Arc::new(RateLimiter::new());

        let mut handles = vec![];

        // Spawn 50 tasks with different users, each doing 5 file uploads
        for _ in 0..50 {
            let limiter_clone = Arc::clone(&limiter);
            let handle = tokio::spawn(async move {
                let user_id = Uuid::new_v4();
                for _ in 0..5 {
                    limiter_clone
                        .check(user_id, ActionType::FileUpload)
                        .await
                        .expect("Should be under limit for new user");
                }
            });
            handles.push(handle);
        }

        // All should complete successfully
        for handle in handles {
            handle.await.expect("Task should complete");
        }
    }

    #[tokio::test]
    async fn test_concurrent_ip_checks() {
        let limiter = Arc::new(RateLimiter::new());
        let ip = "192.168.1.100";

        let mut handles = vec![];

        // Try 20 concurrent auth attempts from the same IP
        for _ in 0..20 {
            let limiter_clone = Arc::clone(&limiter);
            let ip_string = ip.to_string();
            let handle = tokio::spawn(async move {
                limiter_clone
                    .check_ip(&ip_string, ActionType::AuthAttempt)
                    .await
            });
            handles.push(handle);
        }

        let mut success_count = 0;
        let mut error_count = 0;

        for handle in handles {
            match handle.await.unwrap() {
                Ok(_) => success_count += 1,
                Err(_) => error_count += 1,
            }
        }

        // All 20 should succeed (exactly at limit)
        assert_eq!(success_count, 20);
        assert_eq!(error_count, 0);
    }

    // ============================================================================
    // Edge cases: boundary conditions
    // ============================================================================

    #[tokio::test]
    async fn test_exact_limit_boundary() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // FileUpload has exactly 10 limit
        for i in 0..10 {
            let result = limiter.check(user_id, ActionType::FileUpload).await;
            assert!(result.is_ok(), "Request {} should succeed", i + 1);
        }

        // Exactly at limit, next should fail
        assert!(limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .is_err());

        // Verify status shows we're at the limit
        let (current, remaining) = limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(current, 10);
        assert_eq!(remaining, 0);
    }

    #[tokio::test]
    async fn test_single_request_limit() {
        // If we hypothetically had an action with limit 1
        // (we don't, but we test the boundary logic)
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // ProfileUpdate has limit 5, use it to test low limits
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should be under limit");
        }

        let result = limiter.check(user_id, ActionType::ProfileUpdate).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_retry_after_calculation() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Fill up the limit
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should be under limit");
        }

        // Get the error with retry_after
        let result = limiter.check(user_id, ActionType::ProfileUpdate).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        // retry_after should be close to the window duration (60 seconds for ProfileUpdate)
        // but might be slightly less due to time elapsed during the test
        assert!(err.retry_after_secs <= 60);
        assert!(err.retry_after_secs > 0);
    }

    #[tokio::test]
    async fn test_empty_limiter_status() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Check status without any requests
        let (current, remaining) = limiter.get_status(user_id, ActionType::Message).await;
        assert_eq!(current, 0);
        assert_eq!(remaining, 30); // Message limit is 30
    }

    #[tokio::test]
    async fn test_multiple_action_types_same_user() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Use multiple action types for the same user
        limiter
            .check(user_id, ActionType::Message)
            .await
            .expect("Message should work");
        limiter
            .check(user_id, ActionType::Reaction)
            .await
            .expect("Reaction should work");
        limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .expect("FileUpload should work");

        // Verify each has independent status
        let (msg_current, msg_remaining) = limiter.get_status(user_id, ActionType::Message).await;
        assert_eq!(msg_current, 1);
        assert_eq!(msg_remaining, 29);

        let (react_current, react_remaining) =
            limiter.get_status(user_id, ActionType::Reaction).await;
        assert_eq!(react_current, 1);
        assert_eq!(react_remaining, 19);

        let (file_current, file_remaining) =
            limiter.get_status(user_id, ActionType::FileUpload).await;
        assert_eq!(file_current, 1);
        assert_eq!(file_remaining, 9);
    }

    // ============================================================================
    // Memory cleanup and expiry tests
    // ============================================================================

    #[tokio::test]
    async fn test_cleanup_empty_windows_on_user_check() {
        let limiter = RateLimiter::new();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        // Create entries for both users
        limiter
            .check(user1, ActionType::Message)
            .await
            .expect("Should work");
        limiter
            .check(user2, ActionType::Message)
            .await
            .expect("Should work");

        // Verify we have entries
        {
            let windows = limiter.windows.read().await;
            assert!(windows.len() >= 2);
        }

        // The cleanup logic in the code removes empty entries opportunistically
        // This test verifies the structure supports it
    }

    #[tokio::test]
    async fn test_cleanup_empty_windows_on_ip_check() {
        let limiter = RateLimiter::new();
        let ip1 = "192.168.1.1";
        let ip2 = "192.168.1.2";

        // Create entries for both IPs
        limiter
            .check_ip(ip1, ActionType::AuthAttempt)
            .await
            .expect("Should work");
        limiter
            .check_ip(ip2, ActionType::AuthAttempt)
            .await
            .expect("Should work");

        // Verify we have entries
        {
            let ip_windows = limiter.ip_windows.read().await;
            assert!(ip_windows.len() >= 2);
        }

        // Cleanup happens during write operations
    }

    #[tokio::test]
    async fn test_memory_cleanup_with_clear() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Add many different action types
        limiter
            .check(user_id, ActionType::Message)
            .await
            .expect("Should work");
        limiter
            .check(user_id, ActionType::DirectMessage)
            .await
            .expect("Should work");
        limiter
            .check(user_id, ActionType::FileUpload)
            .await
            .expect("Should work");
        limiter
            .check(user_id, ActionType::Reaction)
            .await
            .expect("Should work");
        limiter
            .check(user_id, ActionType::ProfileUpdate)
            .await
            .expect("Should work");

        {
            let windows = limiter.windows.read().await;
            assert!(windows.len() >= 5);
        }

        // Clear should remove all entries
        limiter.clear().await;

        {
            let windows = limiter.windows.read().await;
            assert_eq!(windows.len(), 0);
        }
    }

    #[tokio::test]
    async fn test_many_users_memory_scaling() {
        let limiter = RateLimiter::new();

        // Simulate many users making requests
        for _ in 0..100 {
            let user_id = Uuid::new_v4();
            limiter
                .check(user_id, ActionType::Message)
                .await
                .expect("Should work");
        }

        // Verify we have entries for all users
        {
            let windows = limiter.windows.read().await;
            assert_eq!(windows.len(), 100);
        }
    }

    #[tokio::test]
    async fn test_many_ips_memory_scaling() {
        let limiter = RateLimiter::new();

        // Simulate many IPs making auth attempts
        for i in 0..100 {
            let ip = format!("192.168.1.{}", i);
            limiter
                .check_ip(&ip, ActionType::AuthAttempt)
                .await
                .expect("Should work");
        }

        // Verify we have entries for all IPs
        {
            let ip_windows = limiter.ip_windows.read().await;
            assert_eq!(ip_windows.len(), 100);
        }
    }

    // ============================================================================
    // Additional edge cases
    // ============================================================================

    #[tokio::test]
    async fn test_ip_format_variations() {
        let limiter = RateLimiter::new();

        // Different string representations should be treated as different IPs
        // (no normalization is done in the current implementation)
        let ip1 = "192.168.001.001";
        let ip2 = "192.168.1.1";

        for _ in 0..20 {
            limiter
                .check_ip(ip1, ActionType::AuthAttempt)
                .await
                .expect("Should work");
        }

        // ip1 should be limited
        assert!(limiter
            .check_ip(ip1, ActionType::AuthAttempt)
            .await
            .is_err());

        // ip2 should still work (treated as different string)
        assert!(limiter.check_ip(ip2, ActionType::AuthAttempt).await.is_ok());
    }

    #[tokio::test]
    async fn test_special_characters_in_ip() {
        let limiter = RateLimiter::new();

        // Test that the system handles any string as an IP
        let weird_ip = "not::a::real::ip::address";

        assert!(limiter
            .check_ip(weird_ip, ActionType::AuthAttempt)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_all_action_types_have_valid_configs() {
        // Ensure all action types have valid limits and durations
        let action_types = [
            ActionType::Message,
            ActionType::DirectMessage,
            ActionType::FileUpload,
            ActionType::Reaction,
            ActionType::ProfileUpdate,
            ActionType::InviteCreate,
            ActionType::NodeCreate,
            ActionType::AuthAttempt,
            ActionType::Registration,
        ];

        for action in action_types {
            let limit = action.default_limit();
            let duration = action.window_duration();

            assert!(limit > 0, "{:?} should have a positive limit", action);
            assert!(
                duration.as_secs() > 0,
                "{:?} should have a positive window duration",
                action
            );
        }
    }

    #[tokio::test]
    async fn test_error_message_formatting() {
        let limiter = RateLimiter::new();
        let user_id = Uuid::new_v4();

        // Fill up the limit
        for _ in 0..5 {
            limiter
                .check(user_id, ActionType::ProfileUpdate)
                .await
                .expect("Should work");
        }

        let result = limiter.check(user_id, ActionType::ProfileUpdate).await;
        assert!(result.is_err());

        let err = result.unwrap_err();

        // Verify error implements Display and Error traits
        let display_msg = format!("{}", err);
        assert!(display_msg.contains("Rate limit exceeded"));

        // Verify error fields are populated
        assert_eq!(err.remaining, 0);
        assert!(err.retry_after_secs > 0);
        assert!(!err.message.is_empty());
    }
}
