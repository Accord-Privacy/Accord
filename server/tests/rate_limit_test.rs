//! External integration tests for the rate limiter module
//!
//! Tests RateLimiter, ActionType, check_ip, check, get_status, and clear.
//! The RateLimiter is standalone — no database required.

#![allow(clippy::all)]

use accord_server::rate_limit::{ActionType, RateLimiter};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// ============================================================================
// Group 1 — ActionType defaults (~8 tests)
// ============================================================================

#[test]
fn test_action_type_message_defaults() {
    assert_eq!(ActionType::Message.default_limit(), 30);
    assert_eq!(
        ActionType::Message.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_direct_message_defaults() {
    assert_eq!(ActionType::DirectMessage.default_limit(), 30);
    assert_eq!(
        ActionType::DirectMessage.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_file_upload_defaults() {
    assert_eq!(ActionType::FileUpload.default_limit(), 10);
    assert_eq!(
        ActionType::FileUpload.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_reaction_defaults() {
    assert_eq!(ActionType::Reaction.default_limit(), 20);
    assert_eq!(
        ActionType::Reaction.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_profile_update_defaults() {
    assert_eq!(ActionType::ProfileUpdate.default_limit(), 5);
    assert_eq!(
        ActionType::ProfileUpdate.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_invite_create_defaults() {
    assert_eq!(ActionType::InviteCreate.default_limit(), 10);
    assert_eq!(
        ActionType::InviteCreate.window_duration(),
        Duration::from_secs(3600)
    );
}

#[test]
fn test_action_type_node_create_defaults() {
    assert_eq!(ActionType::NodeCreate.default_limit(), 5);
    assert_eq!(
        ActionType::NodeCreate.window_duration(),
        Duration::from_secs(3600)
    );
}

#[test]
fn test_action_type_auth_attempt_defaults() {
    assert_eq!(ActionType::AuthAttempt.default_limit(), 20);
    assert_eq!(
        ActionType::AuthAttempt.window_duration(),
        Duration::from_secs(60)
    );
}

#[test]
fn test_action_type_registration_defaults() {
    assert_eq!(ActionType::Registration.default_limit(), 20);
    assert_eq!(
        ActionType::Registration.window_duration(),
        Duration::from_secs(3600)
    );
}

#[test]
fn test_all_action_types_have_positive_limits() {
    let types = [
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
    for t in types {
        assert!(t.default_limit() > 0, "{:?} limit must be > 0", t);
        assert!(
            t.window_duration().as_secs() > 0,
            "{:?} window must be > 0s",
            t
        );
    }
}

#[test]
fn test_hourly_window_actions() {
    // InviteCreate, NodeCreate, Registration all use 1-hour windows
    assert_eq!(
        ActionType::InviteCreate.window_duration(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        ActionType::NodeCreate.window_duration(),
        Duration::from_secs(3600)
    );
    assert_eq!(
        ActionType::Registration.window_duration(),
        Duration::from_secs(3600)
    );
}

#[test]
fn test_per_minute_window_actions() {
    // All other actions use 1-minute windows
    for t in [
        ActionType::Message,
        ActionType::DirectMessage,
        ActionType::FileUpload,
        ActionType::Reaction,
        ActionType::ProfileUpdate,
        ActionType::AuthAttempt,
    ] {
        assert_eq!(
            t.window_duration(),
            Duration::from_secs(60),
            "{:?} should have a 60-second window",
            t
        );
    }
}

// ============================================================================
// Group 2 — check_ip (~10 tests)
// ============================================================================

#[tokio::test]
async fn test_check_ip_first_request_succeeds() {
    let limiter = RateLimiter::new();
    let result = limiter.check_ip("10.0.0.1", ActionType::AuthAttempt).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_ip_up_to_limit_all_succeed() {
    let limiter = RateLimiter::new();
    let ip = "10.0.0.2";
    let limit = ActionType::AuthAttempt.default_limit(); // 20

    for i in 0..limit {
        let result = limiter.check_ip(ip, ActionType::AuthAttempt).await;
        assert!(
            result.is_ok(),
            "Request {} of {} should succeed",
            i + 1,
            limit
        );
    }
}

#[tokio::test]
async fn test_check_ip_limit_plus_one_returns_error() {
    let limiter = RateLimiter::new();
    let ip = "10.0.0.3";
    let limit = ActionType::AuthAttempt.default_limit(); // 20

    for _ in 0..limit {
        limiter.check_ip(ip, ActionType::AuthAttempt).await.unwrap();
    }

    let result = limiter.check_ip(ip, ActionType::AuthAttempt).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_check_ip_error_has_correct_fields() {
    let limiter = RateLimiter::new();
    let ip = "10.0.0.4";
    let limit = ActionType::AuthAttempt.default_limit();

    for _ in 0..limit {
        limiter.check_ip(ip, ActionType::AuthAttempt).await.unwrap();
    }

    let err = limiter
        .check_ip(ip, ActionType::AuthAttempt)
        .await
        .unwrap_err();
    assert_eq!(err.remaining, 0);
    assert!(
        err.retry_after_secs <= 60,
        "retry_after_secs should be ≤ window duration"
    );
    assert!(err.retry_after_secs > 0, "retry_after_secs should be > 0");
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn test_check_ip_different_ips_independent() {
    let limiter = RateLimiter::new();
    let ip_a = "10.1.1.1";
    let ip_b = "10.1.1.2";
    let limit = ActionType::AuthAttempt.default_limit();

    // Exhaust ip_a
    for _ in 0..limit {
        limiter
            .check_ip(ip_a, ActionType::AuthAttempt)
            .await
            .unwrap();
    }
    assert!(limiter
        .check_ip(ip_a, ActionType::AuthAttempt)
        .await
        .is_err());

    // ip_b should be unaffected
    assert!(limiter
        .check_ip(ip_b, ActionType::AuthAttempt)
        .await
        .is_ok());
}

#[tokio::test]
async fn test_check_ip_different_action_types_independent() {
    let limiter = RateLimiter::new();
    let ip = "10.2.0.1";

    // Exhaust Registration
    let reg_limit = ActionType::Registration.default_limit();
    for _ in 0..reg_limit {
        limiter
            .check_ip(ip, ActionType::Registration)
            .await
            .unwrap();
    }
    assert!(limiter
        .check_ip(ip, ActionType::Registration)
        .await
        .is_err());

    // AuthAttempt bucket should be untouched
    assert!(limiter.check_ip(ip, ActionType::AuthAttempt).await.is_ok());
}

#[tokio::test]
async fn test_check_ip_empty_string() {
    // Empty string is a valid (if unusual) IP key — should not panic
    let limiter = RateLimiter::new();
    let result = limiter.check_ip("", ActionType::AuthAttempt).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_ip_ipv6_address() {
    let limiter = RateLimiter::new();
    let ipv6 = "2001:db8::1";
    let result = limiter.check_ip(ipv6, ActionType::AuthAttempt).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_check_ip_multiple_rejections_after_limit() {
    let limiter = RateLimiter::new();
    let ip = "10.3.0.1";
    // Note: check_ip uses ip_windows, not user windows — ProfileUpdate via IP
    // We exhaust AuthAttempt instead since that's an IP-appropriate action
    let limit = ActionType::AuthAttempt.default_limit();
    for _ in 0..limit {
        limiter.check_ip(ip, ActionType::AuthAttempt).await.unwrap();
    }

    // Multiple subsequent requests should all fail
    for _ in 0..5 {
        assert!(limiter.check_ip(ip, ActionType::AuthAttempt).await.is_err());
    }
}

#[tokio::test]
async fn test_check_ip_error_display() {
    let limiter = RateLimiter::new();
    let ip = "10.4.0.1";
    let limit = ActionType::AuthAttempt.default_limit();

    for _ in 0..limit {
        limiter.check_ip(ip, ActionType::AuthAttempt).await.unwrap();
    }

    let err = limiter
        .check_ip(ip, ActionType::AuthAttempt)
        .await
        .unwrap_err();
    let display = format!("{}", err);
    assert!(display.contains("Rate limit exceeded"));

    // Verify std::error::Error trait is implemented
    let _: &dyn std::error::Error = &err;
}

// ============================================================================
// Group 3 — check (user_id based) (~10 tests)
// ============================================================================

#[tokio::test]
async fn test_check_first_request_succeeds() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    assert!(limiter.check(user, ActionType::Message).await.is_ok());
}

#[tokio::test]
async fn test_check_up_to_limit_all_succeed() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::FileUpload.default_limit(); // 10

    for i in 0..limit {
        let result = limiter.check(user, ActionType::FileUpload).await;
        assert!(result.is_ok(), "Request {} should succeed", i + 1);
    }
}

#[tokio::test]
async fn test_check_limit_plus_one_returns_error() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::ProfileUpdate.default_limit(); // 5

    for _ in 0..limit {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    assert!(limiter
        .check(user, ActionType::ProfileUpdate)
        .await
        .is_err());
}

#[tokio::test]
async fn test_check_error_has_correct_fields() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..5 {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    let err = limiter
        .check(user, ActionType::ProfileUpdate)
        .await
        .unwrap_err();
    assert_eq!(err.remaining, 0);
    assert!(err.retry_after_secs <= 60);
    assert!(err.retry_after_secs > 0);
    assert!(err.message.contains("ProfileUpdate"));
}

#[tokio::test]
async fn test_check_different_users_independent() {
    let limiter = RateLimiter::new();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let limit = ActionType::FileUpload.default_limit();

    // Exhaust user_a
    for _ in 0..limit {
        limiter.check(user_a, ActionType::FileUpload).await.unwrap();
    }
    assert!(limiter.check(user_a, ActionType::FileUpload).await.is_err());

    // user_b should be unaffected
    assert!(limiter.check(user_b, ActionType::FileUpload).await.is_ok());
}

#[tokio::test]
async fn test_check_different_actions_independent() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    // Exhaust FileUpload (limit 10)
    for _ in 0..10 {
        limiter.check(user, ActionType::FileUpload).await.unwrap();
    }
    assert!(limiter.check(user, ActionType::FileUpload).await.is_err());

    // Message (limit 30) should be untouched
    assert!(limiter.check(user, ActionType::Message).await.is_ok());

    // Reaction (limit 20) should also be untouched
    assert!(limiter.check(user, ActionType::Reaction).await.is_ok());
}

#[tokio::test]
async fn test_check_multiple_rejections_after_limit() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..5 {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    // Should remain rejected for subsequent calls
    for _ in 0..3 {
        assert!(limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn test_check_error_remaining_is_zero() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..5 {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    let err = limiter
        .check(user, ActionType::ProfileUpdate)
        .await
        .unwrap_err();
    assert_eq!(err.remaining, 0);
}

#[tokio::test]
async fn test_check_invite_create_hourly_limit() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::InviteCreate.default_limit(); // 10

    for _ in 0..limit {
        limiter.check(user, ActionType::InviteCreate).await.unwrap();
    }

    let err = limiter
        .check(user, ActionType::InviteCreate)
        .await
        .unwrap_err();
    // retry_after should be within the 1-hour window
    assert!(err.retry_after_secs <= 3600);
    assert!(err.retry_after_secs > 0);
}

#[tokio::test]
async fn test_check_node_create_limit() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::NodeCreate.default_limit(); // 5

    for _ in 0..limit {
        limiter.check(user, ActionType::NodeCreate).await.unwrap();
    }

    let err = limiter
        .check(user, ActionType::NodeCreate)
        .await
        .unwrap_err();
    assert_eq!(err.remaining, 0);
    assert!(err.retry_after_secs <= 3600);
}

// ============================================================================
// Group 4 — get_status (~6 tests)
// ============================================================================

#[tokio::test]
async fn test_get_status_fresh_limiter() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    let (used, remaining) = limiter.get_status(user, ActionType::Message).await;
    assert_eq!(used, 0);
    assert_eq!(remaining, ActionType::Message.default_limit());
}

#[tokio::test]
async fn test_get_status_after_n_requests() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let n = 3;

    for _ in 0..n {
        limiter.check(user, ActionType::FileUpload).await.unwrap();
    }

    let (used, remaining) = limiter.get_status(user, ActionType::FileUpload).await;
    let limit = ActionType::FileUpload.default_limit(); // 10
    assert_eq!(used, n);
    assert_eq!(remaining, limit - n);
}

#[tokio::test]
async fn test_get_status_at_exact_limit() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::ProfileUpdate.default_limit(); // 5

    for _ in 0..limit {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    let (used, remaining) = limiter.get_status(user, ActionType::ProfileUpdate).await;
    assert_eq!(used, limit);
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn test_get_status_independent_per_action() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    // Use 5 Messages and 2 FileUploads
    for _ in 0..5 {
        limiter.check(user, ActionType::Message).await.unwrap();
    }
    for _ in 0..2 {
        limiter.check(user, ActionType::FileUpload).await.unwrap();
    }

    let (msg_used, msg_remaining) = limiter.get_status(user, ActionType::Message).await;
    assert_eq!(msg_used, 5);
    assert_eq!(msg_remaining, 25); // 30 - 5

    let (file_used, file_remaining) = limiter.get_status(user, ActionType::FileUpload).await;
    assert_eq!(file_used, 2);
    assert_eq!(file_remaining, 8); // 10 - 2
}

#[tokio::test]
async fn test_get_status_independent_per_user() {
    let limiter = RateLimiter::new();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    // user_a does 4 uploads, user_b does 1
    for _ in 0..4 {
        limiter.check(user_a, ActionType::FileUpload).await.unwrap();
    }
    limiter.check(user_b, ActionType::FileUpload).await.unwrap();

    let (a_used, a_remaining) = limiter.get_status(user_a, ActionType::FileUpload).await;
    assert_eq!(a_used, 4);
    assert_eq!(a_remaining, 6);

    let (b_used, b_remaining) = limiter.get_status(user_b, ActionType::FileUpload).await;
    assert_eq!(b_used, 1);
    assert_eq!(b_remaining, 9);
}

#[tokio::test]
async fn test_get_status_returns_correct_limit_value() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    // used=0, remaining should equal default_limit
    let (used, remaining) = limiter.get_status(user, ActionType::Reaction).await;
    assert_eq!(used + remaining, ActionType::Reaction.default_limit());
}

// ============================================================================
// Group 5 — clear (~3 tests)
// ============================================================================

#[tokio::test]
async fn test_clear_resets_exhausted_limits() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::ProfileUpdate.default_limit();

    for _ in 0..limit {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }
    // Exhausted
    assert!(limiter
        .check(user, ActionType::ProfileUpdate)
        .await
        .is_err());

    limiter.clear().await;

    // After clear, should work again
    assert!(limiter.check(user, ActionType::ProfileUpdate).await.is_ok());
}

#[tokio::test]
async fn test_clear_resets_status_to_zero() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..7 {
        limiter.check(user, ActionType::Message).await.unwrap();
    }

    limiter.clear().await;

    let (used, remaining) = limiter.get_status(user, ActionType::Message).await;
    assert_eq!(used, 0);
    assert_eq!(remaining, ActionType::Message.default_limit());
}

#[tokio::test]
async fn test_clear_multiple_users_all_reset() {
    let limiter = RateLimiter::new();
    let users: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();

    // Each user does some requests
    for &u in &users {
        for _ in 0..3 {
            limiter.check(u, ActionType::FileUpload).await.unwrap();
        }
    }

    limiter.clear().await;

    // All users should be reset
    for &u in &users {
        let (used, remaining) = limiter.get_status(u, ActionType::FileUpload).await;
        assert_eq!(used, 0);
        assert_eq!(remaining, ActionType::FileUpload.default_limit());
    }
}

// ============================================================================
// Group 6 — Edge cases (~5 tests)
// ============================================================================

#[tokio::test]
async fn test_edge_empty_string_ip() {
    let limiter = RateLimiter::new();
    // Should not panic; empty string is a valid hash key
    for _ in 0..5 {
        assert!(limiter.check_ip("", ActionType::AuthAttempt).await.is_ok());
    }
}

#[tokio::test]
async fn test_edge_concurrent_requests_same_user() {
    let limiter = Arc::new(RateLimiter::new());
    let user = Uuid::new_v4();
    let limit = ActionType::FileUpload.default_limit(); // 10

    let mut handles = vec![];
    for _ in 0..limit {
        let lim = Arc::clone(&limiter);
        handles.push(tokio::spawn(async move {
            lim.check(user, ActionType::FileUpload).await
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    // All 10 spawned concurrently — exactly at limit so all should succeed
    assert_eq!(successes + failures, limit);
    // The sum of accepted + rejected must equal total attempts
    assert_eq!(
        successes, limit,
        "All {} requests should succeed (at the limit)",
        limit
    );

    // One more should now be rejected
    assert!(limiter.check(user, ActionType::FileUpload).await.is_err());
}

#[tokio::test]
async fn test_edge_concurrent_different_users() {
    let limiter = Arc::new(RateLimiter::new());

    let handles: Vec<_> = (0..20)
        .map(|_| {
            let lim = Arc::clone(&limiter);
            tokio::spawn(async move {
                let user = Uuid::new_v4();
                // Each user does one request — should never be rate limited
                lim.check(user, ActionType::Message).await
            })
        })
        .collect();

    for handle in handles {
        assert!(
            handle.await.unwrap().is_ok(),
            "Each unique user's first request should succeed"
        );
    }
}

#[tokio::test]
async fn test_edge_very_rapid_successive_calls() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::Reaction.default_limit(); // 20

    // Fire all requests in a tight loop without yielding
    let mut ok_count = 0;
    let mut err_count = 0;
    for _ in 0..(limit + 5) {
        match limiter.check(user, ActionType::Reaction).await {
            Ok(_) => ok_count += 1,
            Err(_) => err_count += 1,
        }
    }

    assert_eq!(ok_count, limit, "Should accept exactly {} requests", limit);
    assert_eq!(err_count, 5, "Should reject the 5 excess requests");
}

#[tokio::test]
async fn test_edge_concurrent_ip_requests() {
    let limiter = Arc::new(RateLimiter::new());
    let ip = "10.99.0.1".to_string();
    let limit = ActionType::AuthAttempt.default_limit(); // 20

    let handles: Vec<_> = (0..limit)
        .map(|_| {
            let lim = Arc::clone(&limiter);
            let ip = ip.clone();
            tokio::spawn(async move { lim.check_ip(&ip, ActionType::AuthAttempt).await })
        })
        .collect();

    let mut successes = 0;
    for handle in handles {
        if handle.await.unwrap().is_ok() {
            successes += 1;
        }
    }
    assert_eq!(
        successes, limit,
        "All {} concurrent auth attempts should succeed (at limit)",
        limit
    );

    // Next one should be rejected
    assert!(limiter
        .check_ip(&ip, ActionType::AuthAttempt)
        .await
        .is_err());
}

// ============================================================================
// Additional correctness tests
// ============================================================================

#[tokio::test]
async fn test_rate_limiter_default_impl() {
    // RateLimiter implements Default
    let limiter: RateLimiter = Default::default();
    let user = Uuid::new_v4();
    assert!(limiter.check(user, ActionType::Message).await.is_ok());
}

#[tokio::test]
async fn test_used_plus_remaining_equals_limit_throughout() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();
    let limit = ActionType::FileUpload.default_limit();

    for i in 0..limit {
        limiter.check(user, ActionType::FileUpload).await.unwrap();
        let (used, remaining) = limiter.get_status(user, ActionType::FileUpload).await;
        assert_eq!(
            used + remaining,
            limit,
            "at step {}: used={} remaining={}",
            i + 1,
            used,
            remaining
        );
    }
}

#[tokio::test]
async fn test_direct_message_independent_from_message() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    // Use up DirectMessage limit
    let dm_limit = ActionType::DirectMessage.default_limit();
    for _ in 0..dm_limit {
        limiter
            .check(user, ActionType::DirectMessage)
            .await
            .unwrap();
    }
    assert!(limiter
        .check(user, ActionType::DirectMessage)
        .await
        .is_err());

    // Message should still work
    assert!(limiter.check(user, ActionType::Message).await.is_ok());
}

#[tokio::test]
async fn test_get_status_after_clear_fresh_start() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    limiter.check(user, ActionType::NodeCreate).await.unwrap();
    limiter.clear().await;

    let (used, remaining) = limiter.get_status(user, ActionType::NodeCreate).await;
    assert_eq!(used, 0);
    assert_eq!(remaining, ActionType::NodeCreate.default_limit());
}

#[tokio::test]
async fn test_error_implements_std_error() {
    use std::error::Error;
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..5 {
        limiter
            .check(user, ActionType::ProfileUpdate)
            .await
            .unwrap();
    }

    let err = limiter
        .check(user, ActionType::ProfileUpdate)
        .await
        .unwrap_err();
    // RateLimitError must implement std::error::Error
    let _as_trait: &dyn Error = &err;
    let display = format!("{}", err);
    assert!(!display.is_empty());
}

#[tokio::test]
async fn test_node_create_hourly_retry_after() {
    let limiter = RateLimiter::new();
    let user = Uuid::new_v4();

    for _ in 0..ActionType::NodeCreate.default_limit() {
        limiter.check(user, ActionType::NodeCreate).await.unwrap();
    }

    let err = limiter
        .check(user, ActionType::NodeCreate)
        .await
        .unwrap_err();
    // NodeCreate has a 1-hour window, so retry_after should be close to 3600
    assert!(err.retry_after_secs <= 3600);
    assert!(err.retry_after_secs > 0);
}
