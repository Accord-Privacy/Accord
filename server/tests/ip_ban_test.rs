//! Tests for the relay-owner IP ban + connection log surface (DoS/DDoS defense).
//!
//! Governance invariant under test: this surface is node-correlation-free — the
//! connection log stores only IP/event/time and bans key on IP alone.

use accord_server::state::AppState;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn connection_log_records_and_reads_back() {
    let state = AppState::new_in_memory().await.unwrap();
    state
        .db
        .log_connection("203.0.113.7", "connect")
        .await
        .unwrap();
    state
        .db
        .log_connection("203.0.113.7", "disconnect")
        .await
        .unwrap();

    let entries = state.db.get_connection_log(10).await.unwrap();
    assert_eq!(entries.len(), 2);
    // Newest first.
    assert_eq!(entries[0].event, "disconnect");
    assert_eq!(entries[0].ip, "203.0.113.7");
    assert_eq!(entries[1].event, "connect");
}

#[tokio::test]
async fn permanent_ban_blocks_and_unban_clears() {
    let state = AppState::new_in_memory().await.unwrap();
    assert!(!state.is_ip_banned("198.51.100.5").await);

    state
        .ban_ip("198.51.100.5", Some("flooding"), None)
        .await
        .unwrap();
    assert!(state.is_ip_banned("198.51.100.5").await);

    let bans = state.db.list_ip_bans().await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, "198.51.100.5");
    assert_eq!(bans[0].reason.as_deref(), Some("flooding"));
    assert_eq!(bans[0].expires_at, None);

    let removed = state.unban_ip("198.51.100.5").await.unwrap();
    assert!(removed);
    assert!(!state.is_ip_banned("198.51.100.5").await);
}

#[tokio::test]
async fn expired_ban_is_not_enforced() {
    let state = AppState::new_in_memory().await.unwrap();
    // Ban that already expired.
    state
        .ban_ip("192.0.2.9", None, Some(now() - 60))
        .await
        .unwrap();
    assert!(!state.is_ip_banned("192.0.2.9").await);

    // Future expiry is enforced.
    state
        .ban_ip("192.0.2.10", None, Some(now() + 3600))
        .await
        .unwrap();
    assert!(state.is_ip_banned("192.0.2.10").await);
}

#[tokio::test]
async fn boot_cache_load_prunes_expired_and_keeps_active() {
    let state = AppState::new_in_memory().await.unwrap();
    state
        .ban_ip("192.0.2.1", None, Some(now() - 10))
        .await
        .unwrap();
    state.ban_ip("192.0.2.2", None, None).await.unwrap();

    // Simulate a fresh boot: reload the cache from the DB.
    state.load_ip_bans().await;

    assert!(!state.is_ip_banned("192.0.2.1").await); // expired, pruned
    assert!(state.is_ip_banned("192.0.2.2").await); // permanent, kept
                                                    // The expired row is gone from the table too.
    let bans = state.db.list_ip_bans().await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].ip, "192.0.2.2");
}
