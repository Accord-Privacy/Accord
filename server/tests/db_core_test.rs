//! Integration tests for the Database layer (server/src/db/mod.rs).
//!
//! Tests are organized into groups:
//! - Group 1: User CRUD
//! - Group 2: Node CRUD & membership
//! - Group 3: Channel CRUD
//! - Group 4: Message CRUD
//! - Group 5: Ban system (identity + device)

#![allow(clippy::all)]

use accord_server::db::{compute_public_key_hash, Database};
use accord_server::node::NodeRole;
use uuid::Uuid;

/// Spin up a fresh in-memory database for each test.
async fn test_db() -> Database {
    Database::new(":memory:").await.unwrap()
}

// ──────────────────────────────────────────────────────────
// Group 1 — User CRUD
// ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_user_success() {
    let db = test_db().await;
    let user = db.create_user("my_public_key", "my_hash").await.unwrap();
    let expected_pkh = compute_public_key_hash("my_public_key");
    assert_eq!(user.public_key_hash, expected_pkh);
    assert_eq!(user.public_key, "my_public_key");
}

#[tokio::test]
async fn test_create_user_duplicate_public_key_hash_fails() {
    let db = test_db().await;
    db.create_user("same_key", "hash1").await.unwrap();
    // Second user with the same public key yields the same hash → unique constraint violation
    let result = db.create_user("same_key", "hash2").await;
    assert!(
        result.is_err(),
        "Expected error on duplicate public_key_hash"
    );
}

#[tokio::test]
async fn test_get_user_by_id_found() {
    let db = test_db().await;
    let user = db.create_user("pk1", "h1").await.unwrap();
    let found = db.get_user_by_id(user.id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, user.id);
}

#[tokio::test]
async fn test_get_user_by_id_not_found() {
    let db = test_db().await;
    let result = db.get_user_by_id(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_user_by_public_key_hash_found() {
    let db = test_db().await;
    let user = db.create_user("pk2", "h2").await.unwrap();
    let found = db
        .get_user_by_public_key_hash(&user.public_key_hash)
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, user.id);
}

#[tokio::test]
async fn test_get_user_by_public_key_hash_not_found() {
    let db = test_db().await;
    let result = db
        .get_user_by_public_key_hash("nonexistent_hash_00000")
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_public_key_hash_exists_true() {
    let db = test_db().await;
    let user = db.create_user("pk3", "h3").await.unwrap();
    let exists = db
        .public_key_hash_exists(&user.public_key_hash)
        .await
        .unwrap();
    assert!(exists);
}

#[tokio::test]
async fn test_public_key_hash_exists_false() {
    let db = test_db().await;
    let exists = db
        .public_key_hash_exists("definitely_not_there")
        .await
        .unwrap();
    assert!(!exists);
}

#[tokio::test]
async fn test_get_user_password_hash_by_pkh_found() {
    let db = test_db().await;
    let user = db.create_user("pk4", "secret_hash").await.unwrap();
    let pw = db
        .get_user_password_hash_by_pkh(&user.public_key_hash)
        .await
        .unwrap();
    assert_eq!(pw, Some("secret_hash".to_string()));
}

#[tokio::test]
async fn test_get_user_password_hash_by_pkh_not_found() {
    let db = test_db().await;
    let pw = db
        .get_user_password_hash_by_pkh("no_such_user")
        .await
        .unwrap();
    assert!(pw.is_none());
}

#[tokio::test]
async fn test_user_profile_created_with_display_name() {
    let db = test_db().await;
    let user = db.create_user("pk5", "").await.unwrap();
    let profile = db.get_user_profile(user.id).await.unwrap();
    assert!(profile.is_some());
    let profile = profile.unwrap();
    // Default display name is "user-<first 8 chars of hash>"
    assert!(profile.display_name.starts_with("user-"));
}

#[tokio::test]
async fn test_update_user_profile_display_name_roundtrip() {
    let db = test_db().await;
    let user = db.create_user("pk6", "").await.unwrap();
    db.update_user_profile(user.id, Some("Alice"), None, None, None, None, None)
        .await
        .unwrap();
    let profile = db.get_user_profile(user.id).await.unwrap().unwrap();
    assert_eq!(profile.display_name, "Alice");
}

#[tokio::test]
async fn test_count_users_after_multiple_creates() {
    let db = test_db().await;
    // Sentinel system user exists by default (created during migrations)
    let baseline = db.count_users().await.unwrap();
    db.create_user("ka", "").await.unwrap();
    db.create_user("kb", "").await.unwrap();
    db.create_user("kc", "").await.unwrap();
    let count = db.count_users().await.unwrap();
    assert_eq!(count, baseline + 3);
}

// ──────────────────────────────────────────────────────────
// Group 2 — Node CRUD & membership
// ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_node_success() {
    let db = test_db().await;
    let owner = db.create_user("owner_key", "").await.unwrap();
    let node = db
        .create_node("MyNode", owner.id, Some("desc"))
        .await
        .unwrap();
    assert_eq!(node.name, "MyNode");
    assert_eq!(node.owner_id, owner.id);
    assert_eq!(node.description, Some("desc".to_string()));
}

#[tokio::test]
async fn test_create_node_owner_is_admin_member() {
    let db = test_db().await;
    let owner = db.create_user("owner2", "").await.unwrap();
    let node = db.create_node("N1", owner.id, None).await.unwrap();
    let member = db
        .get_node_member(node.id, owner.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(member.role, NodeRole::Admin);
}

#[tokio::test]
async fn test_node_join_and_is_member() {
    let db = test_db().await;
    let owner = db.create_user("owner3", "").await.unwrap();
    let user = db.create_user("member3", "").await.unwrap();
    let node = db.create_node("N2", owner.id, None).await.unwrap();

    db.add_node_member(node.id, user.id, NodeRole::Member)
        .await
        .unwrap();
    assert!(db.is_node_member(node.id, user.id).await.unwrap());
}

#[tokio::test]
async fn test_node_leave_removes_member() {
    let db = test_db().await;
    let owner = db.create_user("owner4", "").await.unwrap();
    let user = db.create_user("member4", "").await.unwrap();
    let node = db.create_node("N3", owner.id, None).await.unwrap();

    db.add_node_member(node.id, user.id, NodeRole::Member)
        .await
        .unwrap();
    db.remove_node_member(node.id, user.id).await.unwrap();
    assert!(!db.is_node_member(node.id, user.id).await.unwrap());
}

#[tokio::test]
async fn test_get_node_members_returns_all() {
    let db = test_db().await;
    let owner = db.create_user("owner5", "").await.unwrap();
    let u1 = db.create_user("m1", "").await.unwrap();
    let u2 = db.create_user("m2", "").await.unwrap();
    let node = db.create_node("N4", owner.id, None).await.unwrap();

    db.add_node_member(node.id, u1.id, NodeRole::Member)
        .await
        .unwrap();
    db.add_node_member(node.id, u2.id, NodeRole::Moderator)
        .await
        .unwrap();

    let members = db.get_node_members(node.id).await.unwrap();
    assert_eq!(members.len(), 3); // owner + u1 + u2
}

#[tokio::test]
async fn test_get_node_member_role() {
    let db = test_db().await;
    let owner = db.create_user("owner6", "").await.unwrap();
    let user = db.create_user("mod1", "").await.unwrap();
    let node = db.create_node("N5", owner.id, None).await.unwrap();

    db.add_node_member(node.id, user.id, NodeRole::Moderator)
        .await
        .unwrap();
    let member = db.get_node_member(node.id, user.id).await.unwrap().unwrap();
    assert_eq!(member.role, NodeRole::Moderator);
}

#[tokio::test]
async fn test_is_node_member_false_for_nonmember() {
    let db = test_db().await;
    let owner = db.create_user("owner7", "").await.unwrap();
    let stranger = db.create_user("stranger", "").await.unwrap();
    let node = db.create_node("N6", owner.id, None).await.unwrap();
    assert!(!db.is_node_member(node.id, stranger.id).await.unwrap());
}

#[tokio::test]
async fn test_delete_node() {
    let db = test_db().await;
    let owner = db.create_user("del_owner", "").await.unwrap();
    let node = db.create_node("ToDelete", owner.id, None).await.unwrap();
    db.delete_node(node.id).await.unwrap();
    let found = db.get_node(node.id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_get_user_nodes() {
    let db = test_db().await;
    let owner = db.create_user("user_nodes_owner", "").await.unwrap();
    db.create_node("NodeA", owner.id, None).await.unwrap();
    db.create_node("NodeB", owner.id, None).await.unwrap();
    let nodes = db.get_user_nodes(owner.id).await.unwrap();
    assert_eq!(nodes.len(), 2);
}

// ──────────────────────────────────────────────────────────
// Group 3 — Channel CRUD
// ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_channel_success() {
    let db = test_db().await;
    let owner = db.create_user("chan_owner", "").await.unwrap();
    let node = db.create_node("ChanNode", owner.id, None).await.unwrap();

    let channel = db
        .create_channel("announcements", node.id, owner.id)
        .await
        .unwrap();
    assert_eq!(channel.name, "announcements");
    assert_eq!(channel.node_id, node.id);
}

#[tokio::test]
async fn test_get_channel_found() {
    let db = test_db().await;
    let owner = db.create_user("chan_owner2", "").await.unwrap();
    let node = db.create_node("ChanNode2", owner.id, None).await.unwrap();
    let channel = db
        .create_channel("general2", node.id, owner.id)
        .await
        .unwrap();

    let found = db.get_channel(channel.id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "general2");
}

#[tokio::test]
async fn test_get_channel_not_found() {
    let db = test_db().await;
    let found = db.get_channel(Uuid::new_v4()).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_get_node_channels_empty_then_populated() {
    let db = test_db().await;
    let owner = db.create_user("chan_owner3", "").await.unwrap();
    let node = db.create_node("ChanNode3", owner.id, None).await.unwrap();

    // create_node creates a "general" channel automatically
    let initial = db.get_node_channels(node.id).await.unwrap();
    let initial_count = initial.len();

    db.create_channel("extra1", node.id, owner.id)
        .await
        .unwrap();
    db.create_channel("extra2", node.id, owner.id)
        .await
        .unwrap();

    let channels = db.get_node_channels(node.id).await.unwrap();
    assert_eq!(channels.len(), initial_count + 2);
}

#[tokio::test]
async fn test_delete_channel_success() {
    let db = test_db().await;
    let owner = db.create_user("chan_del_owner", "").await.unwrap();
    let node = db.create_node("ChanDelNode", owner.id, None).await.unwrap();
    let channel = db
        .create_channel("to_delete", node.id, owner.id)
        .await
        .unwrap();

    db.delete_channel(channel.id).await.unwrap();
    let found = db.get_channel(channel.id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_channel_creator_is_member() {
    let db = test_db().await;
    let owner = db.create_user("chan_member_owner", "").await.unwrap();
    let node = db
        .create_node("ChanMemberNode", owner.id, None)
        .await
        .unwrap();
    let channel = db
        .create_channel("members_chan", node.id, owner.id)
        .await
        .unwrap();

    let members = db.get_channel_members(channel.id).await.unwrap();
    assert!(members.contains(&owner.id));
}

#[tokio::test]
async fn test_add_and_remove_user_from_channel() {
    let db = test_db().await;
    let owner = db.create_user("chan_ar_owner", "").await.unwrap();
    let user = db.create_user("chan_ar_user", "").await.unwrap();
    let node = db.create_node("ChanARNode", owner.id, None).await.unwrap();
    let channel = db
        .create_channel("ar_chan", node.id, owner.id)
        .await
        .unwrap();

    db.add_user_to_channel(channel.id, user.id).await.unwrap();
    let members = db.get_channel_members(channel.id).await.unwrap();
    assert!(members.contains(&user.id));

    db.remove_user_from_channel(channel.id, user.id)
        .await
        .unwrap();
    let members = db.get_channel_members(channel.id).await.unwrap();
    assert!(!members.contains(&user.id));
}

#[tokio::test]
async fn test_channel_with_category() {
    let db = test_db().await;
    let owner = db.create_user("cat_owner", "").await.unwrap();
    let node = db.create_node("CatNode", owner.id, None).await.unwrap();

    let category = db
        .create_channel_category(node.id, "My Category")
        .await
        .unwrap();
    assert_eq!(category.name, "My Category");
    assert_eq!(category.node_id, node.id);

    let categories = db.get_node_categories(node.id).await.unwrap();
    assert_eq!(categories.len(), 1);
    assert_eq!(categories[0].name, "My Category");
}

#[tokio::test]
async fn test_count_node_channels() {
    let db = test_db().await;
    let owner = db.create_user("cnt_chan_owner", "").await.unwrap();
    let node = db.create_node("CntChanNode", owner.id, None).await.unwrap();

    let initial = db.count_node_channels(node.id).await.unwrap();
    db.create_channel("c1", node.id, owner.id).await.unwrap();
    db.create_channel("c2", node.id, owner.id).await.unwrap();

    let count = db.count_node_channels(node.id).await.unwrap();
    assert_eq!(count, initial + 2);
}

// ──────────────────────────────────────────────────────────
// Group 4 — Message CRUD
// ──────────────────────────────────────────────────────────

/// Helper to create a user + node + channel ready for messaging.
async fn setup_message_env(
    db: &Database,
    suffix: &str,
) -> (accord_server::models::User, uuid::Uuid, uuid::Uuid) {
    let user = db
        .create_user(&format!("msg_key_{}", suffix), "")
        .await
        .unwrap();
    let node = db
        .create_node(&format!("MsgNode_{}", suffix), user.id, None)
        .await
        .unwrap();
    let channel = db
        .create_channel(&format!("msg_chan_{}", suffix), node.id, user.id)
        .await
        .unwrap();
    (user, node.id, channel.id)
}

#[tokio::test]
async fn test_store_message_success() {
    let db = test_db().await;
    let (user, _node_id, channel_id) = setup_message_env(&db, "store").await;

    let payload = b"encrypted_blob";
    let (msg_id, seq) = db
        .store_message(channel_id, user.id, payload, None)
        .await
        .unwrap();

    assert!(msg_id != Uuid::nil());
    assert_eq!(seq, 1);
}

#[tokio::test]
async fn test_get_channel_messages_empty() {
    let db = test_db().await;
    let (_, _, channel_id) = setup_message_env(&db, "empty").await;

    let msgs = db.get_channel_messages(channel_id, 10, None).await.unwrap();
    assert!(msgs.is_empty());
}

#[tokio::test]
async fn test_get_channel_messages_with_messages() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "with_msgs").await;

    db.store_message(channel_id, user.id, b"msg1", None)
        .await
        .unwrap();
    db.store_message(channel_id, user.id, b"msg2", None)
        .await
        .unwrap();
    db.store_message(channel_id, user.id, b"msg3", None)
        .await
        .unwrap();

    let msgs = db.get_channel_messages(channel_id, 10, None).await.unwrap();
    assert_eq!(msgs.len(), 3);
}

#[tokio::test]
async fn test_get_channel_messages_ordering_chronological() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "order").await;

    let (id1, _) = db
        .store_message(channel_id, user.id, b"first", None)
        .await
        .unwrap();
    let (id2, _) = db
        .store_message(channel_id, user.id, b"second", None)
        .await
        .unwrap();

    let msgs = db.get_channel_messages(channel_id, 10, None).await.unwrap();
    // Should be returned in chronological order (earliest first after reverse)
    assert_eq!(msgs[0].0, id1);
    assert_eq!(msgs[1].0, id2);
}

#[tokio::test]
async fn test_get_channel_messages_limit() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "limit").await;

    for i in 0..10 {
        db.store_message(channel_id, user.id, format!("msg{}", i).as_bytes(), None)
            .await
            .unwrap();
    }

    let msgs = db.get_channel_messages(channel_id, 5, None).await.unwrap();
    assert_eq!(msgs.len(), 5);
}

#[tokio::test]
async fn test_get_channel_messages_before_pagination() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "before").await;

    db.store_message(channel_id, user.id, b"msg_old", None)
        .await
        .unwrap();
    // Small sleep to ensure distinct timestamps
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (_, _) = db
        .store_message(channel_id, user.id, b"msg_new", None)
        .await
        .unwrap();

    // Fetch current time: messages before "now+1" should return both
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1;

    let msgs = db
        .get_channel_messages(channel_id, 10, Some(now))
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);

    // Fetch only messages before 1 second ago — should just get the old one
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msgs_before = db
        .get_channel_messages(channel_id, 10, Some(cutoff))
        .await
        .unwrap();
    assert_eq!(msgs_before.len(), 1);
    assert_eq!(msgs_before[0].2, b"msg_old".to_vec());
}

#[tokio::test]
async fn test_get_message_by_id_found() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "by_id").await;

    let (msg_id, _) = db
        .store_message(channel_id, user.id, b"find_me", None)
        .await
        .unwrap();

    let detail = db.get_message_details(msg_id).await.unwrap();
    assert!(detail.is_some());
    let (ch_id, s_id, _, _) = detail.unwrap();
    assert_eq!(ch_id, channel_id);
    assert_eq!(s_id, user.id);
}

#[tokio::test]
async fn test_get_message_by_id_not_found() {
    let db = test_db().await;
    let detail = db.get_message_details(Uuid::new_v4()).await.unwrap();
    assert!(detail.is_none());
}

#[tokio::test]
async fn test_delete_message_success() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "del_msg").await;

    let (msg_id, _) = db
        .store_message(channel_id, user.id, b"delete_me", None)
        .await
        .unwrap();

    let result = db.delete_message(msg_id, user.id).await.unwrap();
    assert!(result.is_some());

    // Verify gone
    let msgs = db.get_channel_messages(channel_id, 10, None).await.unwrap();
    assert!(!msgs.iter().any(|(id, _, _, _)| *id == msg_id));
}

#[tokio::test]
async fn test_update_message_edit_content() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "edit_msg").await;

    let (msg_id, _) = db
        .store_message(channel_id, user.id, b"original", None)
        .await
        .unwrap();

    let edited = db
        .edit_message(msg_id, user.id, b"edited_payload")
        .await
        .unwrap();
    assert!(edited);

    // Verify via get_message_details that edited_at is now set
    let detail = db.get_message_details(msg_id).await.unwrap().unwrap();
    assert!(detail.3.is_some(), "edited_at should be set after edit");
}

#[tokio::test]
async fn test_sequence_numbers_monotonically_increase() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "seq").await;

    let (_, seq1) = db
        .store_message(channel_id, user.id, b"m1", None)
        .await
        .unwrap();
    let (_, seq2) = db
        .store_message(channel_id, user.id, b"m2", None)
        .await
        .unwrap();
    let (_, seq3) = db
        .store_message(channel_id, user.id, b"m3", None)
        .await
        .unwrap();

    assert!(seq1 < seq2 && seq2 < seq3);
}

// ──────────────────────────────────────────────────────────
// Group 5 — Ban system
// ──────────────────────────────────────────────────────────

/// Shared ban test environment
async fn setup_ban_env(db: &Database, suffix: &str) -> (Uuid, String, Uuid) {
    let owner = db
        .create_user(&format!("ban_owner_{}", suffix), "")
        .await
        .unwrap();
    let node = db
        .create_node(&format!("BanNode_{}", suffix), owner.id, None)
        .await
        .unwrap();
    let target = db
        .create_user(&format!("ban_target_{}", suffix), "")
        .await
        .unwrap();
    let pkh = target.public_key_hash.clone();
    (node.id, pkh, owner.id)
}

#[tokio::test]
async fn test_ban_from_node_and_is_banned() {
    let db = test_db().await;
    let (node_id, pkh, owner_id) = setup_ban_env(&db, "ban1").await;

    db.ban_from_node(node_id, &pkh, owner_id, None, None)
        .await
        .unwrap();

    assert!(db.is_banned_from_node(node_id, &pkh).await.unwrap());
}

#[tokio::test]
async fn test_unban_from_node() {
    let db = test_db().await;
    let (node_id, pkh, owner_id) = setup_ban_env(&db, "ban2").await;

    db.ban_from_node(node_id, &pkh, owner_id, None, None)
        .await
        .unwrap();
    let unbanned = db.unban_from_node(node_id, &pkh).await.unwrap();
    assert!(unbanned);

    assert!(!db.is_banned_from_node(node_id, &pkh).await.unwrap());
}

#[tokio::test]
async fn test_is_banned_false_for_unbanned_user() {
    let db = test_db().await;
    let (node_id, pkh, _) = setup_ban_env(&db, "ban3").await;
    assert!(!db.is_banned_from_node(node_id, &pkh).await.unwrap());
}

#[tokio::test]
async fn test_get_node_bans_empty() {
    let db = test_db().await;
    let owner = db.create_user("ban_empty_owner", "").await.unwrap();
    let node = db
        .create_node("BanEmptyNode", owner.id, None)
        .await
        .unwrap();
    let bans = db.get_node_bans(node.id).await.unwrap();
    assert!(bans.is_empty());
}

#[tokio::test]
async fn test_get_node_bans_after_ban() {
    let db = test_db().await;
    let (node_id, pkh, owner_id) = setup_ban_env(&db, "ban4").await;
    let (node_id2, pkh2, _) = setup_ban_env(&db, "ban4b").await;

    db.ban_from_node(node_id, &pkh, owner_id, None, None)
        .await
        .unwrap();

    let bans = db.get_node_bans(node_id).await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].public_key_hash, pkh);

    // Unrelated node should have zero bans
    let bans2 = db.get_node_bans(node_id2).await.unwrap();
    let _ = pkh2; // suppress unused warning
    assert!(bans2.is_empty());
}

#[tokio::test]
async fn test_ban_with_expiry_already_expired() {
    let db = test_db().await;
    let (node_id, pkh, owner_id) = setup_ban_env(&db, "ban5").await;

    // Ban with expiry in the past
    let expired = 1u64; // Unix timestamp in 1970
    db.ban_from_node(node_id, &pkh, owner_id, None, Some(expired))
        .await
        .unwrap();

    // Expired bans should not be considered active
    assert!(!db.is_banned_from_node(node_id, &pkh).await.unwrap());
}

#[tokio::test]
async fn test_ban_device_from_node() {
    let db = test_db().await;
    let (node_id, _, owner_id) = setup_ban_env(&db, "dev1").await;

    let device_fp = "fingerprint_abc123";
    db.ban_device_from_node(node_id, device_fp, owner_id, None, None)
        .await
        .unwrap();

    assert!(db
        .is_device_banned_from_node(node_id, device_fp)
        .await
        .unwrap());
}

#[tokio::test]
async fn test_is_device_banned_false_for_unregistered_device() {
    let db = test_db().await;
    let (node_id, _, _) = setup_ban_env(&db, "dev2").await;
    assert!(!db
        .is_device_banned_from_node(node_id, "unknown_fp")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_unban_device_from_node() {
    let db = test_db().await;
    let (node_id, _, owner_id) = setup_ban_env(&db, "dev3").await;

    let device_fp = "fp_to_remove";
    db.ban_device_from_node(node_id, device_fp, owner_id, None, None)
        .await
        .unwrap();

    let removed = db.unban_device_from_node(node_id, device_fp).await.unwrap();
    assert!(removed);

    assert!(!db
        .is_device_banned_from_node(node_id, device_fp)
        .await
        .unwrap());
}

// ──────────────────────────────────────────────────────────
// Bonus: Node role management via member_roles
// ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_assign_and_get_member_roles() {
    let db = test_db().await;
    let owner = db.create_user("role_owner", "").await.unwrap();
    let member = db.create_user("role_member", "").await.unwrap();
    let node = db.create_node("RoleNode", owner.id, None).await.unwrap();

    db.add_node_member(node.id, member.id, NodeRole::Member)
        .await
        .unwrap();

    // Create a custom role
    let role = db
        .create_role(node.id, "Verified", 0x00FF00, 0, 1, false, false, None)
        .await
        .unwrap();

    // Assign it
    db.assign_member_role(node.id, member.id, role.id)
        .await
        .unwrap();

    let roles = db.get_member_roles(node.id, member.id).await.unwrap();
    assert!(roles.iter().any(|r| r.id == role.id));
}

#[tokio::test]
async fn test_remove_member_role() {
    let db = test_db().await;
    let owner = db.create_user("rmrole_owner", "").await.unwrap();
    let member = db.create_user("rmrole_member", "").await.unwrap();
    let node = db.create_node("RmRoleNode", owner.id, None).await.unwrap();

    db.add_node_member(node.id, member.id, NodeRole::Member)
        .await
        .unwrap();

    let role = db
        .create_role(node.id, "Temp", 0, 0, 1, false, false, None)
        .await
        .unwrap();
    db.assign_member_role(node.id, member.id, role.id)
        .await
        .unwrap();

    let removed = db.remove_member_role(member.id, role.id).await.unwrap();
    assert!(removed);

    let roles = db.get_member_roles(node.id, member.id).await.unwrap();
    assert!(!roles.iter().any(|r| r.id == role.id));
}

// ──────────────────────────────────────────────────────────
// Bonus: Miscellaneous
// ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_count_nodes() {
    let db = test_db().await;
    let owner = db.create_user("cnt_node_owner", "").await.unwrap();
    let baseline = db.count_nodes().await.unwrap();
    db.create_node("N_cnt1", owner.id, None).await.unwrap();
    db.create_node("N_cnt2", owner.id, None).await.unwrap();
    let count = db.count_nodes().await.unwrap();
    // +2 user nodes, but sentinel system node also exists
    assert!(count >= baseline + 2);
}

#[tokio::test]
async fn test_count_messages() {
    let db = test_db().await;
    let (user, _, channel_id) = setup_message_env(&db, "cnt_msgs").await;
    let baseline = db.count_messages().await.unwrap();
    db.store_message(channel_id, user.id, b"a", None)
        .await
        .unwrap();
    db.store_message(channel_id, user.id, b"b", None)
        .await
        .unwrap();
    let count = db.count_messages().await.unwrap();
    assert_eq!(count, baseline + 2);
}

#[tokio::test]
async fn test_compute_public_key_hash_deterministic() {
    let h1 = compute_public_key_hash("my_key");
    let h2 = compute_public_key_hash("my_key");
    let h3 = compute_public_key_hash("other_key");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
}

#[tokio::test]
async fn test_get_node_returned_by_get_node() {
    let db = test_db().await;
    let owner = db.create_user("get_node_owner", "").await.unwrap();
    let node = db
        .create_node("GetMeNode", owner.id, Some("hello"))
        .await
        .unwrap();
    let found = db.get_node(node.id).await.unwrap().unwrap();
    assert_eq!(found.name, "GetMeNode");
    assert_eq!(found.description, Some("hello".to_string()));
}
