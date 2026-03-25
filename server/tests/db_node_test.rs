//! Integration tests for the NodeDatabase layer (server/src/db/node_db.rs).
//!
//! Tests are organized into groups:
//! - Group 1: Channel CRUD
//! - Group 2: Channel Categories
//! - Group 3: Messages
//! - Group 4: Node Invites
//! - Group 5: Bans & Device Bans
//! - Group 6: Pins, Threads, Reactions
//! - Group 7: Files & Audit Log
//! - Group 8: Read Receipts & User Profiles

#![allow(clippy::all)]

use accord_server::db::NodeDatabase;
use sqlx::sqlite::SqlitePoolOptions;
use uuid::Uuid;

/// Create a fresh in-memory SQLite pool.
async fn make_pool() -> sqlx::SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("failed to create in-memory SQLite pool")
}

/// Create a NodeDatabase with a fresh pool and a random node_id.
async fn make_node_db() -> (NodeDatabase, Uuid) {
    let pool = make_pool().await;
    let node_id = Uuid::new_v4();
    let node_db = NodeDatabase::new(pool, node_id)
        .await
        .expect("NodeDatabase::new failed");
    (node_db, node_id)
}

/// Convenience: create a channel and return its id.
async fn create_channel(node_db: &NodeDatabase, name: &str) -> Uuid {
    let channel_id = Uuid::new_v4();
    let creator = Uuid::new_v4();
    node_db
        .create_channel(channel_id, name, creator)
        .await
        .expect("create_channel failed")
        .id
}

/// Convenience: store a message and return (msg_id, seq).
async fn store_msg(node_db: &NodeDatabase, channel_id: Uuid, payload: &[u8]) -> (Uuid, i64) {
    let sender = Uuid::new_v4();
    node_db
        .store_message(channel_id, sender, payload, None)
        .await
        .expect("store_message failed")
}

// ─────────────────────────────────────────────────────────────────
// Group 1 — Channel CRUD
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_channel_create_returns_correct_fields() {
    let (node_db, node_id) = make_node_db().await;
    let channel_id = Uuid::new_v4();
    let creator = Uuid::new_v4();
    let channel = node_db
        .create_channel(channel_id, "general", creator)
        .await
        .unwrap();

    assert_eq!(channel.id, channel_id);
    assert_eq!(channel.name, "general");
    assert_eq!(channel.node_id, node_id);
    assert!(channel.members.contains(&creator));
}

#[tokio::test]
async fn test_channel_get_found() {
    let (node_db, _) = make_node_db().await;
    let channel_id = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "test-chan", Uuid::new_v4())
        .await
        .unwrap();

    let found = node_db.get_channel(channel_id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "test-chan");
}

#[tokio::test]
async fn test_channel_get_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.get_channel(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_node_channels_empty() {
    let (node_db, _) = make_node_db().await;
    let channels = node_db.get_node_channels().await.unwrap();
    assert!(channels.is_empty());
}

#[tokio::test]
async fn test_get_node_channels_returns_all() {
    let (node_db, _) = make_node_db().await;
    node_db
        .create_channel(Uuid::new_v4(), "alpha", Uuid::new_v4())
        .await
        .unwrap();
    node_db
        .create_channel(Uuid::new_v4(), "beta", Uuid::new_v4())
        .await
        .unwrap();
    node_db
        .create_channel(Uuid::new_v4(), "gamma", Uuid::new_v4())
        .await
        .unwrap();

    let channels = node_db.get_node_channels().await.unwrap();
    assert_eq!(channels.len(), 3);
}

#[tokio::test]
async fn test_count_channels_increments() {
    let (node_db, _) = make_node_db().await;
    assert_eq!(node_db.count_channels().await.unwrap(), 0);

    node_db
        .create_channel(Uuid::new_v4(), "c1", Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(node_db.count_channels().await.unwrap(), 1);

    node_db
        .create_channel(Uuid::new_v4(), "c2", Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(node_db.count_channels().await.unwrap(), 2);
}

#[tokio::test]
async fn test_delete_channel_removes_it() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "to-delete").await;

    node_db.delete_channel(channel_id).await.unwrap();

    let found = node_db.get_channel(channel_id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_delete_channel_decrements_count() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "decrement-me").await;
    assert_eq!(node_db.count_channels().await.unwrap(), 1);

    node_db.delete_channel(channel_id).await.unwrap();
    assert_eq!(node_db.count_channels().await.unwrap(), 0);
}

#[tokio::test]
async fn test_add_user_to_channel() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "add-user").await;
    let new_user = Uuid::new_v4();

    node_db
        .add_user_to_channel(channel_id, new_user)
        .await
        .unwrap();

    let members = node_db.get_channel_members(channel_id).await.unwrap();
    assert!(members.contains(&new_user));
}

#[tokio::test]
async fn test_remove_user_from_channel() {
    let (node_db, _) = make_node_db().await;
    let user = Uuid::new_v4();
    let channel_id = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "remove-user", user)
        .await
        .unwrap();

    node_db
        .remove_user_from_channel(channel_id, user)
        .await
        .unwrap();

    let members = node_db.get_channel_members(channel_id).await.unwrap();
    assert!(!members.contains(&user));
}

#[tokio::test]
async fn test_add_user_idempotent() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "idempotent").await;
    let user = Uuid::new_v4();

    // Add same user twice — should not error due to INSERT OR IGNORE
    node_db.add_user_to_channel(channel_id, user).await.unwrap();
    node_db.add_user_to_channel(channel_id, user).await.unwrap();

    let members = node_db.get_channel_members(channel_id).await.unwrap();
    let count = members.iter().filter(|&&m| m == user).count();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn test_get_channel_members_creator_included() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();
    let channel_id = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "creator-member", creator)
        .await
        .unwrap();

    let members = node_db.get_channel_members(channel_id).await.unwrap();
    assert!(members.contains(&creator));
}

// ─────────────────────────────────────────────────────────────────
// Group 2 — Categories
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_category_returns_correct_fields() {
    let (node_db, node_id) = make_node_db().await;
    let cat = node_db
        .create_channel_category("Main Category")
        .await
        .unwrap();

    assert_eq!(cat.name, "Main Category");
    assert_eq!(cat.node_id, node_id);
    assert_eq!(cat.position, 0);
}

#[tokio::test]
async fn test_get_category_by_id_found() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db.create_channel_category("FindMe").await.unwrap();

    let found = node_db.get_category_by_id(cat.id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "FindMe");
}

#[tokio::test]
async fn test_get_category_by_id_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.get_category_by_id(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_node_categories_empty() {
    let (node_db, _) = make_node_db().await;
    let cats = node_db.get_node_categories().await.unwrap();
    assert!(cats.is_empty());
}

#[tokio::test]
async fn test_get_node_categories_returns_all() {
    let (node_db, _) = make_node_db().await;
    node_db.create_channel_category("A").await.unwrap();
    node_db.create_channel_category("B").await.unwrap();
    node_db.create_channel_category("C").await.unwrap();

    let cats = node_db.get_node_categories().await.unwrap();
    assert_eq!(cats.len(), 3);
}

#[tokio::test]
async fn test_update_category_name() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db.create_channel_category("OldName").await.unwrap();

    node_db
        .update_channel_category(cat.id, Some("NewName"), None)
        .await
        .unwrap();

    let updated = node_db.get_category_by_id(cat.id).await.unwrap().unwrap();
    assert_eq!(updated.name, "NewName");
}

#[tokio::test]
async fn test_update_category_position() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db
        .create_channel_category("PositionTest")
        .await
        .unwrap();

    node_db
        .update_channel_category(cat.id, None, Some(99))
        .await
        .unwrap();

    let updated = node_db.get_category_by_id(cat.id).await.unwrap().unwrap();
    assert_eq!(updated.position, 99);
}

#[tokio::test]
async fn test_delete_category_removes_it() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db.create_channel_category("ToDelete").await.unwrap();

    node_db.delete_channel_category(cat.id).await.unwrap();

    let result = node_db.get_category_by_id(cat.id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_delete_category_nullifies_channel_category_id() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db
        .create_channel_category("NullableCat")
        .await
        .unwrap();

    let channel_id = Uuid::new_v4();
    let creator = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "chan-with-cat", creator)
        .await
        .unwrap();
    node_db
        .update_channel_category_and_position(channel_id, Some(cat.id), None)
        .await
        .unwrap();

    // Delete category — channel should not be deleted
    node_db.delete_channel_category(cat.id).await.unwrap();

    let channel = node_db.get_channel(channel_id).await.unwrap();
    assert!(
        channel.is_some(),
        "channel should still exist after category delete"
    );
}

#[tokio::test]
async fn test_get_channels_with_categories() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db.create_channel_category("Cat1").await.unwrap();

    let channel_id = Uuid::new_v4();
    let creator = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "categorized", creator)
        .await
        .unwrap();
    node_db
        .update_channel_category_and_position(channel_id, Some(cat.id), Some(0))
        .await
        .unwrap();

    let channels = node_db.get_channels_with_categories().await.unwrap();
    assert!(!channels.is_empty());

    let found = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert_eq!(found.category_id, Some(cat.id));
    assert_eq!(found.category_name.as_deref(), Some("Cat1"));
}

#[tokio::test]
async fn test_update_channel_category_and_position() {
    let (node_db, _) = make_node_db().await;
    let cat = node_db.create_channel_category("MoveTarget").await.unwrap();
    let channel_id = Uuid::new_v4();
    node_db
        .create_channel(channel_id, "moveable", Uuid::new_v4())
        .await
        .unwrap();

    node_db
        .update_channel_category_and_position(channel_id, Some(cat.id), Some(5))
        .await
        .unwrap();

    let channels = node_db.get_channels_with_categories().await.unwrap();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert_eq!(ch.category_id, Some(cat.id));
    assert_eq!(ch.position, 5);
}

// ─────────────────────────────────────────────────────────────────
// Group 3 — Messages
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_store_message_returns_id_and_seq() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "msg-chan").await;
    let sender = Uuid::new_v4();

    let (msg_id, seq) = node_db
        .store_message(channel_id, sender, b"hello", None)
        .await
        .unwrap();

    assert_ne!(msg_id, Uuid::nil());
    assert_eq!(seq, 1);
}

#[tokio::test]
async fn test_store_message_seq_increments() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "seq-chan").await;
    let sender = Uuid::new_v4();

    let (_, s1) = node_db
        .store_message(channel_id, sender, b"m1", None)
        .await
        .unwrap();
    let (_, s2) = node_db
        .store_message(channel_id, sender, b"m2", None)
        .await
        .unwrap();
    let (_, s3) = node_db
        .store_message(channel_id, sender, b"m3", None)
        .await
        .unwrap();

    assert!(s1 < s2 && s2 < s3);
}

#[tokio::test]
async fn test_get_channel_messages_empty() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "empty-msg-chan").await;

    let msgs = node_db
        .get_channel_messages(channel_id, 10, None)
        .await
        .unwrap();
    assert!(msgs.is_empty());
}

#[tokio::test]
async fn test_get_channel_messages_returns_stored() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "filled-chan").await;
    let sender = Uuid::new_v4();

    node_db
        .store_message(channel_id, sender, b"payload1", None)
        .await
        .unwrap();
    node_db
        .store_message(channel_id, sender, b"payload2", None)
        .await
        .unwrap();

    let msgs = node_db
        .get_channel_messages(channel_id, 10, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 2);
}

#[tokio::test]
async fn test_get_channel_messages_respects_limit() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "limit-chan").await;
    let sender = Uuid::new_v4();

    for i in 0..10 {
        node_db
            .store_message(channel_id, sender, format!("msg-{}", i).as_bytes(), None)
            .await
            .unwrap();
    }

    let msgs = node_db
        .get_channel_messages(channel_id, 5, None)
        .await
        .unwrap();
    assert_eq!(msgs.len(), 5);
}

#[tokio::test]
async fn test_get_channel_messages_ordered_chronologically() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "order-chan").await;
    let sender = Uuid::new_v4();

    let (id1, _) = node_db
        .store_message(channel_id, sender, b"first", None)
        .await
        .unwrap();
    let (id2, _) = node_db
        .store_message(channel_id, sender, b"second", None)
        .await
        .unwrap();

    let msgs = node_db
        .get_channel_messages(channel_id, 10, None)
        .await
        .unwrap();
    // get_channel_messages reverses so result is chronological (oldest first)
    assert_eq!(msgs[0].0, id1);
    assert_eq!(msgs[1].0, id2);
}

#[tokio::test]
async fn test_get_channel_messages_paginated_raw() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "paginated-chan").await;
    let sender = Uuid::new_v4();

    node_db
        .store_message(channel_id, sender, b"page1", None)
        .await
        .unwrap();
    node_db
        .store_message(channel_id, sender, b"page2", None)
        .await
        .unwrap();

    let results = node_db
        .get_channel_messages_paginated_raw(channel_id, 10, None)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_get_message_details_found() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "details-chan").await;
    let sender = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"detail-me", None)
        .await
        .unwrap();

    let details = node_db.get_message_details(msg_id).await.unwrap();
    assert!(details.is_some());
    let (ch_id, s_id, _, edited_at) = details.unwrap();
    assert_eq!(ch_id, channel_id);
    assert_eq!(s_id, sender);
    assert!(edited_at.is_none());
}

#[tokio::test]
async fn test_get_message_details_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.get_message_details(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_edit_message_updates_payload_and_edited_at() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "edit-chan").await;
    let sender = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"original", None)
        .await
        .unwrap();

    let edited = node_db
        .edit_message(msg_id, sender, b"new-payload")
        .await
        .unwrap();
    assert!(edited);

    let details = node_db.get_message_details(msg_id).await.unwrap().unwrap();
    assert!(details.3.is_some(), "edited_at should be set after edit");
}

#[tokio::test]
async fn test_edit_message_wrong_sender_returns_false() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "edit-wrong-sender").await;
    let sender = Uuid::new_v4();
    let other = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"original", None)
        .await
        .unwrap();

    let edited = node_db
        .edit_message(msg_id, other, b"hacked")
        .await
        .unwrap();
    assert!(!edited, "wrong sender should not be able to edit");
}

#[tokio::test]
async fn test_delete_message_by_author() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "delete-msg-chan").await;
    let sender = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"delete-me", None)
        .await
        .unwrap();

    let result = node_db.delete_message(msg_id, sender).await.unwrap();
    assert!(result.is_some());

    // Verify gone
    let msgs = node_db
        .get_channel_messages(channel_id, 10, None)
        .await
        .unwrap();
    assert!(!msgs.iter().any(|(id, _, _, _)| *id == msg_id));
}

#[tokio::test]
async fn test_force_delete_message() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "force-delete-chan").await;
    let sender = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"force-delete-me", None)
        .await
        .unwrap();

    let result = node_db.force_delete_message(msg_id).await.unwrap();
    assert!(result.is_some());
    let (ch_id, s_id) = result.unwrap();
    assert_eq!(ch_id, channel_id);
    assert_eq!(s_id, sender);

    // Verify deleted
    let msgs = node_db
        .get_channel_messages(channel_id, 10, None)
        .await
        .unwrap();
    assert!(msgs.is_empty());
}

#[tokio::test]
async fn test_force_delete_nonexistent_message_returns_none() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.force_delete_message(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_store_message_with_reply_to() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "reply-chan").await;
    let sender = Uuid::new_v4();

    let (parent_id, _) = node_db
        .store_message(channel_id, sender, b"parent", None)
        .await
        .unwrap();

    let (reply_id, _) = node_db
        .store_message(channel_id, sender, b"reply", Some(parent_id))
        .await
        .unwrap();

    let details = node_db.get_message_details(reply_id).await.unwrap();
    assert!(details.is_some());
    // Details just returns channel/sender/ts/edited_at; thread tested separately
}

#[tokio::test]
async fn test_search_messages_raw_by_channel_name() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "searchable-channel").await;
    let sender = Uuid::new_v4();

    node_db
        .store_message(channel_id, sender, b"encrypted1", None)
        .await
        .unwrap();
    node_db
        .store_message(channel_id, sender, b"encrypted2", None)
        .await
        .unwrap();

    // search by channel name fragment — search_messages_raw searches channel name
    let results = node_db
        .search_messages_raw("searchable", None, 10)
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
}

#[tokio::test]
async fn test_search_messages_raw_with_channel_filter() {
    let (node_db, _) = make_node_db().await;
    let chan1 = create_channel(&node_db, "find-this").await;
    let chan2 = create_channel(&node_db, "not-this").await;
    let sender = Uuid::new_v4();

    node_db
        .store_message(chan1, sender, b"msg-in-find", None)
        .await
        .unwrap();
    node_db
        .store_message(chan2, sender, b"msg-in-other", None)
        .await
        .unwrap();

    let results = node_db
        .search_messages_raw("find", Some(chan1), 10)
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].channel_id, chan1);
}

// ─────────────────────────────────────────────────────────────────
// Group 4 — Node Invites
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_invite_returns_id() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    let invite_id = node_db
        .create_node_invite(creator, "INVITE01", None, None)
        .await
        .unwrap();

    assert_ne!(invite_id, Uuid::nil());
}

#[tokio::test]
async fn test_get_invite_by_code_found() {
    let (node_db, node_id) = make_node_db().await;
    let creator = Uuid::new_v4();

    node_db
        .create_node_invite(creator, "CODE123", None, None)
        .await
        .unwrap();

    let invite = node_db.get_node_invite_by_code("CODE123").await.unwrap();
    assert!(invite.is_some());
    let inv = invite.unwrap();
    assert_eq!(inv.invite_code, "CODE123");
    assert_eq!(inv.node_id, node_id);
    assert_eq!(inv.created_by, creator);
}

#[tokio::test]
async fn test_get_invite_by_code_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db
        .get_node_invite_by_code("NONEXISTENT")
        .await
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_invite_by_id_found() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    let invite_id = node_db
        .create_node_invite(creator, "BYID01", None, None)
        .await
        .unwrap();

    let invite = node_db.get_node_invite(invite_id).await.unwrap();
    assert!(invite.is_some());
    assert_eq!(invite.unwrap().id, invite_id);
}

#[tokio::test]
async fn test_list_invites_empty() {
    let (node_db, _) = make_node_db().await;
    let invites = node_db.get_node_invites().await.unwrap();
    assert!(invites.is_empty());
}

#[tokio::test]
async fn test_list_invites_returns_all() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    node_db
        .create_node_invite(creator, "INV-A", None, None)
        .await
        .unwrap();
    node_db
        .create_node_invite(creator, "INV-B", None, None)
        .await
        .unwrap();
    node_db
        .create_node_invite(creator, "INV-C", None, None)
        .await
        .unwrap();

    let invites = node_db.get_node_invites().await.unwrap();
    assert_eq!(invites.len(), 3);
}

#[tokio::test]
async fn test_delete_invite() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    let invite_id = node_db
        .create_node_invite(creator, "DEL-INV", None, None)
        .await
        .unwrap();

    node_db.delete_node_invite(invite_id).await.unwrap();

    let found = node_db.get_node_invite(invite_id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn test_use_invite_increments_current_uses() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    node_db
        .create_node_invite(creator, "USE-ME", Some(5), None)
        .await
        .unwrap();

    node_db.increment_invite_usage("USE-ME").await.unwrap();
    node_db.increment_invite_usage("USE-ME").await.unwrap();

    let invite = node_db
        .get_node_invite_by_code("USE-ME")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invite.current_uses, 2);
    assert_eq!(invite.max_uses, Some(5));
}

#[tokio::test]
async fn test_invite_with_max_uses_field() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();

    node_db
        .create_node_invite(creator, "MAX-USE", Some(10), None)
        .await
        .unwrap();

    let invite = node_db
        .get_node_invite_by_code("MAX-USE")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invite.max_uses, Some(10));
    assert_eq!(invite.current_uses, 0);
}

#[tokio::test]
async fn test_invite_with_expiry_field() {
    let (node_db, _) = make_node_db().await;
    let creator = Uuid::new_v4();
    let future_ts = 9_999_999_999u64;

    node_db
        .create_node_invite(creator, "EXP-INV", None, Some(future_ts))
        .await
        .unwrap();

    let invite = node_db
        .get_node_invite_by_code("EXP-INV")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invite.expires_at, Some(future_ts));
}

// ─────────────────────────────────────────────────────────────────
// Group 5 — Bans & Device Bans
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ban_and_is_banned() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let pkh = "hash_of_public_key_001";

    node_db
        .ban_from_node_with_fingerprint(pkh, banner, None, None, None)
        .await
        .unwrap();

    assert!(node_db.is_banned_from_node(pkh).await.unwrap());
}

#[tokio::test]
async fn test_unban_from_node() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let pkh = "hash_unban_test";

    node_db
        .ban_from_node_with_fingerprint(pkh, banner, None, None, None)
        .await
        .unwrap();

    let removed = node_db.unban_from_node(pkh).await.unwrap();
    assert!(removed);
    assert!(!node_db.is_banned_from_node(pkh).await.unwrap());
}

#[tokio::test]
async fn test_is_banned_false_for_unknown() {
    let (node_db, _) = make_node_db().await;
    assert!(!node_db.is_banned_from_node("unknown_hash").await.unwrap());
}

#[tokio::test]
async fn test_ban_with_past_expiry_not_active() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let pkh = "expired_ban_hash";

    // Expired in 1970
    node_db
        .ban_from_node_with_fingerprint(pkh, banner, None, Some(1), None)
        .await
        .unwrap();

    assert!(
        !node_db.is_banned_from_node(pkh).await.unwrap(),
        "expired ban should not be active"
    );
}

#[tokio::test]
async fn test_ban_device_and_is_device_banned() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let fp = "device_fingerprint_xyz";

    node_db
        .ban_device_from_node(fp, banner, None, None)
        .await
        .unwrap();

    assert!(node_db.is_device_banned_from_node(fp).await.unwrap());
}

#[tokio::test]
async fn test_unban_device_from_node() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let fp = "fp_to_unban";

    node_db
        .ban_device_from_node(fp, banner, None, None)
        .await
        .unwrap();

    let removed = node_db.unban_device_from_node(fp).await.unwrap();
    assert!(removed);
    assert!(!node_db.is_device_banned_from_node(fp).await.unwrap());
}

#[tokio::test]
async fn test_is_device_banned_false_for_unknown() {
    let (node_db, _) = make_node_db().await;
    assert!(!node_db
        .is_device_banned_from_node("never_banned_fp")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_get_node_bans_empty() {
    let (node_db, _) = make_node_db().await;
    let bans = node_db.get_node_bans().await.unwrap();
    assert!(bans.is_empty());
}

#[tokio::test]
async fn test_get_node_bans_after_ban() {
    let (node_db, _) = make_node_db().await;
    let banner = Uuid::new_v4();
    let pkh = "listed_ban_hash";

    node_db
        .ban_from_node_with_fingerprint(pkh, banner, None, None, None)
        .await
        .unwrap();

    let bans = node_db.get_node_bans().await.unwrap();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].public_key_hash, pkh);
}

// ─────────────────────────────────────────────────────────────────
// Group 6 — Pins, Threads, Reactions
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_pin_message_returns_true() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "pin-chan").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"pin-me").await;
    let pinner = Uuid::new_v4();

    let pinned = node_db.pin_message(msg_id, pinner).await.unwrap();
    assert!(pinned);
}

#[tokio::test]
async fn test_pin_message_twice_returns_false() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "double-pin-chan").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"double-pin").await;
    let pinner = Uuid::new_v4();

    node_db.pin_message(msg_id, pinner).await.unwrap();
    let second = node_db.pin_message(msg_id, pinner).await.unwrap();
    assert!(
        !second,
        "pinning an already-pinned message should return false"
    );
}

#[tokio::test]
async fn test_unpin_message_returns_true() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "unpin-chan").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"unpin-me").await;
    let pinner = Uuid::new_v4();

    node_db.pin_message(msg_id, pinner).await.unwrap();
    let unpinned = node_db.unpin_message(msg_id).await.unwrap();
    assert!(unpinned);
}

#[tokio::test]
async fn test_unpin_message_not_pinned_returns_false() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "unpin-unpinned").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"not-pinned").await;

    let result = node_db.unpin_message(msg_id).await.unwrap();
    assert!(
        !result,
        "unpinning a non-pinned message should return false"
    );
}

#[tokio::test]
async fn test_get_pinned_messages_empty() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "empty-pins").await;

    let pinned = node_db.get_pinned_messages_raw(channel_id).await.unwrap();
    assert!(pinned.is_empty());
}

#[tokio::test]
async fn test_get_pinned_messages_returns_pinned() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "pin-list-chan").await;
    let pinner = Uuid::new_v4();

    let (msg_id1, _) = store_msg(&node_db, channel_id, b"pinned1").await;
    let (msg_id2, _) = store_msg(&node_db, channel_id, b"unpinned").await;
    let (msg_id3, _) = store_msg(&node_db, channel_id, b"pinned2").await;

    node_db.pin_message(msg_id1, pinner).await.unwrap();
    node_db.pin_message(msg_id3, pinner).await.unwrap();

    let pinned = node_db.get_pinned_messages_raw(channel_id).await.unwrap();
    assert_eq!(pinned.len(), 2);
    let ids: Vec<_> = pinned.iter().map(|m| m.id).collect();
    assert!(ids.contains(&msg_id1));
    assert!(ids.contains(&msg_id3));
    assert!(!ids.contains(&msg_id2));
}

#[tokio::test]
async fn test_get_message_thread_raw_empty() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "thread-empty-chan").await;
    let (parent_id, _) = store_msg(&node_db, channel_id, b"parent").await;

    let thread = node_db.get_message_thread_raw(parent_id).await.unwrap();
    assert!(thread.is_empty(), "no replies yet");
}

#[tokio::test]
async fn test_get_message_thread_raw_with_replies() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "thread-chan").await;
    let sender = Uuid::new_v4();

    let (parent_id, _) = node_db
        .store_message(channel_id, sender, b"parent", None)
        .await
        .unwrap();

    node_db
        .store_message(channel_id, sender, b"reply1", Some(parent_id))
        .await
        .unwrap();
    node_db
        .store_message(channel_id, sender, b"reply2", Some(parent_id))
        .await
        .unwrap();

    let thread = node_db.get_message_thread_raw(parent_id).await.unwrap();
    assert_eq!(thread.len(), 2);
}

#[tokio::test]
async fn test_add_and_get_reactions() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "reaction-chan").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"react-me").await;
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();

    node_db.add_reaction(msg_id, user1, "👍").await.unwrap();
    node_db.add_reaction(msg_id, user2, "👍").await.unwrap();
    node_db.add_reaction(msg_id, user1, "❤️").await.unwrap();

    let reactions = node_db.get_message_reactions(msg_id).await.unwrap();
    assert_eq!(reactions.len(), 2); // two distinct emojis
    let thumbs = reactions.iter().find(|r| r.emoji == "👍").unwrap();
    assert_eq!(thumbs.count, 2);
}

#[tokio::test]
async fn test_remove_reaction() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "remove-reaction-chan").await;
    let (msg_id, _) = store_msg(&node_db, channel_id, b"react").await;
    let user = Uuid::new_v4();

    node_db.add_reaction(msg_id, user, "🔥").await.unwrap();
    let removed = node_db.remove_reaction(msg_id, user, "🔥").await.unwrap();
    assert!(removed);

    let reactions = node_db.get_message_reactions(msg_id).await.unwrap();
    assert!(reactions.is_empty());
}

// ─────────────────────────────────────────────────────────────────
// Group 7 — Files & Audit Log
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_store_and_get_file_metadata() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "file-chan").await;
    let uploader = Uuid::new_v4();
    let file_id = Uuid::new_v4();

    node_db
        .store_file_metadata(
            file_id,
            channel_id,
            uploader,
            b"encrypted_filename",
            1024,
            "sha256_hash",
            "/storage/file.bin",
        )
        .await
        .unwrap();

    let meta = node_db.get_file_metadata(file_id).await.unwrap();
    assert!(meta.is_some());
    let m = meta.unwrap();
    assert_eq!(m.id, file_id);
    assert_eq!(m.channel_id, channel_id);
    assert_eq!(m.file_size_bytes, 1024);
}

#[tokio::test]
async fn test_get_file_metadata_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.get_file_metadata(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_list_channel_files() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "list-files-chan").await;
    let uploader = Uuid::new_v4();

    for i in 0..3 {
        node_db
            .store_file_metadata(
                Uuid::new_v4(),
                channel_id,
                uploader,
                b"enc_name",
                100 + i,
                &format!("hash{}", i),
                &format!("/path/{}", i),
            )
            .await
            .unwrap();
    }

    let files = node_db.list_channel_files(channel_id).await.unwrap();
    assert_eq!(files.len(), 3);
}

#[tokio::test]
async fn test_delete_file_metadata() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "del-file-chan").await;
    let file_id = Uuid::new_v4();

    node_db
        .store_file_metadata(
            file_id,
            channel_id,
            Uuid::new_v4(),
            b"enc",
            512,
            "hash",
            "/path",
        )
        .await
        .unwrap();

    node_db.delete_file_metadata(file_id).await.unwrap();

    let result = node_db.get_file_metadata(file_id).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_log_audit_event() {
    let (node_db, _) = make_node_db().await;
    let actor = Uuid::new_v4();
    let target = Uuid::new_v4();

    let audit_id = node_db
        .log_audit_event(
            actor,
            "create_channel",
            "channel",
            Some(target),
            Some("details here"),
        )
        .await
        .unwrap();

    assert_ne!(audit_id, Uuid::nil());
}

#[tokio::test]
async fn test_get_audit_log_raw() {
    let (node_db, _) = make_node_db().await;
    let actor = Uuid::new_v4();

    node_db
        .log_audit_event(actor, "action_a", "type_a", None, None)
        .await
        .unwrap();
    node_db
        .log_audit_event(actor, "action_b", "type_b", None, None)
        .await
        .unwrap();

    let log = node_db.get_audit_log_raw(10, None).await.unwrap();
    assert_eq!(log.len(), 2);
}

// ─────────────────────────────────────────────────────────────────
// Group 8 — Read Receipts & User Profiles
// ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mark_channel_read_and_get() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "read-chan").await;
    let user = Uuid::new_v4();
    let (msg_id, _) = store_msg(&node_db, channel_id, b"msg").await;

    node_db
        .mark_channel_read(user, channel_id, msg_id)
        .await
        .unwrap();

    let receipt = node_db.get_read_receipt(user, channel_id).await.unwrap();
    assert_eq!(receipt, Some(msg_id));
}

#[tokio::test]
async fn test_get_read_receipt_none_before_mark() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "no-receipt-chan").await;
    let user = Uuid::new_v4();

    let receipt = node_db.get_read_receipt(user, channel_id).await.unwrap();
    assert!(receipt.is_none());
}

#[tokio::test]
async fn test_mark_channel_read_updates_on_second_call() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "update-receipt-chan").await;
    let user = Uuid::new_v4();
    let sender = Uuid::new_v4();

    let (msg1, _) = node_db
        .store_message(channel_id, sender, b"first", None)
        .await
        .unwrap();
    let (msg2, _) = node_db
        .store_message(channel_id, sender, b"second", None)
        .await
        .unwrap();

    node_db
        .mark_channel_read(user, channel_id, msg1)
        .await
        .unwrap();
    node_db
        .mark_channel_read(user, channel_id, msg2)
        .await
        .unwrap();

    let receipt = node_db.get_read_receipt(user, channel_id).await.unwrap();
    assert_eq!(receipt, Some(msg2));
}

#[tokio::test]
async fn test_get_channel_read_receipts_multiple_users() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "multi-receipt-chan").await;
    let u1 = Uuid::new_v4();
    let u2 = Uuid::new_v4();
    let sender = Uuid::new_v4();

    let (msg_id, _) = node_db
        .store_message(channel_id, sender, b"msg", None)
        .await
        .unwrap();

    node_db
        .mark_channel_read(u1, channel_id, msg_id)
        .await
        .unwrap();
    node_db
        .mark_channel_read(u2, channel_id, msg_id)
        .await
        .unwrap();

    let receipts = node_db.get_channel_read_receipts(channel_id).await.unwrap();
    assert_eq!(receipts.len(), 2);
}

#[tokio::test]
async fn test_get_unread_count_no_receipt() {
    let (node_db, _) = make_node_db().await;
    let channel_id = create_channel(&node_db, "unread-no-receipt").await;
    let user = Uuid::new_v4();
    let sender = Uuid::new_v4();

    for _ in 0..3 {
        node_db
            .store_message(channel_id, sender, b"msg", None)
            .await
            .unwrap();
    }

    // No read receipt → all 3 are unread
    let count = node_db.get_unread_count(user, channel_id).await.unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn test_set_and_get_node_user_profile() {
    let (node_db, _) = make_node_db().await;
    let user_id = Uuid::new_v4();

    node_db
        .set_node_user_profile(user_id, Some(b"encrypted_name"), Some(b"encrypted_avatar"))
        .await
        .unwrap();

    let profile = node_db.get_node_user_profile(user_id).await.unwrap();
    assert!(profile.is_some());
    let p = profile.unwrap();
    assert_eq!(p.user_id, user_id);
    assert_eq!(p.encrypted_display_name, Some(b"encrypted_name".to_vec()));
}

#[tokio::test]
async fn test_get_node_user_profile_not_found() {
    let (node_db, _) = make_node_db().await;
    let result = node_db.get_node_user_profile(Uuid::new_v4()).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_get_node_user_profiles_all() {
    let (node_db, _) = make_node_db().await;

    for _ in 0..3 {
        node_db
            .set_node_user_profile(Uuid::new_v4(), None, None)
            .await
            .unwrap();
    }

    let profiles = node_db.get_node_user_profiles().await.unwrap();
    assert_eq!(profiles.len(), 3);
}
