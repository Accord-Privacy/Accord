//! End-to-end tests for the custom-role permission model.
//!
//! Verifies the governance rework: the Node owner has every permission, a plain
//! member only has @everyone, the auto-seeded Admin/Moderator custom roles exist
//! and grant power, rows carrying the legacy Admin/Moderator marker are bridged
//! onto those roles, and arbitrary single-bit custom roles keep their granularity.
//!
//! Memberships here are raw database rows, seeded with the `test-helpers`
//! function `Database::seed_node_member` (SPEC-01 REQ-18).

use accord_server::models::permission_bits::{ALL_PERMISSIONS, MANAGE_NODE};
use accord_server::node::NodeRole;
use accord_server::permissions::Permission;
use accord_server::state::AppState;

async fn user(state: &AppState, seed: &str) -> uuid::Uuid {
    state
        .register_user(format!("pk-{seed}"), "pw".to_string())
        .await
        .expect("register")
}

#[tokio::test]
async fn owner_has_all_permissions() {
    let state = AppState::new_in_memory().await.unwrap();
    let owner = user(&state, "owner").await;
    let node = state.db.create_node("N", owner, None).await.unwrap();

    assert_eq!(
        state
            .db
            .compute_node_permissions(node.id, owner)
            .await
            .unwrap(),
        ALL_PERMISSIONS
    );
    for p in [
        Permission::ManageNode,
        Permission::KickMembers,
        Permission::ManageChannels,
        Permission::ManageRoles,
        Permission::ManageEmojis,
    ] {
        assert!(
            state.db.node_member_can(node.id, owner, p).await,
            "owner {p:?}"
        );
    }
}

#[tokio::test]
async fn plain_member_has_only_everyone() {
    let state = AppState::new_in_memory().await.unwrap();
    let owner = user(&state, "owner").await;
    let alice = user(&state, "alice").await;
    let node = state.db.create_node("N", owner, None).await.unwrap();
    state
        .db
        .seed_node_member(node.id, alice, NodeRole::Member)
        .await
        .unwrap();

    // @everyone lets a member participate...
    assert!(
        state
            .db
            .node_member_can(node.id, alice, Permission::SendMessages)
            .await
    );
    // ...but not manage anything.
    assert!(
        !state
            .db
            .node_member_can(node.id, alice, Permission::KickMembers)
            .await
    );
    assert!(
        !state
            .db
            .node_member_can(node.id, alice, Permission::ManageNode)
            .await
    );
    assert!(
        !state
            .db
            .node_member_can(node.id, alice, Permission::ManageChannels)
            .await
    );
}

#[tokio::test]
async fn management_roles_are_seeded_on_create() {
    let state = AppState::new_in_memory().await.unwrap();
    let owner = user(&state, "owner").await;
    let node = state.db.create_node("N", owner, None).await.unwrap();

    assert!(state
        .db
        .get_role_by_name(node.id, "Admin")
        .await
        .unwrap()
        .is_some());
    assert!(state
        .db
        .get_role_by_name(node.id, "Moderator")
        .await
        .unwrap()
        .is_some());
    // Admin is a full-permission custom role.
    let admin = state
        .db
        .get_role_by_name(node.id, "Admin")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin.permissions, ALL_PERMISSIONS);
}

#[tokio::test]
async fn legacy_admin_member_is_bridged_to_admin_role() {
    let state = AppState::new_in_memory().await.unwrap();
    let owner = user(&state, "owner").await;
    let bob = user(&state, "bob").await;
    let node = state.db.create_node("N", owner, None).await.unwrap();

    // Legacy caller path: add a member as Admin.
    state
        .db
        .seed_node_member(node.id, bob, NodeRole::Admin)
        .await
        .unwrap();

    // He gets management power via the seeded Admin custom role, not a hardcoded enum.
    assert!(
        state
            .db
            .node_member_can(node.id, bob, Permission::ManageNode)
            .await
    );
    assert!(
        state
            .db
            .node_member_can(node.id, bob, Permission::KickMembers)
            .await
    );
    let roles = state.db.get_member_roles(node.id, bob).await.unwrap();
    assert!(roles.iter().any(|r| r.name == "Admin"));
}

#[tokio::test]
async fn single_bit_custom_role_grants_only_its_scope() {
    let state = AppState::new_in_memory().await.unwrap();
    let owner = user(&state, "owner").await;
    let carol = user(&state, "carol").await;
    let node = state.db.create_node("N", owner, None).await.unwrap();
    state
        .db
        .seed_node_member(node.id, carol, NodeRole::Member)
        .await
        .unwrap();

    // Owner-defined custom role holding only MANAGE_NODE.
    let role = state
        .db
        .create_role(node.id, "Settings", 0, MANAGE_NODE, 3, false, false, None)
        .await
        .unwrap();
    state
        .db
        .assign_member_role(node.id, carol, role.id)
        .await
        .unwrap();

    assert!(
        state
            .db
            .node_member_can(node.id, carol, Permission::ManageNode)
            .await
    );
    // But nothing outside that bit.
    assert!(
        !state
            .db
            .node_member_can(node.id, carol, Permission::KickMembers)
            .await
    );
    assert!(
        !state
            .db
            .node_member_can(node.id, carol, Permission::ManageRoles)
            .await
    );
}

/// The legacy role conversion runs once, through the migration ledger, so
/// reopening the database never duplicates or re-creates roles
/// (SPEC-01 REQ-48).
#[tokio::test]
async fn legacy_role_conversion_runs_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.db");
    let path = path.to_str().unwrap();
    let node = {
        let state = AppState::new(path).await.unwrap();
        let owner = user(&state, "owner").await;
        state.db.create_node("N", owner, None).await.unwrap()
    };

    for _ in 0..2 {
        let state = AppState::new(path).await.unwrap();
        assert!(state
            .db
            .ledger_applied_at("spec01_legacy_roles")
            .await
            .unwrap()
            .is_some());
        assert!(state.db.repair_report().ledger_applied.is_empty());
        let roles = state.db.get_node_roles(node.id).await.unwrap();
        for name in ["Admin", "Moderator"] {
            assert_eq!(roles.iter().filter(|r| r.name == name).count(), 1, "{name}");
        }
    }
}
