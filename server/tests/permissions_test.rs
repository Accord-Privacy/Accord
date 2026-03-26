//! External integration tests for the permissions module
//!
//! Covers role_permissions and has_permission for all NodeRoles,
//! verifying that each role gets exactly the right set of permissions.

#![allow(clippy::all)]

use accord_server::node::NodeRole;
use accord_server::permissions::{has_permission, role_permissions, Permission};

// ============================================================================
// Group 1 — Admin role permissions
// ============================================================================

#[test]
fn admin_has_create_channel() {
    assert!(has_permission(NodeRole::Admin, Permission::CreateChannel));
}

#[test]
fn admin_has_delete_channel() {
    assert!(has_permission(NodeRole::Admin, Permission::DeleteChannel));
}

#[test]
fn admin_has_manage_channels() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageChannels));
}

#[test]
fn admin_has_manage_members() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageMembers));
}

#[test]
fn admin_has_kick_members() {
    assert!(has_permission(NodeRole::Admin, Permission::KickMembers));
}

#[test]
fn admin_has_manage_roles() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageRoles));
}

#[test]
fn admin_has_manage_invites() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageInvites));
}

#[test]
fn admin_has_send_messages() {
    assert!(has_permission(NodeRole::Admin, Permission::SendMessages));
}

#[test]
fn admin_has_manage_node() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageNode));
}

#[test]
fn admin_has_view_audit_log() {
    assert!(has_permission(NodeRole::Admin, Permission::ViewAuditLog));
}

#[test]
fn admin_has_manage_emojis() {
    assert!(has_permission(NodeRole::Admin, Permission::ManageEmojis));
}

#[test]
fn admin_permission_set_has_eleven_permissions() {
    // Admin should have all 11 defined permissions
    let perms = role_permissions(NodeRole::Admin);
    assert_eq!(perms.len(), 11);
}

// ============================================================================
// Group 2 — Moderator role permissions
// ============================================================================

#[test]
fn moderator_has_kick_members() {
    assert!(has_permission(NodeRole::Moderator, Permission::KickMembers));
}

#[test]
fn moderator_has_manage_invites() {
    assert!(has_permission(
        NodeRole::Moderator,
        Permission::ManageInvites
    ));
}

#[test]
fn moderator_has_send_messages() {
    assert!(has_permission(
        NodeRole::Moderator,
        Permission::SendMessages
    ));
}

#[test]
fn moderator_has_view_audit_log() {
    assert!(has_permission(
        NodeRole::Moderator,
        Permission::ViewAuditLog
    ));
}

#[test]
fn moderator_lacks_create_channel() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::CreateChannel
    ));
}

#[test]
fn moderator_lacks_delete_channel() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::DeleteChannel
    ));
}

#[test]
fn moderator_lacks_manage_channels() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::ManageChannels
    ));
}

#[test]
fn moderator_lacks_manage_members() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::ManageMembers
    ));
}

#[test]
fn moderator_lacks_manage_roles() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::ManageRoles
    ));
}

#[test]
fn moderator_lacks_manage_node() {
    assert!(!has_permission(NodeRole::Moderator, Permission::ManageNode));
}

#[test]
fn moderator_lacks_manage_emojis() {
    assert!(!has_permission(
        NodeRole::Moderator,
        Permission::ManageEmojis
    ));
}

#[test]
fn moderator_permission_set_has_four_permissions() {
    let perms = role_permissions(NodeRole::Moderator);
    assert_eq!(perms.len(), 4);
}

// ============================================================================
// Group 3 — Member role permissions
// ============================================================================

#[test]
fn member_has_send_messages() {
    assert!(has_permission(NodeRole::Member, Permission::SendMessages));
}

#[test]
fn member_lacks_create_channel() {
    assert!(!has_permission(NodeRole::Member, Permission::CreateChannel));
}

#[test]
fn member_lacks_delete_channel() {
    assert!(!has_permission(NodeRole::Member, Permission::DeleteChannel));
}

#[test]
fn member_lacks_manage_channels() {
    assert!(!has_permission(
        NodeRole::Member,
        Permission::ManageChannels
    ));
}

#[test]
fn member_lacks_manage_members() {
    assert!(!has_permission(NodeRole::Member, Permission::ManageMembers));
}

#[test]
fn member_lacks_kick_members() {
    assert!(!has_permission(NodeRole::Member, Permission::KickMembers));
}

#[test]
fn member_lacks_manage_roles() {
    assert!(!has_permission(NodeRole::Member, Permission::ManageRoles));
}

#[test]
fn member_lacks_manage_invites() {
    assert!(!has_permission(NodeRole::Member, Permission::ManageInvites));
}

#[test]
fn member_lacks_manage_node() {
    assert!(!has_permission(NodeRole::Member, Permission::ManageNode));
}

#[test]
fn member_lacks_view_audit_log() {
    assert!(!has_permission(NodeRole::Member, Permission::ViewAuditLog));
}

#[test]
fn member_lacks_manage_emojis() {
    assert!(!has_permission(NodeRole::Member, Permission::ManageEmojis));
}

#[test]
fn member_permission_set_has_one_permission() {
    let perms = role_permissions(NodeRole::Member);
    assert_eq!(perms.len(), 1);
}

// ============================================================================
// Group 4 — Admin vs Moderator vs Member differences
// ============================================================================

#[test]
fn admin_has_strictly_more_permissions_than_moderator() {
    let admin_perms = role_permissions(NodeRole::Admin);
    let mod_perms = role_permissions(NodeRole::Moderator);
    // Every moderator permission is also an admin permission
    for p in &mod_perms {
        assert!(
            admin_perms.contains(p),
            "Admin should have all moderator permissions, missing: {:?}",
            p
        );
    }
    // Admin has more than moderator
    assert!(admin_perms.len() > mod_perms.len());
}

#[test]
fn moderator_has_strictly_more_permissions_than_member() {
    let mod_perms = role_permissions(NodeRole::Moderator);
    let member_perms = role_permissions(NodeRole::Member);
    // Every member permission is also a moderator permission
    for p in &member_perms {
        assert!(
            mod_perms.contains(p),
            "Moderator should have all member permissions, missing: {:?}",
            p
        );
    }
    // Moderator has more than member
    assert!(mod_perms.len() > member_perms.len());
}

#[test]
fn admin_can_do_things_moderator_cannot() {
    // Admin-only permissions
    let admin_only = [
        Permission::CreateChannel,
        Permission::DeleteChannel,
        Permission::ManageChannels,
        Permission::ManageMembers,
        Permission::ManageRoles,
        Permission::ManageNode,
        Permission::ManageEmojis,
    ];
    for p in admin_only {
        assert!(
            has_permission(NodeRole::Admin, p),
            "Admin should have {:?}",
            p
        );
        assert!(
            !has_permission(NodeRole::Moderator, p),
            "Moderator should NOT have {:?}",
            p
        );
    }
}

#[test]
fn moderator_can_do_things_member_cannot() {
    let mod_only = [
        Permission::KickMembers,
        Permission::ManageInvites,
        Permission::ViewAuditLog,
    ];
    for p in mod_only {
        assert!(
            has_permission(NodeRole::Moderator, p),
            "Moderator should have {:?}",
            p
        );
        assert!(
            !has_permission(NodeRole::Member, p),
            "Member should NOT have {:?}",
            p
        );
    }
}

// ============================================================================
// Group 5 — role_permissions returns a HashSet (deduplication)
// ============================================================================

#[test]
fn role_permissions_returns_set_no_duplicates_admin() {
    let perms = role_permissions(NodeRole::Admin);
    // HashSet guarantees uniqueness; len() == actual distinct perms
    assert_eq!(perms.len(), 11);
}

#[test]
fn role_permissions_returns_set_no_duplicates_moderator() {
    let perms = role_permissions(NodeRole::Moderator);
    assert_eq!(perms.len(), 4);
}

#[test]
fn role_permissions_returns_set_no_duplicates_member() {
    let perms = role_permissions(NodeRole::Member);
    assert_eq!(perms.len(), 1);
}

// ============================================================================
// Group 6 — has_permission consistency with role_permissions
// ============================================================================

#[test]
fn has_permission_consistent_with_role_permissions_admin() {
    let all_perms = [
        Permission::CreateChannel,
        Permission::DeleteChannel,
        Permission::ManageChannels,
        Permission::ManageMembers,
        Permission::KickMembers,
        Permission::ManageRoles,
        Permission::ManageInvites,
        Permission::SendMessages,
        Permission::ManageNode,
        Permission::ViewAuditLog,
        Permission::ManageEmojis,
    ];
    let set = role_permissions(NodeRole::Admin);
    for p in all_perms {
        assert_eq!(
            has_permission(NodeRole::Admin, p),
            set.contains(&p),
            "has_permission and role_permissions disagree on Admin/{:?}",
            p
        );
    }
}

#[test]
fn has_permission_consistent_with_role_permissions_moderator() {
    let all_perms = [
        Permission::CreateChannel,
        Permission::DeleteChannel,
        Permission::ManageChannels,
        Permission::ManageMembers,
        Permission::KickMembers,
        Permission::ManageRoles,
        Permission::ManageInvites,
        Permission::SendMessages,
        Permission::ManageNode,
        Permission::ViewAuditLog,
        Permission::ManageEmojis,
    ];
    let set = role_permissions(NodeRole::Moderator);
    for p in all_perms {
        assert_eq!(
            has_permission(NodeRole::Moderator, p),
            set.contains(&p),
            "has_permission and role_permissions disagree on Moderator/{:?}",
            p
        );
    }
}

#[test]
fn has_permission_consistent_with_role_permissions_member() {
    let all_perms = [
        Permission::CreateChannel,
        Permission::DeleteChannel,
        Permission::ManageChannels,
        Permission::ManageMembers,
        Permission::KickMembers,
        Permission::ManageRoles,
        Permission::ManageInvites,
        Permission::SendMessages,
        Permission::ManageNode,
        Permission::ViewAuditLog,
        Permission::ManageEmojis,
    ];
    let set = role_permissions(NodeRole::Member);
    for p in all_perms {
        assert_eq!(
            has_permission(NodeRole::Member, p),
            set.contains(&p),
            "has_permission and role_permissions disagree on Member/{:?}",
            p
        );
    }
}
