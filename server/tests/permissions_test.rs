//! Permission-vocabulary tests for the custom-role bitflag model.
//!
//! Hardcoded roles were removed: the only hardcoded authorities are the Node
//! owner (all permissions) and the Relay owner (localhost). Admin/Moderator are
//! ordinary owner-defined custom roles. Permission enforcement runs on the
//! `permission_bits` bitflags a member effectively holds; this file covers the
//! `Permission` → bit mapping that enforcement sites read through. See
//! GOVERNANCE.md and docs/permission-system.md.

use accord_server::models::permission_bits::{
    ALL_PERMISSIONS, DEFAULT_EVERYONE, KICK_MEMBERS, MANAGE_CHANNELS, MANAGE_NODE, MANAGE_ROLES,
    SEND_MESSAGES,
};
use accord_server::permissions::{permission_bit, perms_have, Permission};

const ALL_VOCAB: [Permission; 11] = [
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

#[test]
fn all_permissions_grants_every_vocabulary_item() {
    // This is what the Node owner and any ADMINISTRATOR role resolve to.
    for p in ALL_VOCAB {
        assert!(perms_have(ALL_PERMISSIONS, p), "ALL should grant {p:?}");
    }
}

#[test]
fn empty_perms_grant_nothing() {
    for p in ALL_VOCAB {
        assert!(!perms_have(0, p), "empty should deny {p:?}");
    }
}

#[test]
fn default_everyone_can_participate_but_not_manage() {
    // A plain member (no assigned roles) resolves to @everyone = DEFAULT_EVERYONE.
    assert!(perms_have(DEFAULT_EVERYONE, Permission::SendMessages));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageInvites)); // invite mgmt gated to roles

    assert!(!perms_have(DEFAULT_EVERYONE, Permission::KickMembers));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageMembers));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageChannels));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::CreateChannel));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::DeleteChannel));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageRoles));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageNode));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ViewAuditLog));
    assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageEmojis));
}

#[test]
fn single_bit_custom_role_grants_only_its_scope() {
    // A custom role that holds only KICK_MEMBERS grants kick/manage-members and
    // nothing else — proving arbitrary-bit custom roles keep their granularity
    // (the whole point of dropping the coarse hardcoded enum).
    let perms = KICK_MEMBERS;
    assert!(perms_have(perms, Permission::KickMembers));
    assert!(perms_have(perms, Permission::ManageMembers));
    assert!(!perms_have(perms, Permission::ManageChannels));
    assert!(!perms_have(perms, Permission::ManageNode));
    assert!(!perms_have(perms, Permission::SendMessages));
}

#[test]
fn a_moderator_shaped_role_has_expected_scope() {
    // Roughly the seeded "Moderator" default: can kick + manage channels, cannot
    // manage the node or roles.
    let perms = KICK_MEMBERS | MANAGE_CHANNELS;
    assert!(perms_have(perms, Permission::KickMembers));
    assert!(perms_have(perms, Permission::ManageChannels));
    assert!(perms_have(perms, Permission::CreateChannel));
    assert!(!perms_have(perms, Permission::ManageNode));
    assert!(!perms_have(perms, Permission::ManageRoles));
}

#[test]
fn permission_bit_mapping_is_stable() {
    assert_eq!(permission_bit(Permission::SendMessages), SEND_MESSAGES);
    assert_eq!(permission_bit(Permission::KickMembers), KICK_MEMBERS);
    assert_eq!(permission_bit(Permission::ManageMembers), KICK_MEMBERS);
    assert_eq!(permission_bit(Permission::ManageRoles), MANAGE_ROLES);
    assert_eq!(permission_bit(Permission::CreateChannel), MANAGE_CHANNELS);
    assert_eq!(permission_bit(Permission::DeleteChannel), MANAGE_CHANNELS);
    assert_eq!(permission_bit(Permission::ManageChannels), MANAGE_CHANNELS);
    // Coarse-mapped onto MANAGE_NODE (no dedicated bits in the current set).
    assert_eq!(permission_bit(Permission::ManageNode), MANAGE_NODE);
    assert_eq!(permission_bit(Permission::ViewAuditLog), MANAGE_NODE);
    assert_eq!(permission_bit(Permission::ManageEmojis), MANAGE_NODE);
}
