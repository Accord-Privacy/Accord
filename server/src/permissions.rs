//! Permission vocabulary for Node operations.
//!
//! The `Permission` enum is a readable vocabulary used at enforcement sites. The
//! authoritative source of truth is the per-Node **custom-role bitflag** system
//! (`roles`/`member_roles` + `Database::compute_node_permissions`): the only
//! hardcoded authorities are the **Node owner** (`nodes.owner_id`, gets every
//! permission) and, at the relay layer, the **Relay owner** (localhost). Admin /
//! Moderator are ordinary owner-defined custom roles, seeded with sensible
//! defaults on node creation — not hardcoded. See GOVERNANCE.md.
//!
//! This module maps the `Permission` vocabulary onto `permission_bits` so call
//! sites read `perms_have(effective_perms, Permission::X)` while enforcement is
//! driven entirely by the custom-role bitflags a member actually holds.

use crate::models::permission_bits as bits;

/// Permissions that can be granted to roles within a Node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Create new channels within the Node
    CreateChannel,
    /// Delete channels within the Node
    DeleteChannel,
    /// Manage channels (rename, move, organize categories)
    ManageChannels,
    /// Manage Node membership (invite/kick users, change roles)
    ManageMembers,
    /// Kick users from the Node
    KickMembers,
    /// Manage user roles within the Node
    ManageRoles,
    /// Create and manage Node invites
    ManageInvites,
    /// Send messages in channels
    SendMessages,
    /// Manage Node settings (name, description, etc.)
    ManageNode,
    /// View audit logs and Node management history
    ViewAuditLog,
    /// Manage custom emojis (upload/delete)
    ManageEmojis,
}

/// Map a `Permission` vocabulary item onto its `permission_bits` bit.
///
/// Several coarse operations share a bit because Accord's bitflag set does not
/// have a dedicated flag for every enum variant (e.g. create/delete/manage
/// channel all fall under `MANAGE_CHANNELS`; audit-log and emoji management fall
/// under `MANAGE_NODE`).
pub fn permission_bit(permission: Permission) -> u64 {
    match permission {
        Permission::CreateChannel | Permission::DeleteChannel | Permission::ManageChannels => {
            bits::MANAGE_CHANNELS
        }
        Permission::ManageMembers | Permission::KickMembers => bits::KICK_MEMBERS,
        Permission::ManageRoles => bits::MANAGE_ROLES,
        Permission::ManageInvites => bits::CREATE_INVITE,
        Permission::SendMessages => bits::SEND_MESSAGES,
        Permission::ManageNode | Permission::ViewAuditLog | Permission::ManageEmojis => {
            bits::MANAGE_NODE
        }
    }
}

/// Does this effective bitflag set grant `permission`?
///
/// `perms` is expected to come from `Database::compute_node_permissions`, which
/// already expands the Node owner and the `ADMINISTRATOR` bit to the full
/// permission set — so a plain bit test is sufficient here.
pub fn perms_have(perms: u64, permission: Permission) -> bool {
    perms & permission_bit(permission) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::permission_bits::{ALL_PERMISSIONS, DEFAULT_EVERYONE};

    #[test]
    fn all_permissions_grants_everything() {
        // The owner / ADMINISTRATOR expansion (ALL_PERMISSIONS) grants every
        // vocabulary permission.
        for p in [
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
        ] {
            assert!(perms_have(ALL_PERMISSIONS, p), "ALL should grant {p:?}");
        }
    }

    #[test]
    fn default_everyone_can_send_but_not_manage() {
        assert!(perms_have(DEFAULT_EVERYONE, Permission::SendMessages));
        assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageInvites)); // invite mgmt is not default
        assert!(!perms_have(DEFAULT_EVERYONE, Permission::KickMembers));
        assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageNode));
        assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageChannels));
        assert!(!perms_have(DEFAULT_EVERYONE, Permission::ManageRoles));
    }

    #[test]
    fn empty_perms_grant_nothing() {
        assert!(!perms_have(0, Permission::SendMessages));
        assert!(!perms_have(0, Permission::KickMembers));
        assert!(!perms_have(0, Permission::ManageNode));
    }

    #[test]
    fn single_bit_role_grants_only_that_permission() {
        // A custom role holding just MANAGE_CHANNELS grants the channel-management
        // vocabulary but nothing else — proving granularity survives.
        let perms = bits::MANAGE_CHANNELS;
        assert!(perms_have(perms, Permission::CreateChannel));
        assert!(perms_have(perms, Permission::DeleteChannel));
        assert!(perms_have(perms, Permission::ManageChannels));
        assert!(!perms_have(perms, Permission::KickMembers));
        assert!(!perms_have(perms, Permission::ManageNode));
    }

    #[test]
    fn coarse_bits_are_shared_as_documented() {
        assert_eq!(permission_bit(Permission::ViewAuditLog), bits::MANAGE_NODE);
        assert_eq!(permission_bit(Permission::ManageEmojis), bits::MANAGE_NODE);
        assert_eq!(
            permission_bit(Permission::ManageMembers),
            bits::KICK_MEMBERS
        );
    }
}
