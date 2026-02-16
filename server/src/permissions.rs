//! Role-based permission system for Node operations
//!
//! This module defines permissions and maps them to NodeRoles, providing
//! a centralized system for controlling access to Node operations.

use crate::node::NodeRole;
use std::collections::HashSet;

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
}

/// Get all permissions for a given role
pub fn role_permissions(role: NodeRole) -> HashSet<Permission> {
    use Permission::*;

    match role {
        NodeRole::Admin => {
            // Admins have all permissions
            vec![
                CreateChannel,
                DeleteChannel,
                ManageChannels,
                ManageMembers,
                KickMembers,
                ManageRoles,
                ManageInvites,
                SendMessages,
                ManageNode,
                ViewAuditLog,
            ]
            .into_iter()
            .collect()
        }
        NodeRole::Moderator => {
            // Moderators have limited management permissions
            vec![KickMembers, ManageInvites, SendMessages, ViewAuditLog]
                .into_iter()
                .collect()
        }
        NodeRole::Member => {
            // Members can only participate
            vec![SendMessages].into_iter().collect()
        }
    }
}

/// Check if a role has a specific permission
pub fn has_permission(user_role: NodeRole, permission: Permission) -> bool {
    role_permissions(user_role).contains(&permission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_all_permissions() {
        let admin_perms = role_permissions(NodeRole::Admin);

        // Admin should have all permissions
        assert!(admin_perms.contains(&Permission::CreateChannel));
        assert!(admin_perms.contains(&Permission::DeleteChannel));
        assert!(admin_perms.contains(&Permission::ManageMembers));
        assert!(admin_perms.contains(&Permission::KickMembers));
        assert!(admin_perms.contains(&Permission::ManageRoles));
        assert!(admin_perms.contains(&Permission::ManageInvites));
        assert!(admin_perms.contains(&Permission::SendMessages));
        assert!(admin_perms.contains(&Permission::ManageNode));
        assert!(admin_perms.contains(&Permission::ViewAuditLog));
    }

    #[test]
    fn moderator_has_limited_permissions() {
        let mod_perms = role_permissions(NodeRole::Moderator);

        // Moderator should have these permissions
        assert!(mod_perms.contains(&Permission::KickMembers));
        assert!(mod_perms.contains(&Permission::ManageInvites));
        assert!(mod_perms.contains(&Permission::SendMessages));
        assert!(mod_perms.contains(&Permission::ViewAuditLog));

        // But not these
        assert!(!mod_perms.contains(&Permission::CreateChannel));
        assert!(!mod_perms.contains(&Permission::DeleteChannel));
        assert!(!mod_perms.contains(&Permission::ManageMembers));
        assert!(!mod_perms.contains(&Permission::ManageRoles));
        assert!(!mod_perms.contains(&Permission::ManageNode));
    }

    #[test]
    fn member_has_minimal_permissions() {
        let member_perms = role_permissions(NodeRole::Member);

        // Member should only have this permission
        assert!(member_perms.contains(&Permission::SendMessages));

        // But not any management permissions
        assert!(!member_perms.contains(&Permission::CreateChannel));
        assert!(!member_perms.contains(&Permission::DeleteChannel));
        assert!(!member_perms.contains(&Permission::ManageMembers));
        assert!(!member_perms.contains(&Permission::KickMembers));
        assert!(!member_perms.contains(&Permission::ManageRoles));
        assert!(!member_perms.contains(&Permission::ManageInvites));
        assert!(!member_perms.contains(&Permission::ManageNode));
        assert!(!member_perms.contains(&Permission::ViewAuditLog));
    }

    #[test]
    fn has_permission_works_correctly() {
        // Admin should have all permissions
        assert!(has_permission(NodeRole::Admin, Permission::CreateChannel));
        assert!(has_permission(NodeRole::Admin, Permission::ManageNode));

        // Moderator should have some permissions but not others
        assert!(has_permission(NodeRole::Moderator, Permission::KickMembers));
        assert!(!has_permission(
            NodeRole::Moderator,
            Permission::CreateChannel
        ));

        // Member should only send messages
        assert!(has_permission(NodeRole::Member, Permission::SendMessages));
        assert!(!has_permission(NodeRole::Member, Permission::KickMembers));
    }
}
