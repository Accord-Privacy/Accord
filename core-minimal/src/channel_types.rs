//! # Channel System Implementation
//!
//! Demonstrates the hybrid lobby/private channel system with entry requests.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Types of channels in Accord
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelType {
    /// Lobby channel - anyone can join freely
    Lobby,
    /// Private channel with visibility control
    Private { visible_in_list: bool },
    /// Voice channel (can be lobby or private)
    Voice { access_type: VoiceAccessType },
    /// Text channel for messaging
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoiceAccessType {
    Lobby,
    Private { visible_in_list: bool },
}

/// User permissions within a channel
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserPermissions {
    pub can_speak: bool,
    pub can_invite_others: bool,
    pub can_approve_entry: bool,
    pub can_kick_users: bool,
    pub can_modify_channel: bool,
}

/// Channel member information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelMember {
    pub user_id: Uuid,
    pub username: String,
    pub permissions: UserPermissions,
    pub joined_at: chrono::DateTime<chrono::Utc>,
    pub is_online: bool,
}

/// Entry request for private channels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryRequest {
    pub request_id: Uuid,
    pub user_id: Uuid,
    pub username: String,
    pub channel_id: Uuid,
    pub message: Option<String>,
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

/// Channel configuration and state
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub channel_type: ChannelType,
    pub created_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub members: HashMap<Uuid, ChannelMember>,
    pub pending_requests: Vec<EntryRequest>,
    pub max_members: Option<u32>,
}

/// Channel manager handles all channel operations
pub struct ChannelManager {
    channels: HashMap<Uuid, Channel>,
    user_memberships: HashMap<Uuid, HashSet<Uuid>>, // user_id -> channel_ids
}

impl UserPermissions {
    /// Default permissions for regular members
    pub fn member() -> Self {
        Self {
            can_speak: true,
            can_invite_others: false,
            can_approve_entry: false,
            can_kick_users: false,
            can_modify_channel: false,
        }
    }

    /// Permissions for channel moderators
    pub fn moderator() -> Self {
        Self {
            can_speak: true,
            can_invite_others: true,
            can_approve_entry: true,
            can_kick_users: true,
            can_modify_channel: false,
        }
    }

    /// Full permissions for channel admins
    pub fn admin() -> Self {
        Self {
            can_speak: true,
            can_invite_others: true,
            can_approve_entry: true,
            can_kick_users: true,
            can_modify_channel: true,
        }
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelManager {
    /// Create new channel manager
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            user_memberships: HashMap::new(),
        }
    }

    /// Create a new channel
    pub fn create_channel(
        &mut self,
        name: String,
        channel_type: ChannelType,
        creator_id: Uuid,
        creator_username: String,
        description: Option<String>,
    ) -> Uuid {
        let channel_id = Uuid::new_v4();

        let mut members = HashMap::new();
        members.insert(
            creator_id,
            ChannelMember {
                user_id: creator_id,
                username: creator_username,
                permissions: UserPermissions::admin(), // Creator gets admin permissions
                joined_at: chrono::Utc::now(),
                is_online: true,
            },
        );

        let channel = Channel {
            id: channel_id,
            name,
            description,
            channel_type,
            created_by: creator_id,
            created_at: chrono::Utc::now(),
            members,
            pending_requests: Vec::new(),
            max_members: None,
        };

        self.channels.insert(channel_id, channel);

        // Add to user memberships
        self.user_memberships
            .entry(creator_id)
            .or_default()
            .insert(channel_id);

        channel_id
    }

    /// Join a lobby channel immediately
    pub fn join_lobby_channel(
        &mut self,
        channel_id: Uuid,
        user_id: Uuid,
        username: String,
    ) -> Result<(), String> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or("Channel not found")?;

        // Check if it's a lobby channel
        match channel.channel_type {
            ChannelType::Lobby
            | ChannelType::Voice {
                access_type: VoiceAccessType::Lobby,
            }
            | ChannelType::Text => {
                // Check max members
                if let Some(max) = channel.max_members {
                    if channel.members.len() >= max as usize {
                        return Err("Channel is full".to_string());
                    }
                }

                // Check if already a member
                if channel.members.contains_key(&user_id) {
                    return Err("Already a member of this channel".to_string());
                }

                // Add user with default member permissions
                channel.members.insert(
                    user_id,
                    ChannelMember {
                        user_id,
                        username,
                        permissions: UserPermissions::member(),
                        joined_at: chrono::Utc::now(),
                        is_online: true,
                    },
                );

                // Add to user memberships
                self.user_memberships
                    .entry(user_id)
                    .or_default()
                    .insert(channel_id);

                Ok(())
            }
            _ => Err("Cannot directly join private channel".to_string()),
        }
    }

    /// Request entry to a private channel
    pub fn request_entry(
        &mut self,
        channel_id: Uuid,
        user_id: Uuid,
        username: String,
        message: Option<String>,
    ) -> Result<Uuid, String> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or("Channel not found")?;

        // Check if it's a private channel
        match channel.channel_type {
            ChannelType::Private { .. }
            | ChannelType::Voice {
                access_type: VoiceAccessType::Private { .. },
            } => {
                // Check if already a member
                if channel.members.contains_key(&user_id) {
                    return Err("Already a member of this channel".to_string());
                }

                // Check if request already exists
                if channel
                    .pending_requests
                    .iter()
                    .any(|req| req.user_id == user_id)
                {
                    return Err("Entry request already pending".to_string());
                }

                let request_id = Uuid::new_v4();
                let request = EntryRequest {
                    request_id,
                    user_id,
                    username,
                    channel_id,
                    message,
                    requested_at: chrono::Utc::now(),
                };

                channel.pending_requests.push(request);
                Ok(request_id)
            }
            _ => Err("Cannot request entry to lobby channel - just join directly".to_string()),
        }
    }

    /// Approve an entry request
    pub fn approve_entry(&mut self, request_id: Uuid, approver_id: Uuid) -> Result<(), String> {
        // Find the channel and request
        let mut found_channel_id = None;
        let mut user_to_add = None;

        for (channel_id, channel) in &mut self.channels {
            if let Some(pos) = channel
                .pending_requests
                .iter()
                .position(|req| req.request_id == request_id)
            {
                // Check if approver has permission
                if let Some(approver) = channel.members.get(&approver_id) {
                    if !approver.permissions.can_approve_entry {
                        return Err("No permission to approve entry requests".to_string());
                    }
                } else {
                    return Err("Approver not in channel".to_string());
                }

                let request = channel.pending_requests.remove(pos);
                user_to_add = Some((request.user_id, request.username));
                found_channel_id = Some(*channel_id);
                break;
            }
        }

        if let (Some(channel_id), Some((user_id, username))) = (found_channel_id, user_to_add) {
            let channel = self.channels.get_mut(&channel_id).unwrap();

            // Add user as member
            channel.members.insert(
                user_id,
                ChannelMember {
                    user_id,
                    username,
                    permissions: UserPermissions::member(),
                    joined_at: chrono::Utc::now(),
                    is_online: true,
                },
            );

            // Add to user memberships
            self.user_memberships
                .entry(user_id)
                .or_default()
                .insert(channel_id);

            Ok(())
        } else {
            Err("Entry request not found".to_string())
        }
    }

    /// Deny an entry request
    pub fn deny_entry(&mut self, request_id: Uuid, denier_id: Uuid) -> Result<(), String> {
        for channel in self.channels.values_mut() {
            if let Some(pos) = channel
                .pending_requests
                .iter()
                .position(|req| req.request_id == request_id)
            {
                // Check if denier has permission
                if let Some(denier) = channel.members.get(&denier_id) {
                    if !denier.permissions.can_approve_entry {
                        return Err("No permission to deny entry requests".to_string());
                    }
                } else {
                    return Err("Denier not in channel".to_string());
                }

                channel.pending_requests.remove(pos);
                return Ok(());
            }
        }

        Err("Entry request not found".to_string())
    }

    /// Get channels visible to a user
    pub fn get_visible_channels(&self, user_id: Uuid) -> Vec<&Channel> {
        self.channels
            .values()
            .filter(|channel| {
                match &channel.channel_type {
                    // Lobby channels are always visible
                    ChannelType::Lobby | ChannelType::Text => true,
                    ChannelType::Voice {
                        access_type: VoiceAccessType::Lobby,
                    } => true,

                    // Private channels - visible if user is member OR visibility is enabled
                    ChannelType::Private { visible_in_list } => {
                        *visible_in_list || channel.members.contains_key(&user_id)
                    }
                    ChannelType::Voice {
                        access_type: VoiceAccessType::Private { visible_in_list },
                    } => *visible_in_list || channel.members.contains_key(&user_id),
                }
            })
            .collect()
    }

    /// Get pending requests for channels where user can approve
    pub fn get_pending_requests(&self, user_id: Uuid) -> Vec<&EntryRequest> {
        let mut requests = Vec::new();

        for channel in self.channels.values() {
            if let Some(member) = channel.members.get(&user_id) {
                if member.permissions.can_approve_entry {
                    requests.extend(channel.pending_requests.iter());
                }
            }
        }

        requests
    }

    /// Leave a channel
    pub fn leave_channel(&mut self, channel_id: Uuid, user_id: Uuid) -> Result<(), String> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or("Channel not found")?;

        if !channel.members.contains_key(&user_id) {
            return Err("Not a member of this channel".to_string());
        }

        channel.members.remove(&user_id);

        if let Some(memberships) = self.user_memberships.get_mut(&user_id) {
            memberships.remove(&channel_id);
        }

        Ok(())
    }

    /// Get channel by ID
    pub fn get_channel(&self, channel_id: Uuid) -> Option<&Channel> {
        self.channels.get(&channel_id)
    }

    /// Update user online status
    pub fn set_user_online(&mut self, user_id: Uuid, online: bool) {
        for channel in self.channels.values_mut() {
            if let Some(member) = channel.members.get_mut(&user_id) {
                member.is_online = online;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();

        let channel_id = manager.create_channel(
            "General".to_string(),
            ChannelType::Lobby,
            creator_id,
            "TestUser".to_string(),
            Some("General discussion".to_string()),
        );

        let channel = manager.get_channel(channel_id).unwrap();
        assert_eq!(channel.name, "General");
        assert_eq!(channel.created_by, creator_id);
        assert!(channel.members.contains_key(&creator_id));
    }

    #[test]
    fn test_lobby_channel_join() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let channel_id = manager.create_channel(
            "Lobby".to_string(),
            ChannelType::Lobby,
            creator_id,
            "Creator".to_string(),
            None,
        );

        // User should be able to join directly
        let result = manager.join_lobby_channel(channel_id, user_id, "TestUser".to_string());
        assert!(result.is_ok());

        let channel = manager.get_channel(channel_id).unwrap();
        assert!(channel.members.contains_key(&user_id));
    }

    #[test]
    fn test_private_channel_entry_request() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let channel_id = manager.create_channel(
            "Private".to_string(),
            ChannelType::Private {
                visible_in_list: true,
            },
            creator_id,
            "Creator".to_string(),
            None,
        );

        // User should need to request entry
        let request_id = manager
            .request_entry(
                channel_id,
                user_id,
                "TestUser".to_string(),
                Some("Please let me join!".to_string()),
            )
            .unwrap();

        // Creator should be able to approve
        let result = manager.approve_entry(request_id, creator_id);
        assert!(result.is_ok());

        let channel = manager.get_channel(channel_id).unwrap();
        assert!(channel.members.contains_key(&user_id));
        assert!(channel.pending_requests.is_empty());
    }

    #[test]
    fn test_channel_visibility() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Create visible private channel
        let _visible_private = manager.create_channel(
            "Visible Private".to_string(),
            ChannelType::Private {
                visible_in_list: true,
            },
            creator_id,
            "Creator".to_string(),
            None,
        );

        // Create hidden private channel
        let _hidden_private = manager.create_channel(
            "Hidden Private".to_string(),
            ChannelType::Private {
                visible_in_list: false,
            },
            creator_id,
            "Creator".to_string(),
            None,
        );

        // Create lobby channel
        let _lobby = manager.create_channel(
            "Lobby".to_string(),
            ChannelType::Lobby,
            creator_id,
            "Creator".to_string(),
            None,
        );

        let visible_channels = manager.get_visible_channels(user_id);
        // User should see: visible private + lobby, but not hidden private
        assert_eq!(visible_channels.len(), 2);
    }
}
