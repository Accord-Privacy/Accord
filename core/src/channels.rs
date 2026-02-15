//! # Accord Channel Management
//!
//! Hybrid channel system with public lobby and private restricted channels.
//! Supports permission-based access with entry request/approval system.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Channel types in Accord
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChannelType {
    /// Open lobby channel - anyone can join
    Lobby,
    /// Private channel - role/user restricted
    Private { visible_in_list: bool },
    /// Text channel for messaging
    Text,
    /// Voice channel for audio communication
    Voice { channel_type: VoiceChannelType },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VoiceChannelType {
    Lobby,
    Private { visible_in_list: bool },
}

/// User permissions within a channel
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelPermissions {
    pub can_speak: bool,
    pub can_invite: bool,
    pub can_approve_entry: bool,
    pub can_kick: bool,
    pub can_modify_permissions: bool,
}

/// Channel member with their permissions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelMember {
    pub user_id: Uuid,
    pub permissions: ChannelPermissions,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}

/// Entry request for private channels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntryRequest {
    pub request_id: Uuid,
    pub user_id: Uuid,
    pub channel_id: Uuid,
    pub requested_at: chrono::DateTime<chrono::Utc>,
    pub message: Option<String>, // Optional message explaining why they want to join
}

/// Channel configuration and metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Channel {
    pub id: Uuid,
    pub name: String,
    pub channel_type: ChannelType,
    pub description: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: Uuid,
    pub members: HashMap<Uuid, ChannelMember>,
    pub entry_requests: Vec<EntryRequest>,
    pub required_roles: HashSet<String>, // Roles that can auto-join private channels
}

/// Channel manager for handling access control and entry requests
pub struct ChannelManager {
    channels: HashMap<Uuid, Channel>,
    user_channels: HashMap<Uuid, HashSet<Uuid>>, // user_id -> channel_ids
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            user_channels: HashMap::new(),
        }
    }

    /// Create a new channel
    pub fn create_channel(
        &mut self,
        name: String,
        channel_type: ChannelType,
        creator_id: Uuid,
        description: Option<String>,
    ) -> Result<Uuid> {
        let channel_id = Uuid::new_v4();

        // Creator gets full permissions
        let creator_permissions = ChannelPermissions {
            can_speak: true,
            can_invite: true,
            can_approve_entry: true,
            can_kick: true,
            can_modify_permissions: true,
        };

        let mut members = HashMap::new();
        members.insert(
            creator_id,
            ChannelMember {
                user_id: creator_id,
                permissions: creator_permissions,
                joined_at: chrono::Utc::now(),
            },
        );

        let channel = Channel {
            id: channel_id,
            name,
            channel_type,
            description,
            created_at: chrono::Utc::now(),
            created_by: creator_id,
            members,
            entry_requests: Vec::new(),
            required_roles: HashSet::new(),
        };

        self.channels.insert(channel_id, channel);

        // Add to user's channel list
        self.user_channels
            .entry(creator_id)
            .or_insert_with(HashSet::new)
            .insert(channel_id);

        Ok(channel_id)
    }

    /// Join a lobby channel (immediate access)
    pub fn join_lobby_channel(&mut self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not found"))?;

        // Verify it's a lobby channel
        match channel.channel_type {
            ChannelType::Lobby
            | ChannelType::Voice {
                channel_type: VoiceChannelType::Lobby,
            } => {
                // Add user with basic permissions
                let member_permissions = ChannelPermissions {
                    can_speak: true,
                    can_invite: false,
                    can_approve_entry: false,
                    can_kick: false,
                    can_modify_permissions: false,
                };

                channel.members.insert(
                    user_id,
                    ChannelMember {
                        user_id,
                        permissions: member_permissions,
                        joined_at: chrono::Utc::now(),
                    },
                );

                // Add to user's channel list
                self.user_channels
                    .entry(user_id)
                    .or_insert_with(HashSet::new)
                    .insert(channel_id);

                Ok(())
            }
            _ => Err(anyhow::anyhow!("Cannot directly join private channel")),
        }
    }

    /// Request entry to a private channel
    pub fn request_channel_entry(
        &mut self,
        channel_id: Uuid,
        user_id: Uuid,
        message: Option<String>,
    ) -> Result<Uuid> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not found"))?;

        // Verify it's a private channel
        match channel.channel_type {
            ChannelType::Private { .. }
            | ChannelType::Voice {
                channel_type: VoiceChannelType::Private { .. },
            } => {
                // Check if user already has access
                if channel.members.contains_key(&user_id) {
                    return Err(anyhow::anyhow!("User already has access to channel"));
                }

                // Check if request already exists
                if channel
                    .entry_requests
                    .iter()
                    .any(|req| req.user_id == user_id)
                {
                    return Err(anyhow::anyhow!("Entry request already pending"));
                }

                let request_id = Uuid::new_v4();
                let request = EntryRequest {
                    request_id,
                    user_id,
                    channel_id,
                    requested_at: chrono::Utc::now(),
                    message,
                };

                channel.entry_requests.push(request);
                Ok(request_id)
            }
            _ => Err(anyhow::anyhow!("Cannot request entry to lobby channel")),
        }
    }

    /// Approve entry request (requires approval permission)
    pub fn approve_entry_request(&mut self, request_id: Uuid, approver_id: Uuid) -> Result<()> {
        // Find the channel containing this request
        let mut channel_id = None;
        let mut user_to_add = None;

        for (cid, channel) in &mut self.channels {
            if let Some(req_index) = channel
                .entry_requests
                .iter()
                .position(|req| req.request_id == request_id)
            {
                // Check if approver has permission
                let approver_member = channel
                    .members
                    .get(&approver_id)
                    .ok_or_else(|| anyhow::anyhow!("Approver not in channel"))?;

                if !approver_member.permissions.can_approve_entry {
                    return Err(anyhow::anyhow!("No permission to approve entry"));
                }

                let request = channel.entry_requests.remove(req_index);
                user_to_add = Some(request.user_id);
                channel_id = Some(*cid);
                break;
            }
        }

        if let (Some(cid), Some(user_id)) = (channel_id, user_to_add) {
            // Add user to channel with basic permissions
            let member_permissions = ChannelPermissions {
                can_speak: true,
                can_invite: false,
                can_approve_entry: false,
                can_kick: false,
                can_modify_permissions: false,
            };

            let channel = self.channels.get_mut(&cid).unwrap();
            channel.members.insert(
                user_id,
                ChannelMember {
                    user_id,
                    permissions: member_permissions,
                    joined_at: chrono::Utc::now(),
                },
            );

            // Add to user's channel list
            self.user_channels
                .entry(user_id)
                .or_insert_with(HashSet::new)
                .insert(cid);

            Ok(())
        } else {
            Err(anyhow::anyhow!("Entry request not found"))
        }
    }

    /// Deny entry request
    pub fn deny_entry_request(&mut self, request_id: Uuid, denier_id: Uuid) -> Result<()> {
        for channel in self.channels.values_mut() {
            if let Some(req_index) = channel
                .entry_requests
                .iter()
                .position(|req| req.request_id == request_id)
            {
                // Check if denier has permission
                let denier_member = channel
                    .members
                    .get(&denier_id)
                    .ok_or_else(|| anyhow::anyhow!("Denier not in channel"))?;

                if !denier_member.permissions.can_approve_entry {
                    return Err(anyhow::anyhow!("No permission to deny entry"));
                }

                channel.entry_requests.remove(req_index);
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Entry request not found"))
    }

    /// Get visible channels for a user (excludes hidden private channels they're not in)
    pub fn get_visible_channels(&self, user_id: Uuid) -> Vec<&Channel> {
        self.channels
            .values()
            .filter(|channel| {
                match &channel.channel_type {
                    // Lobby channels are always visible
                    ChannelType::Lobby | ChannelType::Text => true,
                    ChannelType::Voice {
                        channel_type: VoiceChannelType::Lobby,
                    } => true,

                    // Private channels - only visible if user is member OR visibility is enabled
                    ChannelType::Private { visible_in_list } => {
                        *visible_in_list || channel.members.contains_key(&user_id)
                    }
                    ChannelType::Voice {
                        channel_type: VoiceChannelType::Private { visible_in_list },
                    } => *visible_in_list || channel.members.contains_key(&user_id),
                }
            })
            .collect()
    }

    /// Get entry requests for channels where user can approve
    pub fn get_pending_requests(&self, approver_id: Uuid) -> Vec<&EntryRequest> {
        let mut requests = Vec::new();

        for channel in self.channels.values() {
            if let Some(member) = channel.members.get(&approver_id) {
                if member.permissions.can_approve_entry {
                    requests.extend(channel.entry_requests.iter());
                }
            }
        }

        requests
    }

    /// Leave a channel
    pub fn leave_channel(&mut self, channel_id: Uuid, user_id: Uuid) -> Result<()> {
        let channel = self
            .channels
            .get_mut(&channel_id)
            .ok_or_else(|| anyhow::anyhow!("Channel not found"))?;

        channel.members.remove(&user_id);

        if let Some(user_channels) = self.user_channels.get_mut(&user_id) {
            user_channels.remove(&channel_id);
        }

        Ok(())
    }

    /// Get channel by ID
    pub fn get_channel(&self, channel_id: Uuid) -> Option<&Channel> {
        self.channels.get(&channel_id)
    }

    /// Check if user has specific permission in channel
    pub fn has_permission(
        &self,
        channel_id: Uuid,
        user_id: Uuid,
        permission: fn(&ChannelPermissions) -> bool,
    ) -> bool {
        if let Some(channel) = self.channels.get(&channel_id) {
            if let Some(member) = channel.members.get(&user_id) {
                return permission(&member.permissions);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lobby_channel_access() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Create lobby channel
        let channel_id = manager
            .create_channel("General".to_string(), ChannelType::Lobby, creator_id, None)
            .unwrap();

        // User can join directly
        manager.join_lobby_channel(channel_id, user_id).unwrap();

        let channel = manager.get_channel(channel_id).unwrap();
        assert!(channel.members.contains_key(&user_id));
    }

    #[test]
    fn test_private_channel_request_approval() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Create private channel
        let channel_id = manager
            .create_channel(
                "Private Room".to_string(),
                ChannelType::Private {
                    visible_in_list: true,
                },
                creator_id,
                None,
            )
            .unwrap();

        // User requests entry
        let request_id = manager
            .request_channel_entry(channel_id, user_id, Some("Please let me join!".to_string()))
            .unwrap();

        // Creator approves
        manager
            .approve_entry_request(request_id, creator_id)
            .unwrap();

        let channel = manager.get_channel(channel_id).unwrap();
        assert!(channel.members.contains_key(&user_id));
        assert!(channel.entry_requests.is_empty());
    }

    #[test]
    fn test_visible_channels_filtering() {
        let mut manager = ChannelManager::new();
        let creator_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // Create visible private channel
        let _visible_private = manager
            .create_channel(
                "Visible Private".to_string(),
                ChannelType::Private {
                    visible_in_list: true,
                },
                creator_id,
                None,
            )
            .unwrap();

        // Create hidden private channel
        let _hidden_private = manager
            .create_channel(
                "Hidden Private".to_string(),
                ChannelType::Private {
                    visible_in_list: false,
                },
                creator_id,
                None,
            )
            .unwrap();

        // Create lobby channel
        let _lobby = manager
            .create_channel("Lobby".to_string(), ChannelType::Lobby, creator_id, None)
            .unwrap();

        let visible = manager.get_visible_channels(user_id);
        // User should see: visible private + lobby, but not hidden private
        assert_eq!(visible.len(), 2);
    }
}
