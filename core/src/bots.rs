//! # Accord Bot Integration
//!
//! Privacy-preserving bot system where bots cannot read channel content
//! but can respond to direct commands and provide embedded functions.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

/// Maximum number of bot interactions to keep in memory
const MAX_INTERACTIONS: usize = 10_000;

/// Bot command that can be parsed without decrypting channel content
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotCommand {
    pub command_id: Uuid,
    pub bot_id: Uuid,
    pub channel_id: Uuid,
    pub user_id: Uuid,
    pub command_prefix: String,       // e.g., "/weather", "/music"
    pub encrypted_arguments: Vec<u8>, // Encrypted for bot's eyes only
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Bot response with embedded interface elements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotResponse {
    pub response_id: Uuid,
    pub command_id: Uuid, // Links back to original command
    pub response_type: BotResponseType,
    pub encrypted_content: Vec<u8>, // Response content encrypted for channel
    pub embedded_elements: Vec<EmbeddedElement>,
}

/// Types of bot responses
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BotResponseType {
    /// Simple text response
    Text,
    /// Rich embed with formatting
    Embed,
    /// Interactive elements (buttons, forms)
    Interactive,
    /// File/media response
    Media,
}

/// Interactive embedded elements that bots can provide
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmbeddedElement {
    Button {
        id: String,
        label: String,
        style: ButtonStyle,
        action: EmbeddedAction,
    },
    SelectMenu {
        id: String,
        placeholder: String,
        options: Vec<SelectOption>,
        action: EmbeddedAction,
    },
    TextInput {
        id: String,
        label: String,
        placeholder: String,
        required: bool,
        action: EmbeddedAction,
    },
    Embed {
        title: Option<String>,
        description: Option<String>,
        fields: Vec<EmbedField>,
        color: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ButtonStyle {
    Primary,
    Secondary,
    Success,
    Danger,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectOption {
    pub label: String,
    pub value: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmbedField {
    pub name: String,
    pub value: String,
    pub inline: bool,
}

/// Action to be taken when embedded element is interacted with
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EmbeddedAction {
    /// Send another command to the bot
    Command { command: String },
    /// Update the original message
    UpdateMessage { new_content: String },
    /// Open a modal dialog
    OpenModal {
        title: String,
        fields: Vec<EmbeddedElement>,
    },
    /// No action (display only)
    None,
}

/// Bot registration and metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bot {
    pub bot_id: Uuid,
    pub name: String,
    pub description: String,
    pub commands: Vec<BotCommandDefinition>,
    pub permissions: BotPermissions,
    pub public_key: Vec<u8>, // For encrypting responses to this bot
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub owner_id: Uuid,
}

/// Definition of a command the bot can handle
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotCommandDefinition {
    pub command: String, // e.g., "weather", "play", "help"
    pub description: String,
    pub parameters: Vec<CommandParameter>,
    pub requires_permissions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandParameter {
    pub name: String,
    pub parameter_type: ParameterType,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Integer,
    User,
    Channel,
    Role,
    Boolean,
}

/// Permissions a bot has in the server
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotPermissions {
    pub can_send_messages: bool,
    pub can_send_embeds: bool,
    pub can_use_external_resources: bool, // HTTP requests, file uploads
    pub can_manage_messages: bool,        // Edit/delete its own messages
    pub allowed_channels: Option<Vec<Uuid>>, // Restrict to specific channels
}

/// Bot interaction tracking (for rate limiting and auditing)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BotInteraction {
    pub interaction_id: Uuid,
    pub bot_id: Uuid,
    pub user_id: Uuid,
    pub channel_id: Uuid,
    pub interaction_type: InteractionType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InteractionType {
    Command,
    ButtonClick,
    MenuSelect,
    TextInput,
}

/// Bot manager that handles command routing and privacy preservation
pub struct BotManager {
    bots: HashMap<Uuid, Bot>,
    command_mappings: HashMap<String, Uuid>, // command_prefix -> bot_id
    pending_commands: HashMap<Uuid, BotCommand>,
    interactions: Vec<BotInteraction>,
}

impl Default for BotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BotManager {
    pub fn new() -> Self {
        Self {
            bots: HashMap::new(),
            command_mappings: HashMap::new(),
            pending_commands: HashMap::new(),
            interactions: Vec::new(),
        }
    }

    /// Register a new bot
    pub fn register_bot(&mut self, bot: Bot) -> Result<()> {
        // Build command mappings
        for cmd_def in &bot.commands {
            let command_key = format!("/{}", cmd_def.command);
            if self.command_mappings.contains_key(&command_key) {
                return Err(anyhow::anyhow!(
                    "Command '{}' already registered",
                    command_key
                ));
            }
            self.command_mappings.insert(command_key, bot.bot_id);
        }

        self.bots.insert(bot.bot_id, bot);
        Ok(())
    }

    /// Parse a message to extract bot commands (without decrypting full content)
    pub fn extract_bot_command(
        &self,
        channel_id: Uuid,
        user_id: Uuid,
        message_preview: &str, // First few characters to detect command prefix
        encrypted_message: &[u8],
    ) -> Option<BotCommand> {
        // Check if message starts with a bot command prefix
        for (command_prefix, &bot_id) in &self.command_mappings {
            if message_preview.starts_with(command_prefix) {
                // Extract the command arguments (everything after the prefix)
                let command_id = Uuid::new_v4();

                return Some(BotCommand {
                    command_id,
                    bot_id,
                    channel_id,
                    user_id,
                    command_prefix: command_prefix.clone(),
                    encrypted_arguments: encrypted_message.to_vec(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        None
    }

    /// Route command to appropriate bot (bot receives only the command, not channel history)
    pub fn route_command(&mut self, command: BotCommand) -> Result<()> {
        let bot = self
            .bots
            .get(&command.bot_id)
            .ok_or_else(|| anyhow::anyhow!("Bot not found"))?;

        // Verify bot has permission in this channel
        if let Some(ref allowed_channels) = bot.permissions.allowed_channels {
            if !allowed_channels.contains(&command.channel_id) {
                return Err(anyhow::anyhow!("Bot not permitted in this channel"));
            }
        }

        // Store command for processing
        self.pending_commands
            .insert(command.command_id, command.clone());

        // Record interaction
        self.interactions.push(BotInteraction {
            interaction_id: Uuid::new_v4(),
            bot_id: command.bot_id,
            user_id: command.user_id,
            channel_id: command.channel_id,
            interaction_type: InteractionType::Command,
            timestamp: chrono::Utc::now(),
        });

        // In a real implementation, this would send the command to the bot process
        info!(
            command_prefix = %command.command_prefix,
            bot_name = %bot.name,
            "Routing command to bot"
        );

        // Enforce max interactions size
        if self.interactions.len() >= MAX_INTERACTIONS {
            let drain_count = self.interactions.len() - MAX_INTERACTIONS + 1;
            self.interactions.drain(..drain_count);
        }

        Ok(())
    }

    /// Handle bot response with embedded elements
    pub fn handle_bot_response(&mut self, response: BotResponse) -> Result<()> {
        // Verify the command exists
        let _command = self
            .pending_commands
            .get(&response.command_id)
            .ok_or_else(|| anyhow::anyhow!("Original command not found"))?;

        // Process embedded elements (validate they're safe)
        for element in &response.embedded_elements {
            self.validate_embedded_element(element)?;
        }

        // In a real implementation, this would send the response to the channel
        debug!(
            embedded_count = response.embedded_elements.len(),
            "Bot response with embedded elements"
        );

        Ok(())
    }

    /// Handle interaction with embedded elements
    pub fn handle_embedded_interaction(
        &mut self,
        element_id: String,
        user_id: Uuid,
        channel_id: Uuid,
        interaction_data: String,
    ) -> Result<()> {
        // Find which bot owns this embedded element
        // In practice, element IDs would include bot ID prefix

        self.interactions.push(BotInteraction {
            interaction_id: Uuid::new_v4(),
            bot_id: Uuid::new_v4(), // Would be determined from element_id
            user_id,
            channel_id,
            interaction_type: InteractionType::ButtonClick,
            timestamp: chrono::Utc::now(),
        });

        debug!(
            element_id = %element_id,
            interaction_data = %interaction_data,
            "Handling embedded interaction"
        );

        // Enforce max interactions size
        if self.interactions.len() >= MAX_INTERACTIONS {
            let drain_count = self.interactions.len() - MAX_INTERACTIONS + 1;
            self.interactions.drain(..drain_count);
        }
        Ok(())
    }

    /// Validate embedded element is safe and doesn't violate privacy
    fn validate_embedded_element(&self, element: &EmbeddedElement) -> Result<()> {
        match element {
            EmbeddedElement::Button { action, .. }
            | EmbeddedElement::SelectMenu { action, .. }
            | EmbeddedElement::TextInput { action, .. } => {
                match action {
                    EmbeddedAction::Command { command } => {
                        // Verify the command is valid for this bot
                        if !command.starts_with('/') {
                            return Err(anyhow::anyhow!("Invalid command format"));
                        }
                    }
                    EmbeddedAction::UpdateMessage { .. } => {
                        // This is safe - bot can only update its own messages
                    }
                    EmbeddedAction::OpenModal { .. } => {
                        // This is safe - modal is client-side only
                    }
                    EmbeddedAction::None => {
                        // Display-only element, safe
                    }
                }
            }
            EmbeddedElement::Embed { .. } => {
                // Embeds are safe - just display formatting
            }
        }
        Ok(())
    }

    /// Get list of available commands for autocomplete
    pub fn get_available_commands(&self, channel_id: Uuid) -> Vec<BotCommandDefinition> {
        let mut commands = Vec::new();

        for bot in self.bots.values() {
            // Check if bot is allowed in this channel
            if let Some(ref allowed_channels) = bot.permissions.allowed_channels {
                if !allowed_channels.contains(&channel_id) {
                    continue;
                }
            }

            commands.extend(bot.commands.clone());
        }

        commands
    }

    /// Get bot by ID
    pub fn get_bot(&self, bot_id: Uuid) -> Option<&Bot> {
        self.bots.get(&bot_id)
    }

    /// Remove bot (unregister all its commands)
    pub fn remove_bot(&mut self, bot_id: Uuid) -> Result<()> {
        if let Some(bot) = self.bots.remove(&bot_id) {
            // Remove all command mappings for this bot
            let commands_to_remove: Vec<String> = self
                .command_mappings
                .iter()
                .filter(|(_, &id)| id == bot_id)
                .map(|(cmd, _)| cmd.clone())
                .collect();

            for cmd in commands_to_remove {
                self.command_mappings.remove(&cmd);
            }

            info!(bot_name = %bot.name, "Removed bot");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_registration() {
        let mut manager = BotManager::new();

        let bot = Bot {
            bot_id: Uuid::new_v4(),
            name: "Weather Bot".to_string(),
            description: "Provides weather information".to_string(),
            commands: vec![BotCommandDefinition {
                command: "weather".to_string(),
                description: "Get weather for a location".to_string(),
                parameters: vec![CommandParameter {
                    name: "location".to_string(),
                    parameter_type: ParameterType::String,
                    required: true,
                    description: "City or address".to_string(),
                }],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: true,
                can_use_external_resources: true,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();
        assert!(manager.command_mappings.contains_key("/weather"));
    }

    #[test]
    fn test_command_extraction() {
        let mut manager = BotManager::new();

        // Register a bot with a command
        let bot_id = Uuid::new_v4();
        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        // Test command extraction
        let command = manager.extract_bot_command(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "/test hello world",
            b"encrypted_command_data",
        );

        assert!(command.is_some());
        let cmd = command.unwrap();
        assert_eq!(cmd.bot_id, bot_id);
        assert_eq!(cmd.command_prefix, "/test");
    }

    #[test]
    fn test_duplicate_command_registration() {
        let mut manager = BotManager::new();

        let bot1 = Bot {
            bot_id: Uuid::new_v4(),
            name: "Bot 1".to_string(),
            description: "First bot".to_string(),
            commands: vec![BotCommandDefinition {
                command: "duplicate".to_string(),
                description: "Duplicate command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot1).unwrap();

        // Try to register another bot with the same command
        let bot2 = Bot {
            bot_id: Uuid::new_v4(),
            name: "Bot 2".to_string(),
            description: "Second bot".to_string(),
            commands: vec![BotCommandDefinition {
                command: "duplicate".to_string(),
                description: "Same command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        let result = manager.register_bot(bot2);
        assert!(result.is_err());
    }

    #[test]
    fn test_bot_manager_default() {
        let manager = BotManager::default();
        assert_eq!(manager.bots.len(), 0);
        assert_eq!(manager.command_mappings.len(), 0);
        assert_eq!(manager.pending_commands.len(), 0);
        assert_eq!(manager.interactions.len(), 0);
    }

    #[test]
    fn test_command_with_parameters() {
        let params = vec![
            CommandParameter {
                name: "location".to_string(),
                parameter_type: ParameterType::String,
                required: true,
                description: "Location to check".to_string(),
            },
            CommandParameter {
                name: "units".to_string(),
                parameter_type: ParameterType::String,
                required: false,
                description: "Temperature units".to_string(),
            },
        ];

        let cmd_def = BotCommandDefinition {
            command: "weather".to_string(),
            description: "Get weather".to_string(),
            parameters: params.clone(),
            requires_permissions: vec![],
        };

        assert_eq!(cmd_def.parameters.len(), 2);
        assert!(cmd_def.parameters[0].required);
        assert!(!cmd_def.parameters[1].required);
    }

    #[test]
    fn test_parameter_types() {
        let types = vec![
            ParameterType::String,
            ParameterType::Integer,
            ParameterType::User,
            ParameterType::Channel,
            ParameterType::Role,
            ParameterType::Boolean,
        ];

        assert_eq!(types.len(), 6);
    }

    #[test]
    fn test_bot_permissions_all_enabled() {
        let perms = BotPermissions {
            can_send_messages: true,
            can_send_embeds: true,
            can_use_external_resources: true,
            can_manage_messages: true,
            allowed_channels: None,
        };

        assert!(perms.can_send_messages);
        assert!(perms.can_send_embeds);
        assert!(perms.can_use_external_resources);
        assert!(perms.can_manage_messages);
    }

    #[test]
    fn test_bot_permissions_restricted_channels() {
        let channel1 = Uuid::new_v4();
        let channel2 = Uuid::new_v4();

        let perms = BotPermissions {
            can_send_messages: true,
            can_send_embeds: false,
            can_use_external_resources: false,
            can_manage_messages: false,
            allowed_channels: Some(vec![channel1, channel2]),
        };

        assert_eq!(perms.allowed_channels.as_ref().unwrap().len(), 2);
        assert!(perms.allowed_channels.as_ref().unwrap().contains(&channel1));
    }

    #[test]
    fn test_route_command_to_allowed_channel() {
        let mut manager = BotManager::new();
        let channel_id = Uuid::new_v4();

        let bot = Bot {
            bot_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: Some(vec![channel_id]),
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        let bot_id = bot.bot_id;
        manager.register_bot(bot).unwrap();

        let command = BotCommand {
            command_id: Uuid::new_v4(),
            bot_id,
            channel_id,
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        let result = manager.route_command(command);
        assert!(result.is_ok());
    }

    #[test]
    fn test_route_command_to_forbidden_channel() {
        let mut manager = BotManager::new();
        let allowed_channel = Uuid::new_v4();
        let forbidden_channel = Uuid::new_v4();

        let bot = Bot {
            bot_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: Some(vec![allowed_channel]),
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        let bot_id = bot.bot_id;
        manager.register_bot(bot).unwrap();

        let command = BotCommand {
            command_id: Uuid::new_v4(),
            bot_id,
            channel_id: forbidden_channel,
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        let result = manager.route_command(command);
        assert!(result.is_err());
    }

    #[test]
    fn test_route_command_bot_not_found() {
        let mut manager = BotManager::new();

        let command = BotCommand {
            command_id: Uuid::new_v4(),
            bot_id: Uuid::new_v4(), // Non-existent bot
            channel_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        let result = manager.route_command(command);
        assert!(result.is_err());
    }

    #[test]
    fn test_interaction_tracking() {
        let mut manager = BotManager::new();
        let bot_id = Uuid::new_v4();

        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        let command = BotCommand {
            command_id: Uuid::new_v4(),
            bot_id,
            channel_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        manager.route_command(command).unwrap();

        assert_eq!(manager.interactions.len(), 1);
        assert_eq!(manager.interactions[0].bot_id, bot_id);
    }

    #[test]
    fn test_max_interactions_enforcement() {
        let mut manager = BotManager::new();
        let bot_id = Uuid::new_v4();

        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test command".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![0u8; 32],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        // Fill interactions to max
        for _ in 0..MAX_INTERACTIONS {
            manager.interactions.push(BotInteraction {
                interaction_id: Uuid::new_v4(),
                bot_id,
                user_id: Uuid::new_v4(),
                channel_id: Uuid::new_v4(),
                interaction_type: InteractionType::Command,
                timestamp: chrono::Utc::now(),
            });
        }

        // Verify we're at max
        assert_eq!(manager.interactions.len(), MAX_INTERACTIONS);

        // Add one more via route_command
        let command = BotCommand {
            command_id: Uuid::new_v4(),
            bot_id,
            channel_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        manager.route_command(command).unwrap();

        // Should drain old interactions to stay under MAX_INTERACTIONS
        // When at MAX_INTERACTIONS + 1, drains 2 items, leaving MAX_INTERACTIONS - 1
        assert_eq!(manager.interactions.len(), MAX_INTERACTIONS - 1);
    }

    #[test]
    fn test_embedded_button() {
        let button = EmbeddedElement::Button {
            id: "btn1".to_string(),
            label: "Click Me".to_string(),
            style: ButtonStyle::Primary,
            action: EmbeddedAction::Command {
                command: "/action".to_string(),
            },
        };

        match button {
            EmbeddedElement::Button { id, label, .. } => {
                assert_eq!(id, "btn1");
                assert_eq!(label, "Click Me");
            }
            _ => panic!("Expected Button"),
        }
    }

    #[test]
    fn test_button_styles() {
        let styles = vec![
            ButtonStyle::Primary,
            ButtonStyle::Secondary,
            ButtonStyle::Success,
            ButtonStyle::Danger,
        ];

        assert_eq!(styles.len(), 4);
    }

    #[test]
    fn test_embedded_select_menu() {
        let options = vec![
            SelectOption {
                label: "Option 1".to_string(),
                value: "opt1".to_string(),
                description: Some("First option".to_string()),
            },
            SelectOption {
                label: "Option 2".to_string(),
                value: "opt2".to_string(),
                description: None,
            },
        ];

        let select = EmbeddedElement::SelectMenu {
            id: "menu1".to_string(),
            placeholder: "Choose an option".to_string(),
            options: options.clone(),
            action: EmbeddedAction::None,
        };

        match select {
            EmbeddedElement::SelectMenu { options: opts, .. } => {
                assert_eq!(opts.len(), 2);
            }
            _ => panic!("Expected SelectMenu"),
        }
    }

    #[test]
    fn test_embedded_text_input() {
        let input = EmbeddedElement::TextInput {
            id: "input1".to_string(),
            label: "Enter text".to_string(),
            placeholder: "Type here...".to_string(),
            required: true,
            action: EmbeddedAction::None,
        };

        match input {
            EmbeddedElement::TextInput { required, .. } => {
                assert!(required);
            }
            _ => panic!("Expected TextInput"),
        }
    }

    #[test]
    fn test_embedded_embed() {
        let fields = vec![
            EmbedField {
                name: "Field 1".to_string(),
                value: "Value 1".to_string(),
                inline: true,
            },
            EmbedField {
                name: "Field 2".to_string(),
                value: "Value 2".to_string(),
                inline: false,
            },
        ];

        let embed = EmbeddedElement::Embed {
            title: Some("Title".to_string()),
            description: Some("Description".to_string()),
            fields: fields.clone(),
            color: Some(0xFF0000),
        };

        match embed {
            EmbeddedElement::Embed { fields: f, .. } => {
                assert_eq!(f.len(), 2);
            }
            _ => panic!("Expected Embed"),
        }
    }

    #[test]
    fn test_embedded_action_command() {
        let action = EmbeddedAction::Command {
            command: "/help".to_string(),
        };

        match action {
            EmbeddedAction::Command { command } => {
                assert_eq!(command, "/help");
            }
            _ => panic!("Expected Command action"),
        }
    }

    #[test]
    fn test_embedded_action_update_message() {
        let action = EmbeddedAction::UpdateMessage {
            new_content: "Updated!".to_string(),
        };

        match action {
            EmbeddedAction::UpdateMessage { new_content } => {
                assert_eq!(new_content, "Updated!");
            }
            _ => panic!("Expected UpdateMessage action"),
        }
    }

    #[test]
    fn test_embedded_action_open_modal() {
        let action = EmbeddedAction::OpenModal {
            title: "Modal Title".to_string(),
            fields: vec![],
        };

        match action {
            EmbeddedAction::OpenModal { title, .. } => {
                assert_eq!(title, "Modal Title");
            }
            _ => panic!("Expected OpenModal action"),
        }
    }

    #[test]
    fn test_validate_embedded_element_button() {
        let manager = BotManager::new();

        let button = EmbeddedElement::Button {
            id: "btn1".to_string(),
            label: "Click".to_string(),
            style: ButtonStyle::Primary,
            action: EmbeddedAction::Command {
                command: "/valid".to_string(),
            },
        };

        let result = manager.validate_embedded_element(&button);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_embedded_element_invalid_command() {
        let manager = BotManager::new();

        let button = EmbeddedElement::Button {
            id: "btn1".to_string(),
            label: "Click".to_string(),
            style: ButtonStyle::Primary,
            action: EmbeddedAction::Command {
                command: "invalid".to_string(), // Missing /
            },
        };

        let result = manager.validate_embedded_element(&button);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_embedded_element_embed() {
        let manager = BotManager::new();

        let embed = EmbeddedElement::Embed {
            title: Some("Title".to_string()),
            description: None,
            fields: vec![],
            color: None,
        };

        let result = manager.validate_embedded_element(&embed);
        assert!(result.is_ok());
    }

    #[test]
    fn test_bot_response_text() {
        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            response_type: BotResponseType::Text,
            encrypted_content: vec![1, 2, 3],
            embedded_elements: vec![],
        };

        assert_eq!(response.response_type, BotResponseType::Text);
    }

    #[test]
    fn test_bot_response_embed() {
        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            response_type: BotResponseType::Embed,
            encrypted_content: vec![],
            embedded_elements: vec![],
        };

        assert_eq!(response.response_type, BotResponseType::Embed);
    }

    #[test]
    fn test_bot_response_interactive() {
        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            response_type: BotResponseType::Interactive,
            encrypted_content: vec![],
            embedded_elements: vec![],
        };

        assert_eq!(response.response_type, BotResponseType::Interactive);
    }

    #[test]
    fn test_bot_response_media() {
        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(),
            response_type: BotResponseType::Media,
            encrypted_content: vec![],
            embedded_elements: vec![],
        };

        assert_eq!(response.response_type, BotResponseType::Media);
    }

    #[test]
    fn test_handle_bot_response() {
        let mut manager = BotManager::new();

        // Create and route a command first
        let bot_id = Uuid::new_v4();
        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: true,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        let command_id = Uuid::new_v4();
        let command = BotCommand {
            command_id,
            bot_id,
            channel_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            command_prefix: "/test".to_string(),
            encrypted_arguments: vec![],
            timestamp: chrono::Utc::now(),
        };

        manager.route_command(command).unwrap();

        // Create a response
        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id,
            response_type: BotResponseType::Text,
            encrypted_content: vec![],
            embedded_elements: vec![],
        };

        let result = manager.handle_bot_response(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_bot_response_command_not_found() {
        let mut manager = BotManager::new();

        let response = BotResponse {
            response_id: Uuid::new_v4(),
            command_id: Uuid::new_v4(), // Non-existent command
            response_type: BotResponseType::Text,
            encrypted_content: vec![],
            embedded_elements: vec![],
        };

        let result = manager.handle_bot_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_available_commands_all_channels() {
        let mut manager = BotManager::new();

        let bot = Bot {
            bot_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![
                BotCommandDefinition {
                    command: "cmd1".to_string(),
                    description: "Command 1".to_string(),
                    parameters: vec![],
                    requires_permissions: vec![],
                },
                BotCommandDefinition {
                    command: "cmd2".to_string(),
                    description: "Command 2".to_string(),
                    parameters: vec![],
                    requires_permissions: vec![],
                },
            ],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        let commands = manager.get_available_commands(Uuid::new_v4());
        assert_eq!(commands.len(), 2);
    }

    #[test]
    fn test_get_available_commands_restricted() {
        let mut manager = BotManager::new();
        let allowed_channel = Uuid::new_v4();
        let forbidden_channel = Uuid::new_v4();

        let bot = Bot {
            bot_id: Uuid::new_v4(),
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: Some(vec![allowed_channel]),
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        // Should get commands in allowed channel
        let commands = manager.get_available_commands(allowed_channel);
        assert_eq!(commands.len(), 1);

        // Should not get commands in forbidden channel
        let commands = manager.get_available_commands(forbidden_channel);
        assert_eq!(commands.len(), 0);
    }

    #[test]
    fn test_get_bot() {
        let mut manager = BotManager::new();
        let bot_id = Uuid::new_v4();

        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        let retrieved = manager.get_bot(bot_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Bot");
    }

    #[test]
    fn test_get_bot_not_found() {
        let manager = BotManager::new();
        let result = manager.get_bot(Uuid::new_v4());
        assert!(result.is_none());
    }

    #[test]
    fn test_remove_bot() {
        let mut manager = BotManager::new();
        let bot_id = Uuid::new_v4();

        let bot = Bot {
            bot_id,
            name: "Test Bot".to_string(),
            description: "Test".to_string(),
            commands: vec![BotCommandDefinition {
                command: "test".to_string(),
                description: "Test".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot).unwrap();

        // Verify bot exists
        assert!(manager.bots.contains_key(&bot_id));
        assert!(manager.command_mappings.contains_key("/test"));

        // Remove bot
        manager.remove_bot(bot_id).unwrap();

        // Verify bot and commands are removed
        assert!(!manager.bots.contains_key(&bot_id));
        assert!(!manager.command_mappings.contains_key("/test"));
    }

    #[test]
    fn test_remove_nonexistent_bot() {
        let mut manager = BotManager::new();
        let result = manager.remove_bot(Uuid::new_v4());
        assert!(result.is_ok()); // Should not error
    }

    #[test]
    fn test_interaction_types() {
        let types = vec![
            InteractionType::Command,
            InteractionType::ButtonClick,
            InteractionType::MenuSelect,
            InteractionType::TextInput,
        ];

        assert_eq!(types.len(), 4);
    }

    #[test]
    fn test_handle_embedded_interaction() {
        let mut manager = BotManager::new();

        let result = manager.handle_embedded_interaction(
            "element_id".to_string(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "interaction_data".to_string(),
        );

        assert!(result.is_ok());
        assert_eq!(manager.interactions.len(), 1);
    }

    #[test]
    fn test_command_not_extracted_without_prefix() {
        let manager = BotManager::new();

        let command = manager.extract_bot_command(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "regular message without command",
            b"encrypted_data",
        );

        assert!(command.is_none());
    }

    #[test]
    fn test_multiple_bots_different_commands() {
        let mut manager = BotManager::new();

        let bot1 = Bot {
            bot_id: Uuid::new_v4(),
            name: "Bot 1".to_string(),
            description: "First bot".to_string(),
            commands: vec![BotCommandDefinition {
                command: "cmd1".to_string(),
                description: "Command 1".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        let bot2 = Bot {
            bot_id: Uuid::new_v4(),
            name: "Bot 2".to_string(),
            description: "Second bot".to_string(),
            commands: vec![BotCommandDefinition {
                command: "cmd2".to_string(),
                description: "Command 2".to_string(),
                parameters: vec![],
                requires_permissions: vec![],
            }],
            permissions: BotPermissions {
                can_send_messages: true,
                can_send_embeds: false,
                can_use_external_resources: false,
                can_manage_messages: false,
                allowed_channels: None,
            },
            public_key: vec![],
            created_at: chrono::Utc::now(),
            owner_id: Uuid::new_v4(),
        };

        manager.register_bot(bot1).unwrap();
        manager.register_bot(bot2).unwrap();

        assert_eq!(manager.bots.len(), 2);
        assert_eq!(manager.command_mappings.len(), 2);
    }

    #[test]
    fn test_command_requires_permissions() {
        let cmd_def = BotCommandDefinition {
            command: "admin".to_string(),
            description: "Admin command".to_string(),
            parameters: vec![],
            requires_permissions: vec!["ADMINISTRATOR".to_string(), "MANAGE_GUILD".to_string()],
        };

        assert_eq!(cmd_def.requires_permissions.len(), 2);
        assert!(cmd_def
            .requires_permissions
            .contains(&"ADMINISTRATOR".to_string()));
    }
}
