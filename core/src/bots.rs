//! # Accord Bot Integration
//!
//! Privacy-preserving bot system where bots cannot read channel content
//! but can respond to direct commands and provide embedded functions.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

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
        println!(
            "Routing command {} to bot {}",
            command.command_prefix, bot.name
        );

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
        println!(
            "Bot response with {} embedded elements",
            response.embedded_elements.len()
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

        println!(
            "Handling embedded interaction: {} = {}",
            element_id, interaction_data
        );
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

            println!("Removed bot: {}", bot.name);
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
}
