//! Input validation functions for Accord server
//!
//! This module provides comprehensive input validation for user-submitted data
//! to ensure data integrity and security throughout the system.

/// Validates username format
///
/// Requirements:
/// - 3-32 characters
/// - Alphanumeric characters plus underscore and hyphen
/// - Cannot start or end with underscore or hyphen
pub fn validate_username(name: &str) -> Result<(), String> {
    if name.len() < 3 {
        return Err("Username must be at least 3 characters long".to_string());
    }

    if name.len() > 32 {
        return Err("Username must not exceed 32 characters".to_string());
    }

    // Check for valid characters (alphanumeric + underscore + hyphen)
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Username can only contain alphanumeric characters, underscores, and hyphens"
                .to_string(),
        );
    }

    // Cannot start or end with special characters
    if name.starts_with('_') || name.starts_with('-') || name.ends_with('_') || name.ends_with('-')
    {
        return Err("Username cannot start or end with underscore or hyphen".to_string());
    }

    Ok(())
}

/// Validates node name format
///
/// Requirements:
/// - 1-100 characters after trimming
/// - Must not be empty after trimming
pub fn validate_node_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();

    if trimmed.is_empty() {
        return Err("Node name cannot be empty".to_string());
    }

    if trimmed.len() > 100 {
        return Err("Node name must not exceed 100 characters".to_string());
    }

    Ok(())
}

/// Validates channel name format
///
/// Requirements:
/// - 1-100 characters
/// - Lowercase alphanumeric characters plus hyphens only
pub fn validate_channel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Channel name cannot be empty".to_string());
    }

    if name.len() > 100 {
        return Err("Channel name must not exceed 100 characters".to_string());
    }

    // Must be lowercase alphanumeric + hyphens
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(
            "Channel name can only contain lowercase alphanumeric characters and hyphens"
                .to_string(),
        );
    }

    Ok(())
}

/// Validates bio text length
///
/// Requirements:
/// - Maximum 500 characters
pub fn validate_bio(bio: &str) -> Result<(), String> {
    if bio.len() > 500 {
        return Err("Bio must not exceed 500 characters".to_string());
    }

    Ok(())
}

/// Validates display name format
///
/// Requirements:
/// - 1-50 characters
/// - Must not be empty
pub fn validate_display_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Display name cannot be empty".to_string());
    }

    if name.len() > 50 {
        return Err("Display name must not exceed 50 characters".to_string());
    }

    Ok(())
}

/// Validates message size for encrypted blob
///
/// Requirements:
/// - Maximum 65536 bytes (64KB)
pub fn validate_message_size(content: &[u8]) -> Result<(), String> {
    if content.len() > 65536 {
        return Err("Message size must not exceed 65536 bytes".to_string());
    }

    Ok(())
}

/// Validates emoji string
///
/// Requirements:
/// - 1-32 characters
/// - Must not be empty
pub fn validate_emoji(emoji: &str) -> Result<(), String> {
    if emoji.is_empty() {
        return Err("Emoji cannot be empty".to_string());
    }

    if emoji.len() > 32 {
        return Err("Emoji must not exceed 32 characters".to_string());
    }

    Ok(())
}

/// Validates invite code format
///
/// Requirements:
/// - 6-12 characters
/// - Alphanumeric characters only
pub fn validate_invite_code(code: &str) -> Result<(), String> {
    if code.len() < 6 {
        return Err("Invite code must be at least 6 characters long".to_string());
    }

    if code.len() > 12 {
        return Err("Invite code must not exceed 12 characters".to_string());
    }

    if !code.chars().all(|c| c.is_alphanumeric()) {
        return Err("Invite code can only contain alphanumeric characters".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test_user").is_ok());
        assert!(validate_username("user-name").is_ok());
        assert!(validate_username("a1b2c3d").is_ok());
        assert!(validate_username("abc").is_ok()); // minimum length
        assert!(validate_username("a".repeat(32).as_str()).is_ok()); // maximum length
    }

    #[test]
    fn test_validate_username_invalid() {
        // Too short
        assert!(validate_username("ab").is_err());
        assert!(validate_username("").is_err());

        // Too long
        assert!(validate_username(&"a".repeat(33)).is_err());

        // Invalid characters
        assert!(validate_username("user@name").is_err());
        assert!(validate_username("user.name").is_err());
        assert!(validate_username("user name").is_err());
        assert!(validate_username("user!").is_err());

        // Leading/trailing special chars
        assert!(validate_username("_username").is_err());
        assert!(validate_username("username_").is_err());
        assert!(validate_username("-username").is_err());
        assert!(validate_username("username-").is_err());
    }

    #[test]
    fn test_validate_node_name_valid() {
        assert!(validate_node_name("MyNode").is_ok());
        assert!(validate_node_name("  MyNode  ").is_ok()); // trimmed
        assert!(validate_node_name("A").is_ok()); // minimum after trim
        assert!(validate_node_name(&"a".repeat(100)).is_ok()); // maximum length
        assert!(validate_node_name("Node with spaces").is_ok());
        assert!(validate_node_name("Node!@#$%").is_ok()); // any chars allowed
    }

    #[test]
    fn test_validate_node_name_invalid() {
        // Empty or whitespace only
        assert!(validate_node_name("").is_err());
        assert!(validate_node_name("   ").is_err());

        // Too long
        assert!(validate_node_name(&"a".repeat(101)).is_err());
    }

    #[test]
    fn test_validate_channel_name_valid() {
        assert!(validate_channel_name("general").is_ok());
        assert!(validate_channel_name("random-chat").is_ok());
        assert!(validate_channel_name("channel123").is_ok());
        assert!(validate_channel_name("a").is_ok()); // minimum length
        assert!(validate_channel_name(&"a".repeat(100)).is_ok()); // maximum length
        assert!(validate_channel_name("test-channel-123").is_ok());
    }

    #[test]
    fn test_validate_channel_name_invalid() {
        // Empty
        assert!(validate_channel_name("").is_err());

        // Too long
        assert!(validate_channel_name(&"a".repeat(101)).is_err());

        // Invalid characters
        assert!(validate_channel_name("Channel").is_err()); // uppercase
        assert!(validate_channel_name("channel_name").is_err()); // underscore
        assert!(validate_channel_name("channel name").is_err()); // space
        assert!(validate_channel_name("channel!").is_err()); // special char
        assert!(validate_channel_name("channel.txt").is_err()); // dot
    }

    #[test]
    fn test_validate_bio_valid() {
        assert!(validate_bio("").is_ok()); // empty is allowed
        assert!(validate_bio("Hello, I'm a developer").is_ok());
        assert!(validate_bio(&"a".repeat(500)).is_ok()); // maximum length
        assert!(validate_bio("Bio with emojis 🚀 and symbols @#$%").is_ok());
    }

    #[test]
    fn test_validate_bio_invalid() {
        // Too long
        assert!(validate_bio(&"a".repeat(501)).is_err());
    }

    #[test]
    fn test_validate_display_name_valid() {
        assert!(validate_display_name("John Doe").is_ok());
        assert!(validate_display_name("A").is_ok()); // minimum length
        assert!(validate_display_name(&"a".repeat(50)).is_ok()); // maximum length
        assert!(validate_display_name("User123").is_ok());
        assert!(validate_display_name("🎉 Cool User 🎉").is_ok());
    }

    #[test]
    fn test_validate_display_name_invalid() {
        // Empty
        assert!(validate_display_name("").is_err());

        // Too long
        assert!(validate_display_name(&"a".repeat(51)).is_err());
    }

    #[test]
    fn test_validate_message_size_valid() {
        assert!(validate_message_size(&[]).is_ok()); // empty
        assert!(validate_message_size(&vec![0u8; 1000]).is_ok()); // small message
        assert!(validate_message_size(&vec![0u8; 65536]).is_ok()); // maximum size
    }

    #[test]
    fn test_validate_message_size_invalid() {
        // Too large
        assert!(validate_message_size(&vec![0u8; 65537]).is_err());
        assert!(validate_message_size(&vec![0u8; 100000]).is_err());
    }

    #[test]
    fn test_validate_emoji_valid() {
        assert!(validate_emoji("😀").is_ok());
        assert!(validate_emoji("👍").is_ok());
        assert!(validate_emoji("🚀").is_ok());
        assert!(validate_emoji("A").is_ok()); // minimum length
        assert!(validate_emoji(&"😀".repeat(8)).is_ok()); // multiple emojis
        assert!(validate_emoji(":smile:").is_ok()); // text emoji
    }

    #[test]
    fn test_validate_emoji_invalid() {
        // Empty
        assert!(validate_emoji("").is_err());

        // Too long
        assert!(validate_emoji(&"a".repeat(33)).is_err());
    }

    #[test]
    fn test_validate_invite_code_valid() {
        assert!(validate_invite_code("abc123").is_ok()); // minimum length
        assert!(validate_invite_code("ABC123DEF456").is_ok()); // maximum length
        assert!(validate_invite_code("INVITE01").is_ok());
        assert!(validate_invite_code("123456").is_ok()); // numbers only
        assert!(validate_invite_code("ABCDEF").is_ok()); // letters only
    }

    #[test]
    fn test_validate_invite_code_invalid() {
        // Too short
        assert!(validate_invite_code("12345").is_err());
        assert!(validate_invite_code("").is_err());

        // Too long
        assert!(validate_invite_code("1234567890123").is_err());

        // Invalid characters
        assert!(validate_invite_code("abc-123").is_err()); // hyphen
        assert!(validate_invite_code("abc_123").is_err()); // underscore
        assert!(validate_invite_code("abc 123").is_err()); // space
        assert!(validate_invite_code("abc!123").is_err()); // special char
    }
}
