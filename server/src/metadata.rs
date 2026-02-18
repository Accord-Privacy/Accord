//! Metadata stripping for minimal metadata mode.
//!
//! When the relay runs in `Minimal` mode, these functions sanitize data before
//! database writes so the relay only persists what is needed for routing.

use crate::state::MetadataMode;

/// Placeholder used for required plaintext name columns in minimal mode.
/// Clients must use encrypted_name fields instead.
const MINIMAL_PLACEHOLDER: &str = "[redacted]";

/// Strip a node name for storage. In minimal mode returns a placeholder;
/// the encrypted_name blob (stored separately) is the authoritative source.
pub fn strip_node_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip an optional description. In minimal mode always returns `None`.
pub fn strip_description(mode: MetadataMode, description: Option<&str>) -> Option<String> {
    match mode {
        MetadataMode::Standard => description.map(|s| s.to_string()),
        MetadataMode::Minimal => None,
    }
}

/// Strip a channel name for storage. Same logic as node names.
pub fn strip_channel_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip a category name for storage.
pub fn strip_category_name(mode: MetadataMode, name: &str) -> String {
    match mode {
        MetadataMode::Standard => name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip a user profile display name for storage.
pub fn strip_display_name(mode: MetadataMode, display_name: &str) -> String {
    match mode {
        MetadataMode::Standard => display_name.to_string(),
        MetadataMode::Minimal => MINIMAL_PLACEHOLDER.to_string(),
    }
}

/// Strip optional profile text fields (bio, custom_status).
/// In minimal mode these are always `None`.
pub fn strip_optional_text(mode: MetadataMode, text: Option<&str>) -> Option<String> {
    match mode {
        MetadataMode::Standard => text.map(|s| s.to_string()),
        MetadataMode::Minimal => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_mode_passthrough() {
        assert_eq!(
            strip_node_name(MetadataMode::Standard, "My Node"),
            "My Node"
        );
        assert_eq!(
            strip_description(MetadataMode::Standard, Some("desc")),
            Some("desc".to_string())
        );
        assert_eq!(
            strip_channel_name(MetadataMode::Standard, "general"),
            "general"
        );
        assert_eq!(strip_display_name(MetadataMode::Standard, "Alice"), "Alice");
        assert_eq!(
            strip_optional_text(MetadataMode::Standard, Some("bio")),
            Some("bio".to_string())
        );
    }

    #[test]
    fn minimal_mode_strips() {
        assert_eq!(
            strip_node_name(MetadataMode::Minimal, "My Node"),
            "[redacted]"
        );
        assert_eq!(strip_description(MetadataMode::Minimal, Some("desc")), None);
        assert_eq!(
            strip_channel_name(MetadataMode::Minimal, "general"),
            "[redacted]"
        );
        assert_eq!(
            strip_display_name(MetadataMode::Minimal, "Alice"),
            "[redacted]"
        );
        assert_eq!(
            strip_optional_text(MetadataMode::Minimal, Some("bio")),
            None
        );
    }
}
