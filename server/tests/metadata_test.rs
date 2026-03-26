//! External integration tests for the metadata module
//!
//! Covers strip_node_name, strip_description, strip_channel_name,
//! strip_category_name, strip_display_name, and strip_optional_text
//! for both Standard and Minimal MetadataMode.

#![allow(clippy::all)]

use accord_server::metadata::{
    strip_category_name, strip_channel_name, strip_description, strip_display_name,
    strip_node_name, strip_optional_text,
};
use accord_server::state::MetadataMode;

const REDACTED: &str = "[redacted]";

// ============================================================================
// Group 1 — Standard mode passes everything through unchanged
// ============================================================================

#[test]
fn standard_strip_node_name_passthrough() {
    assert_eq!(
        strip_node_name(MetadataMode::Standard, "My Server"),
        "My Server"
    );
}

#[test]
fn standard_strip_node_name_empty_string() {
    assert_eq!(strip_node_name(MetadataMode::Standard, ""), "");
}

#[test]
fn standard_strip_node_name_unicode() {
    assert_eq!(
        strip_node_name(MetadataMode::Standard, "日本語サーバー 🎉"),
        "日本語サーバー 🎉"
    );
}

#[test]
fn standard_strip_description_some_passthrough() {
    assert_eq!(
        strip_description(MetadataMode::Standard, Some("A great community")),
        Some("A great community".to_string())
    );
}

#[test]
fn standard_strip_description_none_stays_none() {
    assert_eq!(strip_description(MetadataMode::Standard, None), None);
}

#[test]
fn standard_strip_description_empty_string() {
    assert_eq!(
        strip_description(MetadataMode::Standard, Some("")),
        Some("".to_string())
    );
}

#[test]
fn standard_strip_channel_name_passthrough() {
    assert_eq!(
        strip_channel_name(MetadataMode::Standard, "general"),
        "general"
    );
}

#[test]
fn standard_strip_channel_name_empty_string() {
    assert_eq!(strip_channel_name(MetadataMode::Standard, ""), "");
}

#[test]
fn standard_strip_channel_name_unicode() {
    assert_eq!(
        strip_channel_name(MetadataMode::Standard, "💬 announcements"),
        "💬 announcements"
    );
}

#[test]
fn standard_strip_category_name_passthrough() {
    assert_eq!(
        strip_category_name(MetadataMode::Standard, "Text Channels"),
        "Text Channels"
    );
}

#[test]
fn standard_strip_category_name_empty_string() {
    assert_eq!(strip_category_name(MetadataMode::Standard, ""), "");
}

#[test]
fn standard_strip_category_name_unicode() {
    assert_eq!(
        strip_category_name(MetadataMode::Standard, "Категория"),
        "Категория"
    );
}

#[test]
fn standard_strip_display_name_passthrough() {
    assert_eq!(strip_display_name(MetadataMode::Standard, "Alice"), "Alice");
}

#[test]
fn standard_strip_display_name_empty_string() {
    assert_eq!(strip_display_name(MetadataMode::Standard, ""), "");
}

#[test]
fn standard_strip_display_name_unicode() {
    assert_eq!(
        strip_display_name(MetadataMode::Standard, "ユーザー名"),
        "ユーザー名"
    );
}

#[test]
fn standard_strip_optional_text_some_passthrough() {
    assert_eq!(
        strip_optional_text(MetadataMode::Standard, Some("My bio")),
        Some("My bio".to_string())
    );
}

#[test]
fn standard_strip_optional_text_none_stays_none() {
    assert_eq!(strip_optional_text(MetadataMode::Standard, None), None);
}

#[test]
fn standard_strip_optional_text_empty_string() {
    assert_eq!(
        strip_optional_text(MetadataMode::Standard, Some("")),
        Some("".to_string())
    );
}

// ============================================================================
// Group 2 — Minimal mode strips / redacts all name fields
// ============================================================================

#[test]
fn minimal_strip_node_name_returns_redacted() {
    assert_eq!(
        strip_node_name(MetadataMode::Minimal, "My Server"),
        REDACTED
    );
}

#[test]
fn minimal_strip_node_name_empty_input_still_redacted() {
    assert_eq!(strip_node_name(MetadataMode::Minimal, ""), REDACTED);
}

#[test]
fn minimal_strip_node_name_unicode_input_still_redacted() {
    assert_eq!(
        strip_node_name(MetadataMode::Minimal, "日本語サーバー 🎉"),
        REDACTED
    );
}

#[test]
fn minimal_strip_description_some_returns_none() {
    assert_eq!(
        strip_description(MetadataMode::Minimal, Some("A great community")),
        None
    );
}

#[test]
fn minimal_strip_description_none_stays_none() {
    assert_eq!(strip_description(MetadataMode::Minimal, None), None);
}

#[test]
fn minimal_strip_description_empty_string_returns_none() {
    assert_eq!(strip_description(MetadataMode::Minimal, Some("")), None);
}

#[test]
fn minimal_strip_channel_name_returns_redacted() {
    assert_eq!(
        strip_channel_name(MetadataMode::Minimal, "general"),
        REDACTED
    );
}

#[test]
fn minimal_strip_channel_name_empty_input_still_redacted() {
    assert_eq!(strip_channel_name(MetadataMode::Minimal, ""), REDACTED);
}

#[test]
fn minimal_strip_channel_name_unicode_input_still_redacted() {
    assert_eq!(
        strip_channel_name(MetadataMode::Minimal, "💬 announcements"),
        REDACTED
    );
}

#[test]
fn minimal_strip_category_name_returns_redacted() {
    assert_eq!(
        strip_category_name(MetadataMode::Minimal, "Text Channels"),
        REDACTED
    );
}

#[test]
fn minimal_strip_category_name_empty_input_still_redacted() {
    assert_eq!(strip_category_name(MetadataMode::Minimal, ""), REDACTED);
}

#[test]
fn minimal_strip_category_name_unicode_input_still_redacted() {
    assert_eq!(
        strip_category_name(MetadataMode::Minimal, "Категория"),
        REDACTED
    );
}

#[test]
fn minimal_strip_display_name_returns_redacted() {
    assert_eq!(strip_display_name(MetadataMode::Minimal, "Alice"), REDACTED);
}

#[test]
fn minimal_strip_display_name_empty_input_still_redacted() {
    assert_eq!(strip_display_name(MetadataMode::Minimal, ""), REDACTED);
}

#[test]
fn minimal_strip_display_name_unicode_input_still_redacted() {
    assert_eq!(
        strip_display_name(MetadataMode::Minimal, "ユーザー名"),
        REDACTED
    );
}

#[test]
fn minimal_strip_optional_text_some_returns_none() {
    assert_eq!(
        strip_optional_text(MetadataMode::Minimal, Some("My bio")),
        None
    );
}

#[test]
fn minimal_strip_optional_text_none_stays_none() {
    assert_eq!(strip_optional_text(MetadataMode::Minimal, None), None);
}

#[test]
fn minimal_strip_optional_text_empty_string_returns_none() {
    assert_eq!(strip_optional_text(MetadataMode::Minimal, Some("")), None);
}

// ============================================================================
// Group 3 — Mode boundary: same input, different modes produce different output
// ============================================================================

#[test]
fn node_name_differs_between_modes() {
    let name = "Accord HQ";
    let standard = strip_node_name(MetadataMode::Standard, name);
    let minimal = strip_node_name(MetadataMode::Minimal, name);
    assert_ne!(standard, minimal);
    assert_eq!(standard, name);
    assert_eq!(minimal, REDACTED);
}

#[test]
fn description_differs_between_modes() {
    let desc = Some("Our community node");
    let standard = strip_description(MetadataMode::Standard, desc);
    let minimal = strip_description(MetadataMode::Minimal, desc);
    assert!(standard.is_some());
    assert!(minimal.is_none());
}

#[test]
fn channel_name_differs_between_modes() {
    let name = "off-topic";
    let standard = strip_channel_name(MetadataMode::Standard, name);
    let minimal = strip_channel_name(MetadataMode::Minimal, name);
    assert_ne!(standard, minimal);
    assert_eq!(standard, name);
    assert_eq!(minimal, REDACTED);
}

#[test]
fn category_name_differs_between_modes() {
    let name = "Voice Channels";
    let standard = strip_category_name(MetadataMode::Standard, name);
    let minimal = strip_category_name(MetadataMode::Minimal, name);
    assert_ne!(standard, minimal);
    assert_eq!(standard, name);
    assert_eq!(minimal, REDACTED);
}

#[test]
fn display_name_differs_between_modes() {
    let name = "Bob";
    let standard = strip_display_name(MetadataMode::Standard, name);
    let minimal = strip_display_name(MetadataMode::Minimal, name);
    assert_ne!(standard, minimal);
    assert_eq!(standard, name);
    assert_eq!(minimal, REDACTED);
}

#[test]
fn optional_text_differs_between_modes() {
    let text = Some("Hello world");
    let standard = strip_optional_text(MetadataMode::Standard, text);
    let minimal = strip_optional_text(MetadataMode::Minimal, text);
    assert!(standard.is_some());
    assert!(minimal.is_none());
}

// ============================================================================
// Group 4 — Redacted placeholder is exactly "[redacted]"
// ============================================================================

#[test]
fn minimal_placeholder_exact_value_node_name() {
    assert_eq!(
        strip_node_name(MetadataMode::Minimal, "anything"),
        "[redacted]"
    );
}

#[test]
fn minimal_placeholder_exact_value_channel_name() {
    assert_eq!(
        strip_channel_name(MetadataMode::Minimal, "anything"),
        "[redacted]"
    );
}

#[test]
fn minimal_placeholder_exact_value_category_name() {
    assert_eq!(
        strip_category_name(MetadataMode::Minimal, "anything"),
        "[redacted]"
    );
}

#[test]
fn minimal_placeholder_exact_value_display_name() {
    assert_eq!(
        strip_display_name(MetadataMode::Minimal, "anything"),
        "[redacted]"
    );
}
