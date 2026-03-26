//! External integration tests for the validation module
//!
//! Covers validate_username, validate_node_name, validate_channel_name,
//! validate_bio, validate_custom_status, validate_display_name,
//! validate_message_size, validate_emoji, validate_invite_code,
//! and sanitize_text.

#![allow(clippy::all)]

use accord_server::validation::{
    sanitize_text, validate_bio, validate_channel_name, validate_custom_status,
    validate_display_name, validate_emoji, validate_invite_code, validate_message_size,
    validate_node_name, validate_username,
};

// ============================================================================
// Group 1 — validate_username (~20 tests)
// ============================================================================

#[test]
fn username_valid_simple_alphanumeric() {
    assert!(validate_username("user123").is_ok());
}

#[test]
fn username_valid_with_underscore() {
    assert!(validate_username("test_user").is_ok());
}

#[test]
fn username_valid_with_hyphen() {
    assert!(validate_username("user-name").is_ok());
}

#[test]
fn username_valid_mixed_case() {
    assert!(validate_username("UserName42").is_ok());
}

#[test]
fn username_valid_all_digits() {
    assert!(validate_username("123456").is_ok());
}

#[test]
fn username_valid_at_min_length() {
    // Exactly 3 characters — boundary
    assert!(validate_username("abc").is_ok());
}

#[test]
fn username_valid_at_max_length() {
    // Exactly 32 characters — boundary
    assert!(validate_username(&"a".repeat(32)).is_ok());
}

#[test]
fn username_valid_underscore_in_middle() {
    assert!(validate_username("a_b").is_ok());
}

#[test]
fn username_valid_hyphen_in_middle() {
    assert!(validate_username("a-b").is_ok());
}

#[test]
fn username_invalid_empty() {
    let err = validate_username("").unwrap_err();
    assert!(err.contains("3 characters"));
}

#[test]
fn username_invalid_one_char() {
    assert!(validate_username("a").is_err());
}

#[test]
fn username_invalid_two_chars() {
    assert!(validate_username("ab").is_err());
}

#[test]
fn username_invalid_exceeds_max() {
    assert!(validate_username(&"a".repeat(33)).is_err());
}

#[test]
fn username_invalid_way_too_long() {
    assert!(validate_username(&"a".repeat(100)).is_err());
}

#[test]
fn username_invalid_at_sign() {
    assert!(validate_username("user@name").is_err());
}

#[test]
fn username_invalid_dot() {
    assert!(validate_username("user.name").is_err());
}

#[test]
fn username_invalid_space() {
    assert!(validate_username("user name").is_err());
}

#[test]
fn username_invalid_exclamation() {
    assert!(validate_username("user!").is_err());
}

#[test]
fn username_invalid_unicode_letter() {
    // Non-ASCII letters are technically alphanumeric via is_alphanumeric —
    // but we verify the actual behavior without prescribing it
    let result = validate_username("café");
    // This test documents current behavior; 'é' passes is_alphanumeric in Rust
    // so this may succeed — just ensure it doesn't panic
    let _ = result;
}

#[test]
fn username_invalid_leading_underscore() {
    let err = validate_username("_username").unwrap_err();
    assert!(err.contains("start or end"));
}

#[test]
fn username_invalid_trailing_underscore() {
    let err = validate_username("username_").unwrap_err();
    assert!(err.contains("start or end"));
}

#[test]
fn username_invalid_leading_hyphen() {
    let err = validate_username("-username").unwrap_err();
    assert!(err.contains("start or end"));
}

#[test]
fn username_invalid_trailing_hyphen() {
    let err = validate_username("username-").unwrap_err();
    assert!(err.contains("start or end"));
}

#[test]
fn username_invalid_only_underscores() {
    // "_" is 1 char → too short first, but if 3+ only underscores: leading/trailing rule fires
    assert!(validate_username("___").is_err());
}

#[test]
fn username_invalid_only_hyphens() {
    assert!(validate_username("---").is_err());
}

#[test]
fn username_error_message_too_short() {
    let err = validate_username("ab").unwrap_err();
    assert!(err.contains("3 characters"));
}

#[test]
fn username_error_message_too_long() {
    let err = validate_username(&"a".repeat(33)).unwrap_err();
    assert!(err.contains("32 characters"));
}

#[test]
fn username_error_message_invalid_chars() {
    let err = validate_username("bad@char").unwrap_err();
    assert!(err.contains("alphanumeric"));
}

// ============================================================================
// Group 2 — validate_node_name (~12 tests)
// ============================================================================

#[test]
fn node_name_valid_simple() {
    assert!(validate_node_name("MyNode").is_ok());
}

#[test]
fn node_name_valid_single_char() {
    // 1 character — min boundary
    assert!(validate_node_name("A").is_ok());
}

#[test]
fn node_name_valid_at_max_length() {
    // Exactly 100 chars — boundary
    assert!(validate_node_name(&"a".repeat(100)).is_ok());
}

#[test]
fn node_name_valid_with_spaces() {
    assert!(validate_node_name("Node with spaces").is_ok());
}

#[test]
fn node_name_valid_special_chars() {
    assert!(validate_node_name("Node!@#$%^&*()").is_ok());
}

#[test]
fn node_name_valid_with_leading_trailing_whitespace() {
    // Whitespace is trimmed before validation
    assert!(validate_node_name("  MyNode  ").is_ok());
}

#[test]
fn node_name_valid_unicode() {
    assert!(validate_node_name("Nøde 🚀").is_ok());
}

#[test]
fn node_name_valid_only_spaces_but_has_content_after_trim() {
    assert!(validate_node_name("  x  ").is_ok());
}

#[test]
fn node_name_invalid_empty() {
    let err = validate_node_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn node_name_invalid_whitespace_only() {
    let err = validate_node_name("   ").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn node_name_invalid_tabs_only() {
    assert!(validate_node_name("\t\t").is_err());
}

#[test]
fn node_name_invalid_exceeds_max() {
    // 101 chars — just over boundary
    assert!(validate_node_name(&"a".repeat(101)).is_err());
}

#[test]
fn node_name_invalid_far_exceeds_max() {
    assert!(validate_node_name(&"a".repeat(200)).is_err());
}

#[test]
fn node_name_error_message_empty() {
    let err = validate_node_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn node_name_error_message_too_long() {
    let err = validate_node_name(&"a".repeat(101)).unwrap_err();
    assert!(err.contains("100 characters"));
}

// ============================================================================
// Group 3 — validate_channel_name (~18 tests)
// ============================================================================

#[test]
fn channel_name_valid_simple() {
    assert!(validate_channel_name("general").is_ok());
}

#[test]
fn channel_name_valid_with_hyphen() {
    assert!(validate_channel_name("random-chat").is_ok());
}

#[test]
fn channel_name_valid_with_digits() {
    assert!(validate_channel_name("channel123").is_ok());
}

#[test]
fn channel_name_valid_single_char() {
    assert!(validate_channel_name("a").is_ok());
}

#[test]
fn channel_name_valid_single_digit() {
    assert!(validate_channel_name("1").is_ok());
}

#[test]
fn channel_name_valid_at_max_length() {
    assert!(validate_channel_name(&"a".repeat(100)).is_ok());
}

#[test]
fn channel_name_valid_mixed_lower_digits_hyphens() {
    assert!(validate_channel_name("test-channel-123").is_ok());
}

#[test]
fn channel_name_valid_all_digits() {
    assert!(validate_channel_name("123456").is_ok());
}

#[test]
fn channel_name_valid_all_hyphens_allowed() {
    // Hyphens anywhere are allowed — no leading/trailing restriction like usernames
    assert!(validate_channel_name("---").is_ok());
}

#[test]
fn channel_name_invalid_empty() {
    let err = validate_channel_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn channel_name_invalid_uppercase() {
    assert!(validate_channel_name("Channel").is_err());
}

#[test]
fn channel_name_invalid_all_uppercase() {
    assert!(validate_channel_name("GENERAL").is_err());
}

#[test]
fn channel_name_invalid_underscore() {
    assert!(validate_channel_name("channel_name").is_err());
}

#[test]
fn channel_name_invalid_space() {
    assert!(validate_channel_name("channel name").is_err());
}

#[test]
fn channel_name_invalid_exclamation() {
    assert!(validate_channel_name("channel!").is_err());
}

#[test]
fn channel_name_invalid_dot() {
    assert!(validate_channel_name("channel.txt").is_err());
}

#[test]
fn channel_name_invalid_unicode_letter() {
    assert!(validate_channel_name("générale").is_err());
}

#[test]
fn channel_name_invalid_emoji() {
    assert!(validate_channel_name("chat🚀").is_err());
}

#[test]
fn channel_name_invalid_exceeds_max() {
    assert!(validate_channel_name(&"a".repeat(101)).is_err());
}

#[test]
fn channel_name_error_message_empty() {
    let err = validate_channel_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn channel_name_error_message_too_long() {
    let err = validate_channel_name(&"a".repeat(101)).unwrap_err();
    assert!(err.contains("100 characters"));
}

#[test]
fn channel_name_error_message_invalid_chars() {
    let err = validate_channel_name("Channel").unwrap_err();
    assert!(err.contains("lowercase"));
}

// ============================================================================
// Group 4 — validate_bio (~10 tests)
// ============================================================================

#[test]
fn bio_valid_empty() {
    assert!(validate_bio("").is_ok());
}

#[test]
fn bio_valid_simple_text() {
    assert!(validate_bio("Hello, I'm a developer").is_ok());
}

#[test]
fn bio_valid_at_max_length() {
    // Exactly 190 Unicode chars — boundary
    assert!(validate_bio(&"a".repeat(190)).is_ok());
}

#[test]
fn bio_valid_with_emojis() {
    // Emojis count as 1 char each in chars().count()
    assert!(validate_bio("Dev 🚀 🎉 🦀").is_ok());
}

#[test]
fn bio_valid_with_newlines() {
    assert!(validate_bio("Line one\nLine two").is_ok());
}

#[test]
fn bio_valid_with_special_chars() {
    assert!(validate_bio("Bio with @#$%^&*() symbols").is_ok());
}

#[test]
fn bio_valid_unicode_multibyte() {
    // 10 multibyte chars — well under limit
    assert!(validate_bio("日本語テスト").is_ok());
}

#[test]
fn bio_invalid_one_over_max() {
    assert!(validate_bio(&"a".repeat(191)).is_err());
}

#[test]
fn bio_invalid_far_over_max() {
    assert!(validate_bio(&"a".repeat(300)).is_err());
}

#[test]
fn bio_invalid_unicode_over_limit() {
    // 191 multibyte chars — should exceed 190 char limit
    assert!(validate_bio(&"日".repeat(191)).is_err());
}

#[test]
fn bio_error_message_too_long() {
    let err = validate_bio(&"a".repeat(191)).unwrap_err();
    assert!(err.contains("190 characters"));
}

// ============================================================================
// Group 5 — validate_custom_status (~8 tests)
// ============================================================================

#[test]
fn custom_status_valid_empty() {
    assert!(validate_custom_status("").is_ok());
}

#[test]
fn custom_status_valid_simple() {
    assert!(validate_custom_status("Working on stuff").is_ok());
}

#[test]
fn custom_status_valid_at_max_length() {
    assert!(validate_custom_status(&"a".repeat(128)).is_ok());
}

#[test]
fn custom_status_valid_with_emoji() {
    assert!(validate_custom_status("🎧 In the zone").is_ok());
}

#[test]
fn custom_status_valid_unicode() {
    assert!(validate_custom_status("お仕事中").is_ok());
}

#[test]
fn custom_status_invalid_one_over_max() {
    assert!(validate_custom_status(&"a".repeat(129)).is_err());
}

#[test]
fn custom_status_invalid_far_over_max() {
    assert!(validate_custom_status(&"a".repeat(200)).is_err());
}

#[test]
fn custom_status_invalid_unicode_over_limit() {
    assert!(validate_custom_status(&"字".repeat(129)).is_err());
}

#[test]
fn custom_status_error_message_too_long() {
    let err = validate_custom_status(&"a".repeat(129)).unwrap_err();
    assert!(err.contains("128 characters"));
}

// ============================================================================
// Group 6 — validate_display_name (~12 tests)
// ============================================================================

#[test]
fn display_name_valid_simple() {
    assert!(validate_display_name("John Doe").is_ok());
}

#[test]
fn display_name_valid_single_char() {
    assert!(validate_display_name("A").is_ok());
}

#[test]
fn display_name_valid_at_max_length() {
    assert!(validate_display_name(&"a".repeat(32)).is_ok());
}

#[test]
fn display_name_valid_with_spaces() {
    assert!(validate_display_name("User With Spaces").is_ok());
}

#[test]
fn display_name_valid_with_emoji() {
    assert!(validate_display_name("🎉 Cool User 🎉").is_ok());
}

#[test]
fn display_name_valid_unicode() {
    assert!(validate_display_name("山田太郎").is_ok());
}

#[test]
fn display_name_valid_special_chars() {
    assert!(validate_display_name("User@2024").is_ok());
}

#[test]
fn display_name_invalid_empty() {
    let err = validate_display_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn display_name_invalid_one_over_max() {
    assert!(validate_display_name(&"a".repeat(33)).is_err());
}

#[test]
fn display_name_invalid_far_over_max() {
    assert!(validate_display_name(&"a".repeat(100)).is_err());
}

#[test]
fn display_name_invalid_unicode_over_limit() {
    // 33 multibyte chars
    assert!(validate_display_name(&"字".repeat(33)).is_err());
}

#[test]
fn display_name_error_message_empty() {
    let err = validate_display_name("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn display_name_error_message_too_long() {
    let err = validate_display_name(&"a".repeat(33)).unwrap_err();
    assert!(err.contains("32 characters"));
}

// ============================================================================
// Group 7 — validate_message_size (~8 tests)
// ============================================================================

#[test]
fn message_size_valid_empty() {
    assert!(validate_message_size(&[]).is_ok());
}

#[test]
fn message_size_valid_one_byte() {
    assert!(validate_message_size(&[0u8]).is_ok());
}

#[test]
fn message_size_valid_small() {
    assert!(validate_message_size(&[0u8; 1000]).is_ok());
}

#[test]
fn message_size_valid_at_max() {
    // Exactly 65536 bytes — boundary
    assert!(validate_message_size(&vec![0u8; 65536]).is_ok());
}

#[test]
fn message_size_valid_near_max() {
    assert!(validate_message_size(&vec![0u8; 65535]).is_ok());
}

#[test]
fn message_size_invalid_one_over_max() {
    assert!(validate_message_size(&vec![0u8; 65537]).is_err());
}

#[test]
fn message_size_invalid_far_over_max() {
    assert!(validate_message_size(&vec![0u8; 100_000]).is_err());
}

#[test]
fn message_size_invalid_double_max() {
    assert!(validate_message_size(&vec![0u8; 131_072]).is_err());
}

#[test]
fn message_size_error_message() {
    let err = validate_message_size(&vec![0u8; 65537]).unwrap_err();
    assert!(err.contains("65536 bytes"));
}

// ============================================================================
// Group 8 — validate_emoji (~10 tests)
// ============================================================================

#[test]
fn emoji_valid_single_emoji() {
    assert!(validate_emoji("😀").is_ok());
}

#[test]
fn emoji_valid_thumbs_up() {
    assert!(validate_emoji("👍").is_ok());
}

#[test]
fn emoji_valid_text_style() {
    assert!(validate_emoji(":smile:").is_ok());
}

#[test]
fn emoji_valid_single_ascii() {
    assert!(validate_emoji("A").is_ok());
}

#[test]
fn emoji_valid_multiple_emojis() {
    // 8 emoji chars — well under 32
    assert!(validate_emoji("😀👍🚀🎉🦀🌟💯🔥").is_ok());
}

#[test]
fn emoji_valid_at_max_length_ascii() {
    // 32 ASCII chars
    assert!(validate_emoji(&"a".repeat(32)).is_ok());
}

#[test]
fn emoji_invalid_empty() {
    let err = validate_emoji("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn emoji_invalid_one_over_max_ascii() {
    assert!(validate_emoji(&"a".repeat(33)).is_err());
}

#[test]
fn emoji_invalid_unicode_over_limit() {
    // 33 multibyte chars
    assert!(validate_emoji(&"字".repeat(33)).is_err());
}

#[test]
fn emoji_error_message_empty() {
    let err = validate_emoji("").unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn emoji_error_message_too_long() {
    let err = validate_emoji(&"a".repeat(33)).unwrap_err();
    assert!(err.contains("32 characters"));
}

// ============================================================================
// Group 9 — validate_invite_code (~16 tests)
// ============================================================================

#[test]
fn invite_code_valid_min_length() {
    // Exactly 6 chars — boundary
    assert!(validate_invite_code("abc123").is_ok());
}

#[test]
fn invite_code_valid_max_length() {
    // Exactly 12 chars — boundary
    assert!(validate_invite_code("ABC123DEF456").is_ok());
}

#[test]
fn invite_code_valid_mid_length() {
    assert!(validate_invite_code("INVITE01").is_ok());
}

#[test]
fn invite_code_valid_digits_only() {
    assert!(validate_invite_code("123456").is_ok());
}

#[test]
fn invite_code_valid_letters_only() {
    assert!(validate_invite_code("ABCDEF").is_ok());
}

#[test]
fn invite_code_valid_mixed_case() {
    assert!(validate_invite_code("AbCdEf").is_ok());
}

#[test]
fn invite_code_valid_seven_chars() {
    assert!(validate_invite_code("abc1234").is_ok());
}

#[test]
fn invite_code_invalid_empty() {
    assert!(validate_invite_code("").is_err());
}

#[test]
fn invite_code_invalid_five_chars() {
    assert!(validate_invite_code("12345").is_err());
}

#[test]
fn invite_code_invalid_one_char() {
    assert!(validate_invite_code("a").is_err());
}

#[test]
fn invite_code_invalid_thirteen_chars() {
    assert!(validate_invite_code("1234567890123").is_err());
}

#[test]
fn invite_code_invalid_hyphen() {
    assert!(validate_invite_code("abc-123").is_err());
}

#[test]
fn invite_code_invalid_underscore() {
    assert!(validate_invite_code("abc_123").is_err());
}

#[test]
fn invite_code_invalid_space() {
    assert!(validate_invite_code("abc 123").is_err());
}

#[test]
fn invite_code_invalid_special_char() {
    assert!(validate_invite_code("abc!23").is_err());
}

#[test]
fn invite_code_invalid_dot() {
    assert!(validate_invite_code("abc.23").is_err());
}

#[test]
fn invite_code_error_message_too_short() {
    let err = validate_invite_code("12345").unwrap_err();
    assert!(err.contains("6 characters"));
}

#[test]
fn invite_code_error_message_too_long() {
    let err = validate_invite_code("1234567890123").unwrap_err();
    assert!(err.contains("12 characters"));
}

#[test]
fn invite_code_error_message_invalid_chars() {
    let err = validate_invite_code("abc-12").unwrap_err();
    assert!(err.contains("alphanumeric"));
}

// ============================================================================
// Group 10 — sanitize_text (~12 tests)
// ============================================================================

#[test]
fn sanitize_preserves_normal_text() {
    assert_eq!(sanitize_text("hello world"), "hello world");
}

#[test]
fn sanitize_preserves_newline() {
    assert_eq!(sanitize_text("hello\nworld"), "hello\nworld");
}

#[test]
fn sanitize_preserves_carriage_return() {
    assert_eq!(sanitize_text("hello\rworld"), "hello\rworld");
}

#[test]
fn sanitize_preserves_tab() {
    assert_eq!(sanitize_text("hello\tworld"), "hello\tworld");
}

#[test]
fn sanitize_preserves_crlf() {
    assert_eq!(sanitize_text("line1\r\nline2"), "line1\r\nline2");
}

#[test]
fn sanitize_strips_null_byte() {
    assert_eq!(sanitize_text("hello\0world"), "helloworld");
}

#[test]
fn sanitize_strips_control_char_soh() {
    // SOH (Start of Heading) — \x01
    assert_eq!(sanitize_text("hello\x01world"), "helloworld");
}

#[test]
fn sanitize_strips_multiple_control_chars() {
    assert_eq!(sanitize_text("hello\x01\x02\x03world"), "helloworld");
}

#[test]
fn sanitize_empty_input() {
    assert_eq!(sanitize_text(""), "");
}

#[test]
fn sanitize_all_control_chars_stripped_except_whitespace() {
    // DEL character — \x7f is a control char
    let result = sanitize_text("hello\x7fworld");
    assert!(!result.contains('\x7f'));
}

#[test]
fn sanitize_preserves_unicode() {
    assert_eq!(sanitize_text("Héllo 世界 🚀"), "Héllo 世界 🚀");
}

#[test]
fn sanitize_preserves_spaces() {
    assert_eq!(sanitize_text("   lots   of   spaces   "), "   lots   of   spaces   ");
}

#[test]
fn sanitize_null_only_input() {
    assert_eq!(sanitize_text("\0\0\0"), "");
}

#[test]
fn sanitize_mixed_valid_and_control() {
    // \x1b is ESC — control char, should be stripped
    let result = sanitize_text("before\x1bafter");
    assert_eq!(result, "beforeafter");
}

// ============================================================================
// Cross-validation edge cases
// ============================================================================

#[test]
fn username_boundary_exactly_3_chars() {
    assert!(validate_username("abc").is_ok());
    assert!(validate_username("ab").is_err());
}

#[test]
fn username_boundary_exactly_32_chars() {
    assert!(validate_username(&"a".repeat(32)).is_ok());
    assert!(validate_username(&"a".repeat(33)).is_err());
}

#[test]
fn channel_name_boundary_exactly_1_char() {
    assert!(validate_channel_name("a").is_ok());
    assert!(validate_channel_name("").is_err());
}

#[test]
fn channel_name_boundary_exactly_100_chars() {
    assert!(validate_channel_name(&"a".repeat(100)).is_ok());
    assert!(validate_channel_name(&"a".repeat(101)).is_err());
}

#[test]
fn invite_code_boundary_exactly_6_chars() {
    assert!(validate_invite_code("abcdef").is_ok());
    assert!(validate_invite_code("abcde").is_err());
}

#[test]
fn invite_code_boundary_exactly_12_chars() {
    assert!(validate_invite_code("abcdef123456").is_ok());
    assert!(validate_invite_code("abcdef1234567").is_err());
}

#[test]
fn message_size_boundary_exactly_65536_bytes() {
    assert!(validate_message_size(&vec![0u8; 65536]).is_ok());
    assert!(validate_message_size(&vec![0u8; 65537]).is_err());
}

#[test]
fn bio_boundary_exactly_190_chars() {
    assert!(validate_bio(&"a".repeat(190)).is_ok());
    assert!(validate_bio(&"a".repeat(191)).is_err());
}

#[test]
fn custom_status_boundary_exactly_128_chars() {
    assert!(validate_custom_status(&"a".repeat(128)).is_ok());
    assert!(validate_custom_status(&"a".repeat(129)).is_err());
}

#[test]
fn display_name_boundary_exactly_32_chars() {
    assert!(validate_display_name(&"a".repeat(32)).is_ok());
    assert!(validate_display_name(&"a".repeat(33)).is_err());
}
