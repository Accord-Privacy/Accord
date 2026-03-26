//! Unit tests for pure helper functions in handlers.rs

use accord_server::handlers::{
    content_type_to_ext, detect_content_type, discord_bit_name, extract_content, find_meta_tags,
    html_decode, sanitize_display_name, validate_image_content_type,
};

// ── sanitize_display_name ──────────────────────────────────────

#[test]
fn sanitize_trims_whitespace() {
    assert_eq!(sanitize_display_name("  hello  "), "hello");
}

#[test]
fn sanitize_strips_lt_gt_amp() {
    assert_eq!(
        sanitize_display_name("<script>alert('x')</script>"),
        "scriptalert('x')/script"
    );
    assert_eq!(sanitize_display_name("a&b"), "ab");
    assert_eq!(sanitize_display_name("a<b>c"), "abc");
}

#[test]
fn sanitize_enforces_32_char_limit() {
    let long = "a".repeat(100);
    let result = sanitize_display_name(&long);
    assert_eq!(result.len(), 32);
}

#[test]
fn sanitize_exact_32_chars_stays() {
    let name = "a".repeat(32);
    assert_eq!(sanitize_display_name(&name), name);
}

#[test]
fn sanitize_33_chars_truncated_to_32() {
    let name = "a".repeat(33);
    let result = sanitize_display_name(&name);
    assert_eq!(result.len(), 32);
}

#[test]
fn sanitize_unicode_passes_through() {
    assert_eq!(sanitize_display_name("こんにちは"), "こんにちは");
}

#[test]
fn sanitize_empty_returns_empty() {
    assert_eq!(sanitize_display_name(""), "");
}

#[test]
fn sanitize_whitespace_only_returns_empty() {
    assert_eq!(sanitize_display_name("   "), "");
}

#[test]
fn sanitize_mixed_unicode_and_strips() {
    // & and < > are stripped (not surrounding spaces), unicode preserved, trimmed
    // "  héllo & <world>  " → strip &,<,> → "  héllo  world  " → trim → "héllo  world"
    assert_eq!(sanitize_display_name("  héllo & <world>  "), "héllo  world");
}

// ── validate_image_content_type ───────────────────────────────

#[test]
fn validate_png_accepted() {
    assert_eq!(validate_image_content_type("image/png"), Some("image/png"));
}

#[test]
fn validate_jpeg_accepted() {
    assert_eq!(
        validate_image_content_type("image/jpeg"),
        Some("image/jpeg")
    );
}

#[test]
fn validate_jpg_accepted() {
    assert_eq!(validate_image_content_type("image/jpg"), Some("image/jpeg"));
}

#[test]
fn validate_gif_accepted() {
    assert_eq!(validate_image_content_type("image/gif"), Some("image/gif"));
}

#[test]
fn validate_webp_accepted() {
    assert_eq!(
        validate_image_content_type("image/webp"),
        Some("image/webp")
    );
}

#[test]
fn validate_svg_rejected() {
    assert_eq!(validate_image_content_type("image/svg+xml"), None);
}

#[test]
fn validate_text_rejected() {
    assert_eq!(validate_image_content_type("text/plain"), None);
}

#[test]
fn validate_empty_rejected() {
    assert_eq!(validate_image_content_type(""), None);
}

#[test]
fn validate_octet_stream_rejected() {
    assert_eq!(
        validate_image_content_type("application/octet-stream"),
        None
    );
}

// ── content_type_to_ext ───────────────────────────────────────

#[test]
fn ext_png() {
    assert_eq!(content_type_to_ext("image/png"), "png");
}

#[test]
fn ext_jpeg() {
    assert_eq!(content_type_to_ext("image/jpeg"), "jpg");
}

#[test]
fn ext_jpg_alias() {
    assert_eq!(content_type_to_ext("image/jpg"), "jpg");
}

#[test]
fn ext_gif() {
    assert_eq!(content_type_to_ext("image/gif"), "gif");
}

#[test]
fn ext_webp() {
    assert_eq!(content_type_to_ext("image/webp"), "webp");
}

#[test]
fn ext_unknown_falls_back_to_bin() {
    assert_eq!(content_type_to_ext("application/octet-stream"), "bin");
    assert_eq!(content_type_to_ext(""), "bin");
    assert_eq!(content_type_to_ext("image/svg+xml"), "bin");
}

// ── detect_content_type ───────────────────────────────────────

#[test]
fn detect_png_magic_bytes() {
    let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    assert_eq!(detect_content_type(&data), Some("image/png"));
}

#[test]
fn detect_jpeg_magic_bytes() {
    let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    assert_eq!(detect_content_type(&data), Some("image/jpeg"));
}

#[test]
fn detect_gif_magic_bytes() {
    let data = b"GIF89a\x01\x00\x01\x00";
    assert_eq!(detect_content_type(data), Some("image/gif"));
}

#[test]
fn detect_gif87a_magic_bytes() {
    let data = b"GIF87a\x01\x00\x01\x00";
    assert_eq!(detect_content_type(data), Some("image/gif"));
}

#[test]
fn detect_webp_magic_bytes() {
    // RIFF????WEBP
    let mut data = [0u8; 12];
    data[0..4].copy_from_slice(b"RIFF");
    data[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // file size (irrelevant)
    data[8..12].copy_from_slice(b"WEBP");
    assert_eq!(detect_content_type(&data), Some("image/webp"));
}

#[test]
fn detect_unknown_returns_none() {
    let data = b"hello world this is not an image";
    assert_eq!(detect_content_type(data), None);
}

#[test]
fn detect_too_short_returns_none() {
    assert_eq!(detect_content_type(&[0xFF, 0xD8, 0xFF]), None);
    assert_eq!(detect_content_type(&[]), None);
}

// ── discord_bit_name ──────────────────────────────────────────

#[test]
fn discord_known_bits() {
    assert_eq!(discord_bit_name(7), "Use Application Commands (bit 7)");
    assert_eq!(discord_bit_name(8), "View Audit Log (bit 8)");
    assert_eq!(discord_bit_name(9), "Priority Speaker (bit 9)");
    assert_eq!(discord_bit_name(12), "Send TTS Messages (bit 12)");
    assert_eq!(discord_bit_name(18), "Use External Emojis (bit 18)");
    assert_eq!(discord_bit_name(25), "Use VAD (bit 25)");
    assert_eq!(discord_bit_name(26), "Change Nickname (bit 26)");
    assert_eq!(discord_bit_name(40), "Moderate Members (bit 40)");
}

#[test]
fn discord_unknown_bit_returns_unknown() {
    assert_eq!(discord_bit_name(0), "Unknown");
    assert_eq!(discord_bit_name(1), "Unknown");
    assert_eq!(discord_bit_name(99), "Unknown");
    assert_eq!(discord_bit_name(u32::MAX), "Unknown");
}

// ── find_meta_tags ────────────────────────────────────────────

#[test]
fn find_meta_tags_basic() {
    let html = r#"<html><head><meta property="og:title" content="Hello"></head></html>"#;
    let tags = find_meta_tags(html);
    assert_eq!(tags.len(), 1);
    assert!(tags[0].contains("og:title"));
}

#[test]
fn find_meta_tags_multiple() {
    let html = r#"
        <meta property="og:title" content="Hello">
        <meta property="og:description" content="World">
        <meta name="viewport" content="width=device-width">
    "#;
    let tags = find_meta_tags(html);
    assert_eq!(tags.len(), 3);
}

#[test]
fn find_meta_tags_empty_html() {
    assert!(find_meta_tags("").is_empty());
    assert!(find_meta_tags("<html></html>").is_empty());
}

#[test]
fn find_meta_tags_no_meta_in_html() {
    let html = "<html><body><p>no meta here</p></body></html>";
    assert!(find_meta_tags(html).is_empty());
}

#[test]
fn find_meta_tags_case_insensitive() {
    // The function lowercases HTML to find <meta — uppercase should match
    let html = r#"<META property="og:title" content="Hello">"#;
    let tags = find_meta_tags(html);
    assert_eq!(tags.len(), 1);
}

#[test]
fn find_meta_tags_unclosed_tag_stops() {
    // A meta tag with no closing > should not be included (loop breaks)
    let html = "<meta property=\"og:title\" content=\"test\"";
    let tags = find_meta_tags(html);
    assert!(tags.is_empty());
}

// ── extract_content ───────────────────────────────────────────

#[test]
fn extract_content_double_quotes() {
    let tag = r#"<meta property="og:title" content="Hello World">"#;
    assert_eq!(extract_content(tag), Some("Hello World".to_string()));
}

#[test]
fn extract_content_single_quotes() {
    let tag = "<meta property='og:title' content='Hello World'>";
    assert_eq!(extract_content(tag), Some("Hello World".to_string()));
}

#[test]
fn extract_content_with_entities() {
    let tag = r#"<meta content="Hello &amp; World">"#;
    assert_eq!(extract_content(tag), Some("Hello & World".to_string()));
}

#[test]
fn extract_content_missing_returns_none() {
    let tag = r#"<meta property="og:title">"#;
    assert_eq!(extract_content(tag), None);
}

#[test]
fn extract_content_empty_value() {
    let tag = r#"<meta content="">"#;
    assert_eq!(extract_content(tag), Some("".to_string()));
}

#[test]
fn extract_content_no_content_attr() {
    let tag = r#"<meta name="viewport">"#;
    assert_eq!(extract_content(tag), None);
}

// ── html_decode ───────────────────────────────────────────────

#[test]
fn html_decode_amp() {
    assert_eq!(html_decode("Hello &amp; World"), "Hello & World");
}

#[test]
fn html_decode_lt_gt() {
    assert_eq!(html_decode("a &lt; b &gt; c"), "a < b > c");
}

#[test]
fn html_decode_quot() {
    assert_eq!(html_decode("&quot;quoted&quot;"), "\"quoted\"");
}

#[test]
fn html_decode_apos_numeric() {
    assert_eq!(html_decode("it&#39;s"), "it's");
}

#[test]
fn html_decode_apos_hex() {
    assert_eq!(html_decode("it&#x27;s"), "it's");
}

#[test]
fn html_decode_apos_named() {
    assert_eq!(html_decode("it&apos;s"), "it's");
}

#[test]
fn html_decode_no_entities() {
    assert_eq!(html_decode("plain text"), "plain text");
}

#[test]
fn html_decode_empty() {
    assert_eq!(html_decode(""), "");
}

#[test]
fn html_decode_multiple_entities() {
    assert_eq!(
        html_decode("&lt;div class=&quot;hello&quot;&gt;Hello &amp; World&lt;/div&gt;"),
        r#"<div class="hello">Hello & World</div>"#
    );
}
