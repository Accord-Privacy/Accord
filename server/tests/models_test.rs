//! External integration tests for `accord_server::models`.
//!
//! Covers permission bit constants, enums, and serde round-trips from outside
//! the crate so that only the public API is exercised.

#![allow(clippy::all)]

use accord_server::models::{
    permission_bits::{
        compute_channel_permissions, map_discord_permissions, name, ADD_REACTIONS, ADMINISTRATOR,
        ALL_PERMISSIONS, ATTACH_FILES, BAN_MEMBERS, CONNECT, CREATE_INVITE, DEAFEN_MEMBERS,
        DEFAULT_EVERYONE, EMBED_LINKS, KICK_MEMBERS, MANAGE_CHANNELS, MANAGE_MESSAGES, MANAGE_NODE,
        MANAGE_ROLES, MENTION_EVERYONE, MOVE_MEMBERS, MUTE_MEMBERS, READ_MESSAGE_HISTORY,
        SEND_MESSAGES, SPEAK, VIEW_CHANNEL,
    },
    AuthRequest, AuthResponse, BanUserRequest, ChannelType, CreateNodeRequest, EditMessageRequest,
    ErrorResponse, NotificationPrivacy, PermissionDeniedResponse, PushPlatform, RegisterRequest,
    WsMessageType,
};
use uuid::Uuid;

// ────────────────────────────────────────────────────────────────
// Permission bit constants — structural properties
// ────────────────────────────────────────────────────────────────

/// Every named permission constant must be a power of two (exactly one bit set).
#[test]
fn permission_constants_are_powers_of_two() {
    let all: &[u64] = &[
        CREATE_INVITE,
        KICK_MEMBERS,
        BAN_MEMBERS,
        ADMINISTRATOR,
        MANAGE_CHANNELS,
        MANAGE_NODE,
        ADD_REACTIONS,
        VIEW_CHANNEL,
        SEND_MESSAGES,
        MANAGE_MESSAGES,
        EMBED_LINKS,
        ATTACH_FILES,
        READ_MESSAGE_HISTORY,
        MENTION_EVERYONE,
        CONNECT,
        SPEAK,
        MUTE_MEMBERS,
        DEAFEN_MEMBERS,
        MOVE_MEMBERS,
        MANAGE_ROLES,
    ];
    for &b in all {
        assert!(
            b != 0 && (b & b.wrapping_sub(1)) == 0,
            "permission {:#018x} ({}) is not a power of two",
            b,
            name(b)
        );
    }
}

/// No two permission constants may share the same value.
#[test]
fn permission_constants_have_no_collisions() {
    let all: &[u64] = &[
        CREATE_INVITE,
        KICK_MEMBERS,
        BAN_MEMBERS,
        ADMINISTRATOR,
        MANAGE_CHANNELS,
        MANAGE_NODE,
        ADD_REACTIONS,
        VIEW_CHANNEL,
        SEND_MESSAGES,
        MANAGE_MESSAGES,
        EMBED_LINKS,
        ATTACH_FILES,
        READ_MESSAGE_HISTORY,
        MENTION_EVERYONE,
        CONNECT,
        SPEAK,
        MUTE_MEMBERS,
        DEAFEN_MEMBERS,
        MOVE_MEMBERS,
        MANAGE_ROLES,
    ];
    for i in 0..all.len() {
        for j in (i + 1)..all.len() {
            assert_ne!(
                all[i], all[j],
                "collision: index {i} and {j} both equal {:#018x}",
                all[i]
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────
// DEFAULT_EVERYONE
// ────────────────────────────────────────────────────────────────

/// DEFAULT_EVERYONE must contain every bit listed in the source definition.
#[test]
fn default_everyone_contains_all_expected_bits() {
    let expected: &[u64] = &[
        VIEW_CHANNEL,
        SEND_MESSAGES,
        READ_MESSAGE_HISTORY,
        ADD_REACTIONS,
        CONNECT,
        SPEAK,
        EMBED_LINKS,
        ATTACH_FILES,
        CREATE_INVITE,
    ];
    for &b in expected {
        assert_ne!(
            DEFAULT_EVERYONE & b,
            0,
            "DEFAULT_EVERYONE is missing {}",
            name(b)
        );
    }
}

/// DEFAULT_EVERYONE must NOT grant privileged / moderation bits.
#[test]
fn default_everyone_excludes_privileged_bits() {
    let privileged: &[u64] = &[
        ADMINISTRATOR,
        KICK_MEMBERS,
        BAN_MEMBERS,
        MANAGE_CHANNELS,
        MANAGE_NODE,
        MANAGE_MESSAGES,
        MANAGE_ROLES,
        MUTE_MEMBERS,
        DEAFEN_MEMBERS,
        MOVE_MEMBERS,
        MENTION_EVERYONE,
    ];
    for &b in privileged {
        assert_eq!(
            DEFAULT_EVERYONE & b,
            0,
            "DEFAULT_EVERYONE should NOT include {}",
            name(b)
        );
    }
}

/// DEFAULT_EVERYONE must be a strict subset of ALL_PERMISSIONS.
#[test]
fn default_everyone_is_subset_of_all_permissions() {
    assert_eq!(
        DEFAULT_EVERYONE & ALL_PERMISSIONS,
        DEFAULT_EVERYONE,
        "DEFAULT_EVERYONE contains bits not in ALL_PERMISSIONS"
    );
}

// ────────────────────────────────────────────────────────────────
// ALL_PERMISSIONS
// ────────────────────────────────────────────────────────────────

/// ALL_PERMISSIONS must contain every individual permission constant.
#[test]
fn all_permissions_contains_every_defined_bit() {
    let all: &[u64] = &[
        CREATE_INVITE,
        KICK_MEMBERS,
        BAN_MEMBERS,
        ADMINISTRATOR,
        MANAGE_CHANNELS,
        MANAGE_NODE,
        ADD_REACTIONS,
        VIEW_CHANNEL,
        SEND_MESSAGES,
        MANAGE_MESSAGES,
        EMBED_LINKS,
        ATTACH_FILES,
        READ_MESSAGE_HISTORY,
        MENTION_EVERYONE,
        CONNECT,
        SPEAK,
        MUTE_MEMBERS,
        DEAFEN_MEMBERS,
        MOVE_MEMBERS,
        MANAGE_ROLES,
    ];
    for &b in all {
        assert_ne!(
            ALL_PERMISSIONS & b,
            0,
            "ALL_PERMISSIONS is missing {}",
            name(b)
        );
    }
}

/// ALL_PERMISSIONS must equal exactly the OR of all 20 constants — no phantom bits.
#[test]
fn all_permissions_equals_union_of_constants() {
    let union: u64 = [
        CREATE_INVITE,
        KICK_MEMBERS,
        BAN_MEMBERS,
        ADMINISTRATOR,
        MANAGE_CHANNELS,
        MANAGE_NODE,
        ADD_REACTIONS,
        VIEW_CHANNEL,
        SEND_MESSAGES,
        MANAGE_MESSAGES,
        EMBED_LINKS,
        ATTACH_FILES,
        READ_MESSAGE_HISTORY,
        MENTION_EVERYONE,
        CONNECT,
        SPEAK,
        MUTE_MEMBERS,
        DEAFEN_MEMBERS,
        MOVE_MEMBERS,
        MANAGE_ROLES,
    ]
    .iter()
    .fold(0u64, |acc, &b| acc | b);

    assert_eq!(
        ALL_PERMISSIONS, union,
        "ALL_PERMISSIONS has extra bits beyond the 20 defined constants"
    );
}

/// Exactly 20 distinct bits are set in ALL_PERMISSIONS.
#[test]
fn all_permissions_has_exactly_20_bits() {
    assert_eq!(
        ALL_PERMISSIONS.count_ones(),
        20,
        "expected 20 permission bits, got {}",
        ALL_PERMISSIONS.count_ones()
    );
}

// ────────────────────────────────────────────────────────────────
// name()
// ────────────────────────────────────────────────────────────────

#[test]
fn name_returns_correct_string_for_every_defined_permission() {
    assert_eq!(name(CREATE_INVITE), "CREATE_INVITE");
    assert_eq!(name(KICK_MEMBERS), "KICK_MEMBERS");
    assert_eq!(name(BAN_MEMBERS), "BAN_MEMBERS");
    assert_eq!(name(ADMINISTRATOR), "ADMINISTRATOR");
    assert_eq!(name(MANAGE_CHANNELS), "MANAGE_CHANNELS");
    assert_eq!(name(MANAGE_NODE), "MANAGE_NODE");
    assert_eq!(name(ADD_REACTIONS), "ADD_REACTIONS");
    assert_eq!(name(VIEW_CHANNEL), "VIEW_CHANNEL");
    assert_eq!(name(SEND_MESSAGES), "SEND_MESSAGES");
    assert_eq!(name(MANAGE_MESSAGES), "MANAGE_MESSAGES");
    assert_eq!(name(EMBED_LINKS), "EMBED_LINKS");
    assert_eq!(name(ATTACH_FILES), "ATTACH_FILES");
    assert_eq!(name(READ_MESSAGE_HISTORY), "READ_MESSAGE_HISTORY");
    assert_eq!(name(MENTION_EVERYONE), "MENTION_EVERYONE");
    assert_eq!(name(CONNECT), "CONNECT");
    assert_eq!(name(SPEAK), "SPEAK");
    assert_eq!(name(MUTE_MEMBERS), "MUTE_MEMBERS");
    assert_eq!(name(DEAFEN_MEMBERS), "DEAFEN_MEMBERS");
    assert_eq!(name(MOVE_MEMBERS), "MOVE_MEMBERS");
    assert_eq!(name(MANAGE_ROLES), "MANAGE_ROLES");
}

#[test]
fn name_returns_unknown_for_zero() {
    assert_eq!(name(0), "UNKNOWN");
}

/// Bit positions not occupied by any constant must return "UNKNOWN".
#[test]
fn name_returns_unknown_for_gaps_and_large_values() {
    // Gaps: bits 7, 8, 9, 12, 18, 19, 25-27, 29+
    let gap_bits: &[u64] = &[
        1 << 7,
        1 << 8,
        1 << 9,
        1 << 12,
        1 << 18,
        1 << 19,
        1 << 25,
        1 << 29,
        1 << 40,
        1 << 63,
    ];
    for &b in gap_bits {
        assert_eq!(
            name(b),
            "UNKNOWN",
            "expected UNKNOWN for undefined bit {:#018x}",
            b
        );
    }
}

/// Every bit set in ALL_PERMISSIONS returns a non-"UNKNOWN" name.
#[test]
fn name_is_known_for_every_bit_in_all_permissions() {
    for bit_pos in 0u64..64 {
        let b = 1u64 << bit_pos;
        if ALL_PERMISSIONS & b != 0 {
            assert_ne!(
                name(b),
                "UNKNOWN",
                "bit {bit_pos} is in ALL_PERMISSIONS but name() returned UNKNOWN"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────
// compute_channel_permissions()
// ────────────────────────────────────────────────────────────────

/// ADMINISTRATOR flag bypasses all channel overwrites and grants ALL_PERMISSIONS.
#[test]
fn compute_channel_perms_admin_bypasses_everything() {
    let perms = compute_channel_permissions(
        ADMINISTRATOR,
        Some((0, VIEW_CHANNEL | SEND_MESSAGES)), // deny everything
        Some((0, CONNECT | SPEAK)),
    );
    assert_eq!(perms, ALL_PERMISSIONS);
}

/// Passing no overwrites returns the base permissions unchanged.
#[test]
fn compute_channel_perms_no_overwrites_returns_base() {
    let base = VIEW_CHANNEL | SEND_MESSAGES | ADD_REACTIONS;
    assert_eq!(compute_channel_permissions(base, None, None), base);
}

/// Category overwrite can deny and allow bits.
#[test]
fn compute_channel_perms_category_overwrites_applied() {
    let base = VIEW_CHANNEL | SEND_MESSAGES | ADD_REACTIONS;
    // Deny SEND_MESSAGES, allow EMBED_LINKS
    let result = compute_channel_permissions(base, Some((EMBED_LINKS, SEND_MESSAGES)), None);
    assert_ne!(result & VIEW_CHANNEL, 0, "VIEW_CHANNEL should survive");
    assert_eq!(
        result & SEND_MESSAGES,
        0,
        "SEND_MESSAGES denied by category"
    );
    assert_ne!(result & EMBED_LINKS, 0, "EMBED_LINKS allowed by category");
}

/// Channel overwrite takes precedence over category overwrite.
#[test]
fn compute_channel_perms_channel_overwrite_overrides_category() {
    // Category grants SEND_MESSAGES, channel denies it
    let base = VIEW_CHANNEL;
    let result = compute_channel_permissions(
        base,
        Some((SEND_MESSAGES, 0)), // category allows SEND_MESSAGES
        Some((0, SEND_MESSAGES)), // channel denies it
    );
    assert_eq!(
        result & SEND_MESSAGES,
        0,
        "channel deny should override category allow"
    );
}

/// Full cascade: base → category allow/deny → channel allow/deny.
#[test]
fn compute_channel_perms_full_cascade() {
    let base = VIEW_CHANNEL | SEND_MESSAGES | ADD_REACTIONS;
    let result = compute_channel_permissions(
        base,
        Some((EMBED_LINKS, SEND_MESSAGES)), // cat: +EMBED_LINKS -SEND_MESSAGES
        Some((ATTACH_FILES, ADD_REACTIONS)), // ch:  +ATTACH_FILES -ADD_REACTIONS
    );
    assert_ne!(result & VIEW_CHANNEL, 0);
    assert_eq!(result & SEND_MESSAGES, 0);
    assert_ne!(result & EMBED_LINKS, 0);
    assert_eq!(result & ADD_REACTIONS, 0);
    assert_ne!(result & ATTACH_FILES, 0);
}

// ────────────────────────────────────────────────────────────────
// map_discord_permissions()
// ────────────────────────────────────────────────────────────────

#[test]
fn map_discord_perms_zero_produces_zero() {
    assert_eq!(map_discord_permissions(0), 0);
}

#[test]
fn map_discord_perms_known_bits_map_correctly() {
    // Discord bit 0x1 → CREATE_INVITE
    assert_eq!(map_discord_permissions(0x1), CREATE_INVITE);
    // Discord bit 0x8 → ADMINISTRATOR
    assert_eq!(map_discord_permissions(0x8), ADMINISTRATOR);
    // Discord bit 0x400 → VIEW_CHANNEL
    assert_eq!(map_discord_permissions(0x400), VIEW_CHANNEL);
}

#[test]
fn map_discord_perms_multiple_bits() {
    let discord = 0x1 | 0x8 | 0x400;
    let expected = CREATE_INVITE | ADMINISTRATOR | VIEW_CHANNEL;
    assert_eq!(map_discord_permissions(discord), expected);
}

#[test]
fn map_discord_perms_unmapped_bit_produces_zero() {
    // 0x80 = VIEW_AUDIT_LOG in Discord — not mapped in Accord Phase 1
    assert_eq!(map_discord_permissions(0x80), 0);
}

#[test]
fn map_discord_perms_all_known_discord_bits() {
    // All 20 Discord bits that ARE mapped
    let all_discord: u64 = 0x1
        | 0x2
        | 0x4
        | 0x8
        | 0x10
        | 0x20
        | 0x40
        | 0x400
        | 0x800
        | 0x2000
        | 0x4000
        | 0x8000
        | 0x10000
        | 0x20000
        | 0x100000
        | 0x200000
        | 0x400000
        | 0x800000
        | 0x1000000
        | 0x10000000;

    let result = map_discord_permissions(all_discord);
    assert_eq!(
        result, ALL_PERMISSIONS,
        "mapping all 20 Discord bits should yield ALL_PERMISSIONS"
    );
}

// ────────────────────────────────────────────────────────────────
// ChannelType enum
// ────────────────────────────────────────────────────────────────

#[test]
fn channel_type_default_is_text() {
    assert_eq!(ChannelType::default(), ChannelType::Text);
}

#[test]
fn channel_type_from_i32_valid_values() {
    assert_eq!(ChannelType::from_i32(0), Some(ChannelType::Text));
    assert_eq!(ChannelType::from_i32(2), Some(ChannelType::Voice));
    assert_eq!(ChannelType::from_i32(4), Some(ChannelType::Category));
}

#[test]
fn channel_type_from_i32_invalid_values() {
    assert_eq!(ChannelType::from_i32(1), None);
    assert_eq!(ChannelType::from_i32(3), None);
    assert_eq!(ChannelType::from_i32(-1), None);
    assert_eq!(ChannelType::from_i32(99), None);
    assert_eq!(ChannelType::from_i32(i32::MIN), None);
    assert_eq!(ChannelType::from_i32(i32::MAX), None);
}

#[test]
fn channel_type_serde_roundtrip_all_variants() {
    for variant in [ChannelType::Text, ChannelType::Voice, ChannelType::Category] {
        let json = serde_json::to_string(&variant).expect("serialize ChannelType");
        let back: ChannelType = serde_json::from_str(&json).expect("deserialize ChannelType");
        assert_eq!(back, variant, "serde round-trip failed for {:?}", variant);
    }
}

#[test]
fn channel_type_text_serializes_as_variant_name() {
    // ChannelType derives Serialize without repr — serde emits the variant name.
    let json = serde_json::to_string(&ChannelType::Text).unwrap();
    assert_eq!(json, "\"Text\"");
}

#[test]
fn channel_type_voice_serializes_as_variant_name() {
    let json = serde_json::to_string(&ChannelType::Voice).unwrap();
    assert_eq!(json, "\"Voice\"");
}

#[test]
fn channel_type_category_serializes_as_variant_name() {
    let json = serde_json::to_string(&ChannelType::Category).unwrap();
    assert_eq!(json, "\"Category\"");
}

// ────────────────────────────────────────────────────────────────
// PushPlatform enum
// ────────────────────────────────────────────────────────────────

#[test]
fn push_platform_as_str_values() {
    assert_eq!(PushPlatform::Ios.as_str(), "ios");
    assert_eq!(PushPlatform::Android.as_str(), "android");
}

#[test]
fn push_platform_from_str_valid() {
    assert_eq!("ios".parse::<PushPlatform>().unwrap(), PushPlatform::Ios);
    assert_eq!(
        "android".parse::<PushPlatform>().unwrap(),
        PushPlatform::Android
    );
}

#[test]
fn push_platform_from_str_case_sensitive() {
    assert!("IOS".parse::<PushPlatform>().is_err());
    assert!("Android".parse::<PushPlatform>().is_err());
    assert!("ANDROID".parse::<PushPlatform>().is_err());
}

#[test]
fn push_platform_from_str_unknown() {
    let err = "windows".parse::<PushPlatform>().unwrap_err();
    assert!(
        err.contains("unknown platform"),
        "unexpected error message: {err}"
    );
}

#[test]
fn push_platform_as_str_roundtrip() {
    for p in [PushPlatform::Ios, PushPlatform::Android] {
        let s = p.as_str();
        let back: PushPlatform = s.parse().unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn push_platform_serde_roundtrip() {
    for p in [PushPlatform::Ios, PushPlatform::Android] {
        let json = serde_json::to_string(&p).unwrap();
        let back: PushPlatform = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }
}

#[test]
fn push_platform_serde_lowercase_strings() {
    // serde(rename_all = "lowercase") — serializes as bare lowercase string
    assert_eq!(
        serde_json::to_string(&PushPlatform::Ios).unwrap(),
        "\"ios\""
    );
    assert_eq!(
        serde_json::to_string(&PushPlatform::Android).unwrap(),
        "\"android\""
    );
}

// ────────────────────────────────────────────────────────────────
// NotificationPrivacy enum
// ────────────────────────────────────────────────────────────────

#[test]
fn notification_privacy_default_is_partial() {
    assert_eq!(NotificationPrivacy::default(), NotificationPrivacy::Partial);
}

#[test]
fn notification_privacy_as_str_values() {
    assert_eq!(NotificationPrivacy::Full.as_str(), "full");
    assert_eq!(NotificationPrivacy::Partial.as_str(), "partial");
    assert_eq!(NotificationPrivacy::Stealth.as_str(), "stealth");
}

#[test]
fn notification_privacy_from_str_valid() {
    assert_eq!(
        "full".parse::<NotificationPrivacy>().unwrap(),
        NotificationPrivacy::Full
    );
    assert_eq!(
        "partial".parse::<NotificationPrivacy>().unwrap(),
        NotificationPrivacy::Partial
    );
    assert_eq!(
        "stealth".parse::<NotificationPrivacy>().unwrap(),
        NotificationPrivacy::Stealth
    );
}

#[test]
fn notification_privacy_from_str_unknown() {
    let err = "none".parse::<NotificationPrivacy>().unwrap_err();
    assert!(
        err.contains("unknown privacy level"),
        "unexpected error: {err}"
    );
}

#[test]
fn notification_privacy_as_str_roundtrip() {
    for v in [
        NotificationPrivacy::Full,
        NotificationPrivacy::Partial,
        NotificationPrivacy::Stealth,
    ] {
        let s = v.as_str();
        let back: NotificationPrivacy = s.parse().unwrap();
        assert_eq!(back, v);
    }
}

#[test]
fn notification_privacy_serde_roundtrip() {
    for v in [
        NotificationPrivacy::Full,
        NotificationPrivacy::Partial,
        NotificationPrivacy::Stealth,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: NotificationPrivacy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }
}

// ────────────────────────────────────────────────────────────────
// WsMessageType — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn ws_message_type_ping_serializes_to_string() {
    let json = serde_json::to_string(&WsMessageType::Ping).unwrap();
    assert_eq!(json, "\"Ping\"");
}

#[test]
fn ws_message_type_pong_deserializes_from_string() {
    let msg: WsMessageType = serde_json::from_str("\"Pong\"").unwrap();
    assert!(matches!(msg, WsMessageType::Pong));
}

#[test]
fn ws_message_type_roundtrip_join_node() {
    let id = Uuid::new_v4();
    let original = WsMessageType::JoinNode { node_id: id };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(back, WsMessageType::JoinNode { node_id } if node_id == id),
        "JoinNode round-trip failed"
    );
}

#[test]
fn ws_message_type_roundtrip_channel_message() {
    let id = Uuid::new_v4();
    let reply_id = Uuid::new_v4();
    let original = WsMessageType::ChannelMessage {
        channel_id: id,
        encrypted_data: "payload".to_string(),
        reply_to: Some(reply_id),
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(
            &back,
            WsMessageType::ChannelMessage { channel_id, encrypted_data, reply_to }
            if *channel_id == id
                && encrypted_data == "payload"
                && *reply_to == Some(reply_id)
        ),
        "ChannelMessage round-trip failed"
    );
}

#[test]
fn ws_message_type_roundtrip_channel_message_no_reply() {
    let id = Uuid::new_v4();
    let original = WsMessageType::ChannelMessage {
        channel_id: id,
        encrypted_data: "enc".to_string(),
        reply_to: None,
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(&back, WsMessageType::ChannelMessage { reply_to: None, .. }),
        "reply_to should round-trip as None"
    );
}

#[test]
fn ws_message_type_roundtrip_edit_message() {
    let msg_id = Uuid::new_v4();
    let original = WsMessageType::EditMessage {
        message_id: msg_id,
        encrypted_data: "new_enc".to_string(),
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(
            &back,
            WsMessageType::EditMessage { message_id, encrypted_data }
            if *message_id == msg_id && encrypted_data == "new_enc"
        ),
        "EditMessage round-trip failed"
    );
}

#[test]
fn ws_message_type_roundtrip_delete_message() {
    let msg_id = Uuid::new_v4();
    let original = WsMessageType::DeleteMessage { message_id: msg_id };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(matches!(&back, WsMessageType::DeleteMessage { message_id } if *message_id == msg_id));
}

#[test]
fn ws_message_type_roundtrip_voice_key_exchange() {
    let ch = Uuid::new_v4();
    let target = Uuid::new_v4();
    let original = WsMessageType::VoiceKeyExchange {
        channel_id: ch,
        wrapped_key: "base64key".to_string(),
        target_user_id: Some(target),
        sender_ssrc: 42,
        key_generation: 7,
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(
            &back,
            WsMessageType::VoiceKeyExchange {
                channel_id,
                sender_ssrc,
                key_generation,
                ..
            }
            if *channel_id == ch && *sender_ssrc == 42 && *key_generation == 7
        ),
        "VoiceKeyExchange round-trip failed"
    );
}

#[test]
fn ws_message_type_roundtrip_bot_response() {
    let original = WsMessageType::BotResponse {
        bot_id: "bot42".to_string(),
        invocation_id: "inv-1".to_string(),
        content: serde_json::json!({"key": "value", "num": 42}),
    };
    let json = serde_json::to_string(&original).unwrap();
    let back: WsMessageType = serde_json::from_str(&json).unwrap();
    assert!(
        matches!(
            &back,
            WsMessageType::BotResponse { bot_id, invocation_id, .. }
            if bot_id == "bot42" && invocation_id == "inv-1"
        ),
        "BotResponse round-trip failed"
    );
}

// ────────────────────────────────────────────────────────────────
// RegisterRequest — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn register_request_minimal_fields() {
    let json = r#"{"public_key":"pk1","password":"pw1"}"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.public_key, "pk1");
    assert_eq!(req.password, "pw1");
    assert_eq!(req.username, "", "username should default to empty string");
    assert_eq!(req.display_name, None);
}

#[test]
fn register_request_with_all_fields() {
    let json =
        r#"{"username":"ignored","public_key":"pk2","password":"pw2","display_name":"Alice"}"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.public_key, "pk2");
    assert_eq!(req.display_name, Some("Alice".to_string()));
}

#[test]
fn register_request_display_name_none() {
    let json = r#"{"public_key":"pk3","password":"pw3"}"#;
    let req: RegisterRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.display_name, None);
}

// ────────────────────────────────────────────────────────────────
// AuthRequest — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn auth_request_with_public_key() {
    let json = r#"{"password":"pw","public_key":"mykey"}"#;
    let req: AuthRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.password, "pw");
    assert_eq!(req.public_key, Some("mykey".to_string()));
    assert_eq!(req.public_key_hash, None);
    assert_eq!(req.username, "");
}

#[test]
fn auth_request_with_public_key_hash() {
    let json = r#"{"password":"pw","public_key_hash":"deadbeef"}"#;
    let req: AuthRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.public_key_hash, Some("deadbeef".to_string()));
    assert_eq!(req.public_key, None);
}

#[test]
fn auth_request_both_fields_none_when_absent() {
    let json = r#"{"password":"pw"}"#;
    let req: AuthRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.public_key, None);
    assert_eq!(req.public_key_hash, None);
}

// ────────────────────────────────────────────────────────────────
// CreateNodeRequest — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn create_node_request_with_description() {
    let json = r#"{"name":"My Server","description":"A cool place"}"#;
    let req: CreateNodeRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.name, "My Server");
    assert_eq!(req.description, Some("A cool place".to_string()));
}

#[test]
fn create_node_request_without_description() {
    let json = r#"{"name":"My Server"}"#;
    let req: CreateNodeRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.name, "My Server");
    assert_eq!(req.description, None);
}

// ────────────────────────────────────────────────────────────────
// EditMessageRequest — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn edit_message_request_deserialize() {
    let json = r#"{"encrypted_data":"base64blob"}"#;
    let req: EditMessageRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.encrypted_data, "base64blob");
}

// ────────────────────────────────────────────────────────────────
// BanUserRequest — serde (optional fields)
// ────────────────────────────────────────────────────────────────

#[test]
fn ban_user_request_minimal() {
    let json = r#"{"public_key_hash":"abc123"}"#;
    let req: BanUserRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.public_key_hash, "abc123");
    assert_eq!(req.reason_encrypted, None);
    assert_eq!(req.expires_at, None);
    assert_eq!(req.device_fingerprint_hash, None);
}

#[test]
fn ban_user_request_full() {
    let json = r#"{
        "public_key_hash":"abc123",
        "reason_encrypted":"encryptedReason",
        "expires_at":9999999999,
        "device_fingerprint_hash":"fp_hash"
    }"#;
    let req: BanUserRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.reason_encrypted, Some("encryptedReason".to_string()));
    assert_eq!(req.expires_at, Some(9999999999));
    assert_eq!(req.device_fingerprint_hash, Some("fp_hash".to_string()));
}

// ────────────────────────────────────────────────────────────────
// AuthResponse — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn auth_response_serialize() {
    let id = Uuid::nil();
    let resp = AuthResponse {
        token: "tok123".to_string(),
        user_id: id,
        expires_at: 1_700_000_000,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["token"], "tok123");
    assert_eq!(v["user_id"], id.to_string());
    assert_eq!(v["expires_at"], 1_700_000_000u64);
}

// ────────────────────────────────────────────────────────────────
// ErrorResponse — serde
// ────────────────────────────────────────────────────────────────

#[test]
fn error_response_serialize() {
    let resp = ErrorResponse {
        error: "resource not found".to_string(),
        code: 404,
    };
    let json = serde_json::to_string(&resp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["error"], "resource not found");
    assert_eq!(v["code"], 404);
}

// ────────────────────────────────────────────────────────────────
// PermissionDeniedResponse — constructor and fields
// ────────────────────────────────────────────────────────────────

#[test]
fn permission_denied_response_code_is_403() {
    let r = PermissionDeniedResponse::new("MANAGE_CHANNELS", "member");
    assert_eq!(r.code, 403);
}

#[test]
fn permission_denied_response_fields_correct() {
    let r = PermissionDeniedResponse::new("BAN_MEMBERS", "moderator");
    assert_eq!(r.required_permission, "BAN_MEMBERS");
    assert_eq!(r.user_role, "moderator");
    assert!(r.error.contains("BAN_MEMBERS"), "error: {}", r.error);
    assert!(r.error.contains("moderator"), "error: {}", r.error);
}

#[test]
fn permission_denied_response_serializes_all_fields() {
    let r = PermissionDeniedResponse::new("KICK_MEMBERS", "guest");
    let json = serde_json::to_string(&r).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["code"], 403);
    assert_eq!(v["required_permission"], "KICK_MEMBERS");
    assert_eq!(v["user_role"], "guest");
    assert!(v["error"].as_str().unwrap().contains("KICK_MEMBERS"));
}
