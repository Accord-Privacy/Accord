//! External integration tests for the webhooks module — pure/testable functions only.
//!
//! Covers:
//!   - `validate_events()` — valid, invalid, empty, mixed, duplicates
//!   - `compute_hmac_sha256()` — RFC 4231 vectors, edge cases, key/data variance
//!   - `Webhook` struct serde round-trip
//!   - `CreateWebhookRequest` / `UpdateWebhookRequest` deserialization
//!   - `WebhookPayload` serialization

#![allow(clippy::all)]

use accord_server::webhooks::{
    compute_hmac_sha256, validate_events, CreateWebhookRequest, UpdateWebhookRequest, Webhook,
    WebhookPayload,
};
use serde_json::json;
use uuid::Uuid;

// ============================================================================
// Group 1 — validate_events
// ============================================================================

#[test]
fn validate_single_valid_event() {
    let events = vec!["message_create".to_string()];
    assert!(validate_events(&events).is_ok());
}

#[test]
fn validate_all_valid_event_types() {
    let all = vec![
        "message_create".to_string(),
        "message_delete".to_string(),
        "member_join".to_string(),
        "member_leave".to_string(),
        "reaction_add".to_string(),
    ];
    assert!(validate_events(&all).is_ok());
}

#[test]
fn validate_each_event_individually() {
    let valid = [
        "message_create",
        "message_delete",
        "member_join",
        "member_leave",
        "reaction_add",
    ];
    for event in valid {
        let events = vec![event.to_string()];
        assert!(
            validate_events(&events).is_ok(),
            "'{}' should be a valid event type",
            event
        );
    }
}

#[test]
fn validate_empty_list_returns_error() {
    let events: Vec<String> = vec![];
    let err = validate_events(&events).unwrap_err();
    assert!(
        err.contains("at least one event"),
        "Expected 'at least one event' in error, got: {}",
        err
    );
}

#[test]
fn validate_single_invalid_event_returns_error() {
    let events = vec!["not_a_real_event".to_string()];
    let err = validate_events(&events).unwrap_err();
    assert!(err.contains("Invalid event type"), "got: {}", err);
    assert!(err.contains("not_a_real_event"), "got: {}", err);
}

#[test]
fn validate_mixed_valid_and_invalid_returns_error() {
    let events = vec!["message_create".to_string(), "bogus_event".to_string()];
    let err = validate_events(&events).unwrap_err();
    assert!(err.contains("bogus_event"), "got: {}", err);
}

#[test]
fn validate_duplicate_valid_events_ok() {
    // Duplicates aren't explicitly disallowed by validate_events — both are valid strings
    let events = vec!["message_create".to_string(), "message_create".to_string()];
    assert!(
        validate_events(&events).is_ok(),
        "duplicate valid events should pass validation"
    );
}

#[test]
fn validate_invalid_event_error_mentions_valid_types() {
    let events = vec!["channel_create".to_string()];
    let err = validate_events(&events).unwrap_err();
    // The error should mention valid types in some form
    assert!(err.contains("Valid types"), "got: {}", err);
}

#[test]
fn validate_case_sensitive_rejection() {
    // Event names are case-sensitive; uppercase should fail
    let events = vec!["Message_Create".to_string()];
    let err = validate_events(&events).unwrap_err();
    assert!(err.contains("Invalid event type"), "got: {}", err);
}

// ============================================================================
// Group 2 — compute_hmac_sha256
// ============================================================================

#[test]
fn hmac_rfc4231_test_case_2() {
    // RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let result = compute_hmac_sha256(key, data);
    assert_eq!(
        result,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn hmac_output_is_64_hex_chars() {
    let result = compute_hmac_sha256(b"any-key", b"any-data");
    assert_eq!(result.len(), 64, "SHA-256 hex output must be 64 characters");
    assert!(
        result.chars().all(|c| c.is_ascii_hexdigit()),
        "Output must be lowercase hex"
    );
}

#[test]
fn hmac_empty_key_empty_message_is_deterministic() {
    let a = compute_hmac_sha256(b"", b"");
    let b = compute_hmac_sha256(b"", b"");
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn hmac_empty_key_nonempty_message() {
    let result = compute_hmac_sha256(b"", b"hello world");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hmac_nonempty_key_empty_message() {
    let result = compute_hmac_sha256(b"secret-key", b"");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hmac_same_inputs_same_output() {
    let key = b"webhook-signing-secret";
    let data = b"{\"event\":\"message_create\"}";
    let first = compute_hmac_sha256(key, data);
    let second = compute_hmac_sha256(key, data);
    assert_eq!(
        first, second,
        "Same inputs must always produce the same HMAC"
    );
}

#[test]
fn hmac_different_keys_produce_different_outputs() {
    let data = b"same payload for both";
    let a = compute_hmac_sha256(b"key-alpha", data);
    let b = compute_hmac_sha256(b"key-beta", data);
    assert_ne!(a, b, "Different keys must produce different HMACs");
}

#[test]
fn hmac_different_data_produce_different_outputs() {
    let key = b"shared-key";
    let a = compute_hmac_sha256(key, b"payload-one");
    let b = compute_hmac_sha256(key, b"payload-two");
    assert_ne!(a, b, "Different data must produce different HMACs");
}

#[test]
fn hmac_long_key_over_block_size_works() {
    // Keys longer than 64 bytes (SHA-256 block size) are hashed before use
    let long_key = vec![0xABu8; 128];
    let result = compute_hmac_sha256(&long_key, b"test data");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn hmac_long_key_vs_short_key_differ() {
    let data = b"identical payload";
    let short = compute_hmac_sha256(b"short", data);
    let long = compute_hmac_sha256(&vec![0x73u8; 128], data); // 's' * 128
    assert_ne!(short, long);
}

#[test]
fn hmac_binary_data_payload() {
    // Should handle non-UTF8 binary data without panicking
    let key = b"binary-key";
    let data: Vec<u8> = (0u8..=255).collect();
    let result = compute_hmac_sha256(key, &data);
    assert_eq!(result.len(), 64);
}

#[test]
fn hmac_key_exactly_block_size() {
    // Key exactly 64 bytes — exercises the non-hashed path
    let key = vec![0x42u8; 64];
    let result = compute_hmac_sha256(&key, b"exactly at block boundary");
    assert_eq!(result.len(), 64);
    assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
}

// ============================================================================
// Group 3 — Webhook struct serde
// ============================================================================

#[test]
fn webhook_serialize_deserialize_roundtrip_no_channel() {
    let id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let created_by = Uuid::new_v4();

    let webhook = Webhook {
        id,
        node_id,
        channel_id: None,
        url: "https://example.com/webhook-endpoint".to_string(),
        secret: "s3cr3t-key-1234".to_string(),
        events: "message_create,member_join".to_string(),
        created_by,
        created_at: 1_700_000_000,
        active: true,
    };

    let json_str = serde_json::to_string(&webhook).expect("serialization failed");
    let restored: Webhook = serde_json::from_str(&json_str).expect("deserialization failed");

    assert_eq!(restored.id, id);
    assert_eq!(restored.node_id, node_id);
    assert_eq!(restored.channel_id, None);
    assert_eq!(restored.url, "https://example.com/webhook-endpoint");
    assert_eq!(restored.secret, "s3cr3t-key-1234");
    assert_eq!(restored.events, "message_create,member_join");
    assert_eq!(restored.created_by, created_by);
    assert_eq!(restored.created_at, 1_700_000_000u64);
    assert!(restored.active);
}

#[test]
fn webhook_serialize_deserialize_roundtrip_with_channel() {
    let channel_id = Uuid::new_v4();
    let webhook = Webhook {
        id: Uuid::new_v4(),
        node_id: Uuid::new_v4(),
        channel_id: Some(channel_id),
        url: "https://hooks.example.org/receive".to_string(),
        secret: "channel-secret".to_string(),
        events: "reaction_add".to_string(),
        created_by: Uuid::new_v4(),
        created_at: 1_234_567_890,
        active: false,
    };

    let json_str = serde_json::to_string(&webhook).unwrap();
    let restored: Webhook = serde_json::from_str(&json_str).unwrap();

    assert_eq!(restored.channel_id, Some(channel_id));
    assert!(!restored.active);
}

#[test]
fn webhook_deserialize_from_json_literal() {
    let id = Uuid::new_v4();
    let node_id = Uuid::new_v4();
    let created_by = Uuid::new_v4();

    let json_val = json!({
        "id": id,
        "node_id": node_id,
        "channel_id": null,
        "url": "https://hooks.example.com/v2",
        "secret": "hmac-secret-abc",
        "events": "message_delete,member_leave",
        "created_by": created_by,
        "created_at": 1_600_000_000u64,
        "active": true
    });

    let webhook: Webhook = serde_json::from_value(json_val).expect("deserialization failed");
    assert_eq!(webhook.id, id);
    assert_eq!(webhook.url, "https://hooks.example.com/v2");
    assert_eq!(webhook.channel_id, None);
    assert_eq!(webhook.events, "message_delete,member_leave");
}

#[test]
fn webhook_serializes_channel_id_as_uuid_string() {
    let channel_id = Uuid::new_v4();
    let webhook = Webhook {
        id: Uuid::new_v4(),
        node_id: Uuid::new_v4(),
        channel_id: Some(channel_id),
        url: "https://example.com/".to_string(),
        secret: "s".to_string(),
        events: "message_create".to_string(),
        created_by: Uuid::new_v4(),
        created_at: 0,
        active: true,
    };

    let val = serde_json::to_value(&webhook).unwrap();
    let cid_str = val["channel_id"]
        .as_str()
        .expect("channel_id should be a string");
    assert_eq!(cid_str, channel_id.to_string());
}

// ============================================================================
// Group 4 — CreateWebhookRequest deserialization
// ============================================================================

#[test]
fn create_request_minimal_url_and_events() {
    let json_val = json!({
        "url": "https://example.com/webhook",
        "events": ["message_create"]
    });

    let req: CreateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.url, "https://example.com/webhook");
    assert_eq!(req.events, vec!["message_create"]);
    assert!(req.channel_id.is_none());
    assert!(req.secret.is_none());
}

#[test]
fn create_request_all_fields_populated() {
    let channel_id = Uuid::new_v4();
    let json_val = json!({
        "url": "https://example.com/webhook",
        "events": ["message_create", "member_join", "reaction_add"],
        "channel_id": channel_id,
        "secret": "custom-hmac-secret"
    });

    let req: CreateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.events.len(), 3);
    assert_eq!(req.channel_id, Some(channel_id));
    assert_eq!(req.secret.as_deref(), Some("custom-hmac-secret"));
}

#[test]
fn create_request_explicit_null_channel_id() {
    let json_val = json!({
        "url": "https://example.com/hook",
        "events": ["message_delete"],
        "channel_id": null
    });

    let req: CreateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert!(req.channel_id.is_none());
}

#[test]
fn create_request_multiple_events() {
    let json_val = json!({
        "url": "https://example.com/all",
        "events": ["message_create", "message_delete", "member_join", "member_leave", "reaction_add"]
    });

    let req: CreateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.events.len(), 5);
}

#[test]
fn create_request_empty_events_vec() {
    // Deserialization should succeed even if events is empty (validation is a separate step)
    let json_val = json!({
        "url": "https://example.com/hook",
        "events": []
    });

    let req: CreateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert!(req.events.is_empty());
}

// ============================================================================
// Group 5 — UpdateWebhookRequest deserialization
// ============================================================================

#[test]
fn update_request_empty_object_all_none() {
    let json_val = json!({});
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert!(req.url.is_none());
    assert!(req.events.is_none());
    assert!(req.channel_id.is_none());
    assert!(req.secret.is_none());
    assert!(req.active.is_none());
}

#[test]
fn update_request_url_only() {
    let json_val = json!({ "url": "https://new-endpoint.example.com/hook" });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(
        req.url.as_deref(),
        Some("https://new-endpoint.example.com/hook")
    );
    assert!(req.events.is_none());
    assert!(req.active.is_none());
}

#[test]
fn update_request_active_false() {
    let json_val = json!({ "active": false });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.active, Some(false));
    assert!(req.url.is_none());
}

#[test]
fn update_request_active_true() {
    let json_val = json!({ "active": true });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.active, Some(true));
}

#[test]
fn update_request_events_only() {
    let json_val = json!({ "events": ["message_create", "reaction_add"] });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(
        req.events.as_deref(),
        Some(&["message_create".to_string(), "reaction_add".to_string()][..])
    );
}

#[test]
fn update_request_secret_only() {
    let json_val = json!({ "secret": "new-signing-secret" });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.secret.as_deref(), Some("new-signing-secret"));
}

#[test]
fn update_request_channel_id_uuid() {
    let cid = Uuid::new_v4();
    let json_val = json!({ "channel_id": cid });
    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.channel_id, Some(cid));
}

#[test]
fn update_request_all_fields() {
    let cid = Uuid::new_v4();
    let json_val = json!({
        "url": "https://updated.example.com/hook",
        "events": ["member_join"],
        "channel_id": cid,
        "secret": "updated-secret",
        "active": true
    });

    let req: UpdateWebhookRequest = serde_json::from_value(json_val).unwrap();
    assert_eq!(req.url.as_deref(), Some("https://updated.example.com/hook"));
    assert!(req.events.is_some());
    assert_eq!(req.channel_id, Some(cid));
    assert_eq!(req.secret.as_deref(), Some("updated-secret"));
    assert_eq!(req.active, Some(true));
}

// ============================================================================
// Group 6 — WebhookPayload serialization
// ============================================================================

#[test]
fn webhook_payload_top_level_fields() {
    let payload = WebhookPayload {
        event: "message_create".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        data: json!({ "content": "Hello" }),
    };

    let val = serde_json::to_value(&payload).unwrap();
    let obj = val.as_object().unwrap();

    assert_eq!(obj.len(), 3, "payload must have exactly 3 top-level fields");
    assert!(obj.contains_key("event"));
    assert!(obj.contains_key("timestamp"));
    assert!(obj.contains_key("data"));
}

#[test]
fn webhook_payload_event_field_preserved() {
    let payload = WebhookPayload {
        event: "member_leave".to_string(),
        timestamp: "2024-06-15T12:00:00Z".to_string(),
        data: json!({}),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert_eq!(val["event"], "member_leave");
}

#[test]
fn webhook_payload_timestamp_field_preserved() {
    let ts = "2024-03-20T08:30:00+00:00";
    let payload = WebhookPayload {
        event: "reaction_add".to_string(),
        timestamp: ts.to_string(),
        data: json!(null),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert_eq!(val["timestamp"], ts);
}

#[test]
fn webhook_payload_data_nested_values() {
    let payload = WebhookPayload {
        event: "message_create".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        data: json!({
            "message_id": "abc-123",
            "content": "Hello, world!",
            "user_id": "user-uuid",
            "channel_id": "chan-uuid"
        }),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert_eq!(val["data"]["message_id"], "abc-123");
    assert_eq!(val["data"]["content"], "Hello, world!");
}

#[test]
fn webhook_payload_empty_data_object() {
    let payload = WebhookPayload {
        event: "member_join".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        data: json!({}),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert!(val["data"].as_object().unwrap().is_empty());
}

#[test]
fn webhook_payload_json_string_is_valid() {
    let payload = WebhookPayload {
        event: "reaction_add".to_string(),
        timestamp: "2024-03-20T08:30:00Z".to_string(),
        data: json!({ "emoji": "thumbsup", "user_id": "u123" }),
    };

    let json_str = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["event"], "reaction_add");
    assert_eq!(parsed["data"]["emoji"], "thumbsup");
}

#[test]
fn webhook_payload_data_can_be_null() {
    let payload = WebhookPayload {
        event: "test".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        data: json!(null),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert!(val["data"].is_null());
}

#[test]
fn webhook_payload_data_can_be_array() {
    let payload = WebhookPayload {
        event: "batch".to_string(),
        timestamp: "2024-01-01T00:00:00Z".to_string(),
        data: json!(["item1", "item2", "item3"]),
    };

    let val = serde_json::to_value(&payload).unwrap();
    assert!(val["data"].is_array());
    assert_eq!(val["data"].as_array().unwrap().len(), 3);
}
