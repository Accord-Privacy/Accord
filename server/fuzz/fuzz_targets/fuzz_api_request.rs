#![no_main]
use libfuzzer_sys::fuzz_target;

use accord_server::models::{
    AuthRequest, CreateNodeRequest, EditMessageRequest, RegisterRequest,
    CreateInviteRequest, BanUserRequest, SendFriendRequestRequest,
    PublishKeyBundleRequest, StorePrekeyMessageRequest, RegisterDeviceTokenRequest,
    CreateRoleRequest, UpdateRoleRequest, SetChannelOverwriteRequest,
    AddAutoModWordRequest, SetSlowModeRequest, SetNodeUserProfileRequest,
};
use accord_server::validation;

/// Fuzz HTTP JSON request body deserialization for all critical API endpoints.
///
/// These are the structs that axum's `Json<T>` extractor deserializes from
/// untrusted HTTP request bodies. None should panic on arbitrary input.
fuzz_target!(|data: &[u8]| {
    // Auth endpoints
    let _ = serde_json::from_slice::<RegisterRequest>(data);
    let _ = serde_json::from_slice::<AuthRequest>(data);

    // Node/channel management
    let _ = serde_json::from_slice::<CreateNodeRequest>(data);
    let _ = serde_json::from_slice::<CreateInviteRequest>(data);
    let _ = serde_json::from_slice::<EditMessageRequest>(data);

    // Moderation
    let _ = serde_json::from_slice::<BanUserRequest>(data);
    let _ = serde_json::from_slice::<SendFriendRequestRequest>(data);

    // Key exchange
    let _ = serde_json::from_slice::<PublishKeyBundleRequest>(data);
    let _ = serde_json::from_slice::<StorePrekeyMessageRequest>(data);

    // Push notifications
    let _ = serde_json::from_slice::<RegisterDeviceTokenRequest>(data);

    // Roles & permissions
    let _ = serde_json::from_slice::<CreateRoleRequest>(data);
    let _ = serde_json::from_slice::<UpdateRoleRequest>(data);
    let _ = serde_json::from_slice::<SetChannelOverwriteRequest>(data);

    // Auto-mod
    let _ = serde_json::from_slice::<AddAutoModWordRequest>(data);
    let _ = serde_json::from_slice::<SetSlowModeRequest>(data);
    let _ = serde_json::from_slice::<SetNodeUserProfileRequest>(data);

    // Validation functions (take string input from untrusted sources)
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = validation::validate_username(s);
        let _ = validation::validate_node_name(s);
        let _ = validation::validate_channel_name(s);
        let _ = validation::validate_display_name(s);
        let _ = validation::validate_bio(s);
        let _ = validation::validate_emoji(s);
        let _ = validation::validate_invite_code(s);
    }
    let _ = validation::validate_message_size(data);
});
