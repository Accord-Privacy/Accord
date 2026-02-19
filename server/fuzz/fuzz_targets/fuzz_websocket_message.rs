#![no_main]
use libfuzzer_sys::fuzz_target;

/// Fuzz the WebSocket message (WsMessage) JSON deserialization path.
///
/// In production, incoming WebSocket text frames are deserialized as
/// `WsMessage` via serde_json. This target feeds arbitrary bytes through
/// that same path to ensure no panics on malformed input.
fuzz_target!(|data: &[u8]| {
    // Attempt to parse as UTF-8 string first (WS text frames are UTF-8)
    if let Ok(text) = std::str::from_utf8(data) {
        // Try deserializing as WsMessage — the primary untrusted input path
        let _ = serde_json::from_str::<accord_server::models::WsMessage>(text);

        // Also try just the message type enum directly
        let _ = serde_json::from_str::<accord_server::models::WsMessageType>(text);
    }

    // Also try from raw bytes (binary WS frames)
    let _ = serde_json::from_slice::<accord_server::models::WsMessage>(data);
});
