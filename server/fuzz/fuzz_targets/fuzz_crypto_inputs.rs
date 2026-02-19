#![no_main]
use libfuzzer_sys::fuzz_target;

use accord_core::protocol::MessageSerializer;

/// Fuzz crypto and protocol input parsing in accord-core.
///
/// Targets:
/// 1. Protocol message deserialization (bincode) — the NetworkMessage format
///    used for internal protocol framing. Malformed bytes must not panic.
/// 2. DoubleRatchetMessage deserialization — ensuring malformed ciphertext
///    envelope bytes don't cause panics.
fuzz_target!(|data: &[u8]| {
    // 1. Protocol message deserialization (bincode-based)
    //    This is the core wire format — any bytes from the network go through here.
    let _ = MessageSerializer::deserialize(data);

    // 2. Try deserializing as a DoubleRatchetMessage (serde/bincode)
    //    In production, encrypted message blobs are decoded from base64 then
    //    deserialized. Feed raw bytes to ensure no panics.
    let _ = bincode::deserialize::<accord_core::double_ratchet::DoubleRatchetMessage>(data);

    // 3. Try deserializing a MessageHeader
    let _ = bincode::deserialize::<accord_core::double_ratchet::MessageHeader>(data);

    // 4. Base64 decode + deserialize chain (simulates real input path)
    //    Clients send base64-encoded encrypted blobs; server decodes then processes.
    if let Ok(decoded) = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        data,
    ) {
        let _ = MessageSerializer::deserialize(&decoded);
        let _ = bincode::deserialize::<accord_core::double_ratchet::DoubleRatchetMessage>(&decoded);
    }
});
