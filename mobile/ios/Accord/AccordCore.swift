// AccordCore.swift — Swift wrapper around accord-core FFI
// Provides a safe, idiomatic Swift API for the Accord crypto engine.

import Foundation
import AccordCoreFFI

// MARK: - Error types

public enum AccordError: Error, CustomStringConvertible {
    case nullPointer
    case invalidUtf8
    case cryptoError
    case serializationError
    case noSession
    case unknown(Int32)

    init(code: Int32) {
        switch code {
        case -1: self = .nullPointer
        case -2: self = .invalidUtf8
        case -3: self = .cryptoError
        case -4: self = .serializationError
        case -5: self = .noSession
        default: self = .unknown(code)
        }
    }

    public var description: String {
        switch self {
        case .nullPointer: return "Null pointer passed to FFI"
        case .invalidUtf8: return "Invalid UTF-8 string"
        case .cryptoError: return "Cryptographic operation failed"
        case .serializationError: return "Serialization failed"
        case .noSession: return "No session found"
        case .unknown(let code): return "Unknown error (code: \(code))"
        }
    }
}

// MARK: - Buffer helper

/// Safely extract Data from an AccordBuffer and free it.
private func consumeBuffer(_ buf: UnsafeMutablePointer<AccordBuffer>?) throws -> Data {
    guard let buf = buf else {
        throw AccordError.cryptoError
    }
    defer { accord_buffer_free(buf) }
    guard let data = buf.pointee.data else {
        throw AccordError.nullPointer
    }
    return Data(bytes: data, count: buf.pointee.len)
}

// MARK: - KeyMaterial

/// Wrapper around local cryptographic key material.
/// Manages identity key, signed prekey, and one-time prekeys.
public final class KeyMaterial {
    let raw: UnsafeMutablePointer<AccordKeyMaterial>

    /// Generate fresh key material.
    /// - Parameter oneTimePrekeys: Number of one-time prekeys to generate (default: 10)
    public init(oneTimePrekeys: UInt32 = 10) {
        self.raw = accord_keymaterial_generate(oneTimePrekeys)
    }

    deinit {
        accord_keymaterial_free(raw)
    }

    /// The 32-byte identity public key.
    public var identityKey: Data {
        get throws {
            try consumeBuffer(accord_keymaterial_identity_key(raw))
        }
    }

    /// The 32-byte signed prekey public key.
    public var signedPrekey: Data {
        get throws {
            try consumeBuffer(accord_keymaterial_signed_prekey(raw))
        }
    }

    /// Serialized publishable key bundle (for uploading to server).
    public var publishableBundle: Data {
        get throws {
            try consumeBuffer(accord_keymaterial_publishable_bundle(raw))
        }
    }
}

// MARK: - PreKeyBundle serialization

/// Serialize a PreKeyBundle from raw key components.
public func serializePreKeyBundle(
    identityKey: Data,
    signedPrekey: Data,
    oneTimePrekey: Data? = nil
) throws -> Data {
    return try identityKey.withUnsafeBytes { ikPtr in
        try signedPrekey.withUnsafeBytes { spkPtr in
            let ikBase = ikPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let spkBase = spkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)

            if let opk = oneTimePrekey {
                return try opk.withUnsafeBytes { opkPtr in
                    let opkBase = opkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    return try consumeBuffer(
                        accord_prekey_bundle_serialize(ikBase, spkBase, opkBase)
                    )
                }
            } else {
                return try consumeBuffer(
                    accord_prekey_bundle_serialize(ikBase, spkBase, nil)
                )
            }
        }
    }
}

// MARK: - SessionManager

/// Manages encrypted Double Ratchet sessions with peers.
/// Thread-safety: NOT thread-safe. Use from a single serial queue.
public final class SessionManager {
    private let raw: UnsafeMutablePointer<AccordSessionManager>

    public init() {
        self.raw = accord_session_manager_new()
    }

    deinit {
        accord_session_manager_free(raw)
    }

    /// Check if a session exists for the given peer and channel.
    public func hasSession(peerUserId: String, channelId: String) -> Bool {
        let result = accord_session_manager_has_session(raw, peerUserId, channelId)
        return result == 1
    }

    /// Initiate a new session (Alice's side).
    /// Returns the serialized X3DH initial message to send to the peer.
    public func initiateSession(
        keyMaterial: KeyMaterial,
        peerUserId: String,
        channelId: String,
        theirBundle: Data,
        firstMessage: Data
    ) throws -> Data {
        return try theirBundle.withUnsafeBytes { bundlePtr in
            try firstMessage.withUnsafeBytes { msgPtr in
                let bundleBase = bundlePtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                let msgBase = msgPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return try consumeBuffer(
                    accord_session_manager_initiate(
                        raw,
                        keyMaterial.raw,
                        peerUserId,
                        channelId,
                        bundleBase,
                        theirBundle.count,
                        msgBase,
                        firstMessage.count
                    )
                )
            }
        }
    }

    /// Receive an initial X3DH message (Bob's side) and establish a session.
    /// Returns the decrypted first message.
    public func receiveInitialMessage(
        keyMaterial: KeyMaterial,
        peerUserId: String,
        channelId: String,
        initialMessage: Data
    ) throws -> Data {
        return try initialMessage.withUnsafeBytes { msgPtr in
            let msgBase = msgPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return try consumeBuffer(
                accord_session_manager_receive_initial(
                    raw,
                    keyMaterial.raw,
                    peerUserId,
                    channelId,
                    msgBase,
                    initialMessage.count
                )
            )
        }
    }

    /// Encrypt a message for an established session.
    /// Returns the serialized DoubleRatchetMessage.
    public func encrypt(
        peerUserId: String,
        channelId: String,
        plaintext: Data
    ) throws -> Data {
        return try plaintext.withUnsafeBytes { ptr in
            let base = ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return try consumeBuffer(
                accord_session_manager_encrypt(
                    raw,
                    peerUserId,
                    channelId,
                    base,
                    plaintext.count
                )
            )
        }
    }

    /// Decrypt a message from an established session.
    /// Returns the plaintext.
    public func decrypt(
        peerUserId: String,
        channelId: String,
        ciphertext: Data
    ) throws -> Data {
        return try ciphertext.withUnsafeBytes { ptr in
            let base = ptr.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return try consumeBuffer(
                accord_session_manager_decrypt(
                    raw,
                    peerUserId,
                    channelId,
                    base,
                    ciphertext.count
                )
            )
        }
    }
}
