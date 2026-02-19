// CryptoService.swift — Wraps AccordCore FFI for end-to-end encryption

import Foundation

/// Manages cryptographic identity and encrypted sessions via AccordCore FFI.
@Observable
final class CryptoService {
    private let keyMaterial: KeyMaterial
    private let sessionManager: SessionManager

    init(keyMaterial: KeyMaterial) {
        self.keyMaterial = keyMaterial
        self.sessionManager = SessionManager()
    }

    /// Our public identity key (32 bytes).
    var identityKey: Data {
        get throws { try keyMaterial.identityKey }
    }

    /// Bundle to publish to the relay so others can initiate sessions with us.
    var publishableBundle: Data {
        get throws { try keyMaterial.publishableBundle }
    }

    // MARK: - Session Management

    func hasSession(peerUserId: String, channelId: String) -> Bool {
        sessionManager.hasSession(peerUserId: peerUserId, channelId: channelId)
    }

    /// Initiate an encrypted session with a peer. Returns the initial message to send.
    func initiateSession(
        peerUserId: String,
        channelId: String,
        theirBundle: Data,
        firstMessage: Data
    ) throws -> Data {
        try sessionManager.initiateSession(
            keyMaterial: keyMaterial,
            peerUserId: peerUserId,
            channelId: channelId,
            theirBundle: theirBundle,
            firstMessage: firstMessage
        )
    }

    /// Receive an initial session message from a peer. Returns decrypted plaintext.
    func receiveInitialMessage(
        peerUserId: String,
        channelId: String,
        initialMessage: Data
    ) throws -> Data {
        try sessionManager.receiveInitialMessage(
            keyMaterial: keyMaterial,
            peerUserId: peerUserId,
            channelId: channelId,
            initialMessage: initialMessage
        )
    }

    /// Encrypt plaintext for an established session.
    func encrypt(peerUserId: String, channelId: String, plaintext: Data) throws -> Data {
        try sessionManager.encrypt(peerUserId: peerUserId, channelId: channelId, plaintext: plaintext)
    }

    /// Decrypt ciphertext from an established session.
    func decrypt(peerUserId: String, channelId: String, ciphertext: Data) throws -> Data {
        try sessionManager.decrypt(peerUserId: peerUserId, channelId: channelId, ciphertext: ciphertext)
    }

    // MARK: - Convenience

    /// Encrypt a string message, returning ciphertext data.
    func encryptMessage(_ text: String, peerUserId: String, channelId: String) throws -> Data {
        guard let plaintext = text.data(using: .utf8) else {
            throw AccordError.invalidUtf8
        }
        return try encrypt(peerUserId: peerUserId, channelId: channelId, plaintext: plaintext)
    }

    /// Decrypt ciphertext data to a string.
    func decryptMessage(_ ciphertext: Data, peerUserId: String, channelId: String) throws -> String {
        let plaintext = try decrypt(peerUserId: peerUserId, channelId: channelId, ciphertext: ciphertext)
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw AccordError.invalidUtf8
        }
        return text
    }
}
