// CryptoService.swift — Wraps AccordCore FFI for end-to-end encryption

import Foundation
import CryptoKit

/// Manages cryptographic identity and encrypted sessions via AccordCore FFI.
@Observable
final class CryptoService {
    private let keyMaterial: KeyMaterial
    private let sessionManager: SessionManager

    /// Cache of derived symmetric channel keys (channelId → key)
    private var channelKeyCache: [String: SymmetricKey] = [:]

    init(keyMaterial: KeyMaterial) {
        self.keyMaterial = keyMaterial
        self.sessionManager = SessionManager()
    }

    /// Our public identity key (32 bytes).
    var identityKey: Data {
        get throws { try keyMaterial.identityKey }
    }

    /// Our public identity key as hex string (for API registration).
    var identityKeyHex: String {
        get throws {
            try keyMaterial.identityKey.map { String(format: "%02x", $0) }.joined()
        }
    }

    /// Bundle to publish to the relay so others can initiate sessions with us.
    var publishableBundle: Data {
        get throws { try keyMaterial.publishableBundle }
    }

    // MARK: - Key Bundle Publishing

    /// Publish our key bundle to the relay via API.
    func publishKeyBundle(api: APIService) async throws {
        let idKey = try keyMaterial.identityKey.base64EncodedString()
        let spk = try keyMaterial.signedPrekey.base64EncodedString()
        try await api.publishKeyBundle(identityKey: idKey, signedPrekey: spk)
    }

    // MARK: - Channel (Symmetric) Encryption

    /// Derive a deterministic AES-256-GCM key for a channel.
    /// Matches desktop: SHA256(channelId + ":" + token + ":" + identityKeyPrefix)
    func deriveChannelKey(channelId: String, token: String) throws -> SymmetricKey {
        if let cached = channelKeyCache[channelId] {
            return cached
        }
        let idKeyHex = try identityKeyHex
        let prefix = String(idKeyHex.prefix(32))
        let material = "\(channelId):\(token):\(prefix)"
        let hash = SHA256.hash(data: Data(material.utf8))
        let key = SymmetricKey(data: hash)
        channelKeyCache[channelId] = key
        return key
    }

    /// Encrypt a message for a group channel using symmetric AES-256-GCM.
    /// Returns base64-encoded (12-byte IV || ciphertext+tag).
    func encryptChannelMessage(_ plaintext: String, channelId: String, token: String) throws -> String {
        let key = try deriveChannelKey(channelId: channelId, token: token)
        guard let data = plaintext.data(using: .utf8) else {
            throw AccordError.invalidUtf8
        }
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(data, using: key, nonce: nonce)
        // Combined = nonce (12) + ciphertext + tag (16)
        guard let combined = sealed.combined else {
            throw AccordError.cryptoError
        }
        return combined.base64EncodedString()
    }

    /// Decrypt a channel message from base64-encoded AES-GCM ciphertext.
    func decryptChannelMessage(_ ciphertext: String, channelId: String, token: String) throws -> String {
        let key = try deriveChannelKey(channelId: channelId, token: token)
        guard let combined = Data(base64Encoded: ciphertext) else {
            throw AccordError.cryptoError
        }
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw AccordError.invalidUtf8
        }
        return text
    }

    func clearChannelKeyCache() {
        channelKeyCache.removeAll()
    }

    // MARK: - DM Session Management (Double Ratchet via FFI)

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

    /// Encrypt plaintext for an established DM session.
    func encrypt(peerUserId: String, channelId: String, plaintext: Data) throws -> Data {
        try sessionManager.encrypt(peerUserId: peerUserId, channelId: channelId, plaintext: plaintext)
    }

    /// Decrypt ciphertext from an established DM session.
    func decrypt(peerUserId: String, channelId: String, ciphertext: Data) throws -> Data {
        try sessionManager.decrypt(peerUserId: peerUserId, channelId: channelId, ciphertext: ciphertext)
    }

    // MARK: - DM Convenience

    /// Encrypt a DM string message, returning base64 ciphertext.
    func encryptDMMessage(_ text: String, peerUserId: String, channelId: String) throws -> String {
        guard let plaintext = text.data(using: .utf8) else {
            throw AccordError.invalidUtf8
        }
        let ciphertext = try encrypt(peerUserId: peerUserId, channelId: channelId, plaintext: plaintext)
        return ciphertext.base64EncodedString()
    }

    /// Decrypt base64 DM ciphertext to a string.
    func decryptDMMessage(_ ciphertextB64: String, peerUserId: String, channelId: String) throws -> String {
        guard let ciphertext = Data(base64Encoded: ciphertextB64) else {
            throw AccordError.cryptoError
        }
        let plaintext = try decrypt(peerUserId: peerUserId, channelId: channelId, ciphertext: ciphertext)
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw AccordError.invalidUtf8
        }
        return text
    }

    /// Establish a DM session with a peer by fetching their bundle from the API,
    /// then send the first encrypted message.
    func establishAndEncryptDM(
        _ text: String,
        peerUserId: String,
        channelId: String,
        api: APIService
    ) async throws -> String {
        guard let plaintext = text.data(using: .utf8) else {
            throw AccordError.invalidUtf8
        }

        if hasSession(peerUserId: peerUserId, channelId: channelId) {
            // Existing session — just encrypt
            let ciphertext = try encrypt(peerUserId: peerUserId, channelId: channelId, plaintext: plaintext)
            return ciphertext.base64EncodedString()
        }

        // Need to establish session via X3DH
        let bundleDTO = try await api.fetchKeyBundle(userId: peerUserId)

        // Reconstruct the serialized bundle from DTO
        guard let ikData = Data(base64Encoded: bundleDTO.identity_key),
              let spkData = Data(base64Encoded: bundleDTO.signed_prekey) else {
            throw AccordError.cryptoError
        }
        let opkData = bundleDTO.one_time_prekey.flatMap { Data(base64Encoded: $0) }
        let theirBundle = try serializePreKeyBundle(
            identityKey: ikData,
            signedPrekey: spkData,
            oneTimePrekey: opkData
        )

        let initialMessage = try initiateSession(
            peerUserId: peerUserId,
            channelId: channelId,
            theirBundle: theirBundle,
            firstMessage: plaintext
        )
        return initialMessage.base64EncodedString()
    }
}
