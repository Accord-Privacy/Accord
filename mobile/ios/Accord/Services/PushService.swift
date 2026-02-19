// PushService.swift — Privacy-first push notification handling for Accord
//
// Supports 3 privacy levels:
//   - Full: sender name + message preview (from encrypted metadata)
//   - Sender-only: "Message from [name]"
//   - Minimal: "New message" (default — most private)

import Foundation
import UserNotifications
import UIKit
import CryptoKit

// MARK: - Privacy Level

enum PushPrivacyLevel: String, CaseIterable, Codable {
    case full = "full"
    case senderOnly = "sender_only"
    case minimal = "minimal"

    var displayName: String {
        switch self {
        case .full: return "Full"
        case .senderOnly: return "Sender Only"
        case .minimal: return "Minimal"
        }
    }

    var description: String {
        switch self {
        case .full: return "Show sender name and message preview"
        case .senderOnly: return "Show \"Message from [name]\" only"
        case .minimal: return "Show \"New message\" with no details"
        }
    }
}

// MARK: - Push Payload

struct PushPayload: Codable {
    let event: String
    let channelId: String?
    let nodeId: String?
    let count: Int?
    let senderName: String?
    let encryptedMetadata: String?

    enum CodingKeys: String, CodingKey {
        case event
        case channelId = "channel_id"
        case nodeId = "node_id"
        case count
        case senderName = "sender_name"
        case encryptedMetadata = "encrypted_metadata"
    }
}

// MARK: - Decrypted Push Metadata

struct PushMetadata: Codable {
    let senderName: String?
    let channelName: String?
    let preview: String?

    enum CodingKeys: String, CodingKey {
        case senderName = "sender_name"
        case channelName = "channel_name"
        case preview
    }
}

// MARK: - Push Service

@Observable
final class PushService: NSObject {
    static let shared = PushService()

    private(set) var isRegistered = false
    private(set) var deviceToken: String?
    private(set) var privacyLevel: PushPrivacyLevel = .minimal

    private var apiService: APIService?

    private let privacyLevelKey = "accord.push.privacyLevel"
    private let deviceTokenKey = "accord.push.deviceToken"

    private override init() {
        super.init()
        // Restore saved privacy level (default: minimal — most private)
        if let saved = UserDefaults.standard.string(forKey: privacyLevelKey),
           let level = PushPrivacyLevel(rawValue: saved) {
            privacyLevel = level
        }
    }

    // MARK: - Configuration

    func configure(apiService: APIService) {
        self.apiService = apiService
    }

    // MARK: - Registration

    func requestPermissionAndRegister() async {
        let center = UNUserNotificationCenter.current()

        do {
            let granted = try await center.requestAuthorization(options: [.alert, .badge, .sound])
            guard granted else { return }

            await MainActor.run {
                UIApplication.shared.registerForRemoteNotifications()
            }
        } catch {
            print("[PushService] Permission request failed: \(error)")
        }
    }

    func didRegisterForRemoteNotifications(deviceToken data: Data) {
        let token = data.map { String(format: "%02x", $0) }.joined()
        self.deviceToken = token
        UserDefaults.standard.set(token, forKey: deviceTokenKey)

        Task {
            await uploadToken(token)
        }
    }

    func didFailToRegisterForRemoteNotifications(error: Error) {
        print("[PushService] Failed to register for remote notifications: \(error)")
    }

    private func uploadToken(_ token: String) async {
        guard let api = apiService else { return }

        do {
            try await api.registerPushToken(
                platform: "ios",
                token: token,
                privacyLevel: privacyLevel.rawValue
            )
            isRegistered = true
        } catch {
            print("[PushService] Token upload failed: \(error)")
        }
    }

    // MARK: - Privacy Level

    func updatePrivacyLevel(_ level: PushPrivacyLevel) async {
        privacyLevel = level
        UserDefaults.standard.set(level.rawValue, forKey: privacyLevelKey)

        guard let api = apiService else { return }
        do {
            try await api.updatePushPrivacy(privacyLevel: level.rawValue)
        } catch {
            print("[PushService] Privacy level update failed: \(error)")
        }
    }

    // MARK: - Handle Incoming Push

    func handlePush(userInfo: [AnyHashable: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: userInfo),
              let payload = try? JSONDecoder().decode(PushPayload.self, from: data) else {
            // Minimal fallback
            showNotification(title: "Accord", body: "New message", channelId: nil)
            return
        }

        displayNotification(for: payload)
    }

    private func displayNotification(for payload: PushPayload) {
        // Try to decrypt encrypted metadata if present
        var metadata: PushMetadata?
        if let encrypted = payload.encryptedMetadata {
            metadata = decryptMetadata(encrypted)
        }

        let title: String
        let body: String

        switch privacyLevel {
        case .full:
            let sender = metadata?.senderName ?? payload.senderName ?? "Someone"
            let preview = metadata?.preview ?? "sent a message"
            let channel = metadata?.channelName
            title = channel != nil ? "#\(channel!)" : "Accord"
            body = "\(sender): \(preview)"

        case .senderOnly:
            let sender = metadata?.senderName ?? payload.senderName ?? "Someone"
            title = "Accord"
            body = "Message from \(sender)"

        case .minimal:
            title = "Accord"
            body = "New message"
        }

        showNotification(title: title, body: body, channelId: payload.channelId)
    }

    private func showNotification(title: String, body: String, channelId: String?) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        if let channelId {
            content.userInfo["channel_id"] = channelId
        }

        // Update badge count
        incrementBadgeCount()

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Badge Management

    func incrementBadgeCount() {
        let current = UserDefaults.standard.integer(forKey: "accord.badgeCount")
        let newCount = current + 1
        UserDefaults.standard.set(newCount, forKey: "accord.badgeCount")
        Task { @MainActor in
            UNUserNotificationCenter.current().setBadgeCount(newCount)
        }
    }

    func resetBadgeCount() {
        UserDefaults.standard.set(0, forKey: "accord.badgeCount")
        Task { @MainActor in
            UNUserNotificationCenter.current().setBadgeCount(0)
        }
    }

    // MARK: - Token Lifecycle

    /// Call on logout to deregister push token from server
    func deregister() async {
        guard let api = apiService, let token = deviceToken else { return }

        do {
            try await api.deregisterPushToken(token: token)
        } catch {
            print("[PushService] Deregister failed: \(error)")
        }

        isRegistered = false
        deviceToken = nil
        UserDefaults.standard.removeObject(forKey: deviceTokenKey)
        resetBadgeCount()
    }

    /// Call when identity key changes to rotate the push token
    func rotateTokenOnKeyChange() async {
        guard let token = deviceToken else { return }
        await uploadToken(token)
    }

    // MARK: - Crypto

    /// Decrypt encrypted push metadata using the local identity private key.
    /// Uses X25519 ECDH + HKDF + AES-256-GCM (matching core/src/push_crypto.rs).
    private func decryptMetadata(_ base64Encoded: String) -> PushMetadata? {
        guard let data = Data(base64Encoded: base64Encoded) else { return nil }

        // The encrypted blob layout (matching Rust bincode serialization):
        // [32 bytes ephemeral public key] [12 bytes nonce] [remaining: ciphertext]
        guard data.count > 44 else { return nil }

        let ephemeralPublicBytes = data[0..<32]
        let nonceBytes = data[32..<44]
        let ciphertext = data[44...]

        // Get our private key from keychain
        guard let privateKeyBytes = getIdentityPrivateKey() else { return nil }

        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes)
            let ephemeralPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicBytes)

            // ECDH
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)

            // HKDF to derive AES key
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: "accord-push-metadata-v1".data(using: .utf8)!,
                outputByteCount: 32
            )

            // AES-256-GCM decrypt
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonceBytes),
                ciphertext: ciphertext.dropLast(16),
                tag: ciphertext.suffix(16)
            )
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

            return try JSONDecoder().decode(PushMetadata.self, from: plaintext)
        } catch {
            print("[PushService] Metadata decryption failed: \(error)")
            return nil
        }
    }

    /// Retrieve identity private key from keychain.
    /// This must match whatever key storage the app's E2EE layer uses.
    private func getIdentityPrivateKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.accord.identity",
            kSecAttrAccount as String: "private_key",
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }
}

// MARK: - APIService Push Extensions

extension APIService {
    func registerPushToken(platform: String, token: String, privacyLevel: String) async throws {
        struct Req: Encodable {
            let platform: String
            let token: String
            let privacy_level: String
        }
        try await requestVoid("POST", path: "/push/register",
                              body: Req(platform: platform, token: token, privacy_level: privacyLevel))
    }

    func deregisterPushToken(token: String) async throws {
        struct Req: Encodable { let token: String }
        try await requestVoid("DELETE", path: "/push/register", body: Req(token: token))
    }

    func updatePushPrivacy(privacyLevel: String) async throws {
        struct Req: Encodable { let privacy_level: String }
        try await requestVoid("PUT", path: "/push/privacy", body: Req(privacy_level: privacyLevel))
    }
}
