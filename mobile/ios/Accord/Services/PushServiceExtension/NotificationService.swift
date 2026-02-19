// NotificationService.swift — UNNotificationServiceExtension for Accord
//
// Intercepts push notifications before display to:
// 1. Decrypt encrypted metadata (E2EE push content)
// 2. Apply privacy level formatting
// 3. Update badge count
//
// This runs in a separate extension process with limited memory/time (~30s).

import UserNotifications
import CryptoKit
import Foundation

class NotificationService: UNNotificationServiceExtension {

    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var bestAttemptContent: UNMutableNotificationContent?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        self.contentHandler = contentHandler
        bestAttemptContent = (request.content.mutableCopy() as? UNMutableNotificationContent)

        guard let content = bestAttemptContent else {
            contentHandler(request.content)
            return
        }

        let userInfo = content.userInfo

        // Load privacy level from shared app group defaults
        let privacyLevel = loadPrivacyLevel()

        // Try to decrypt encrypted metadata
        var senderName: String?
        var channelName: String?
        var preview: String?

        if let encryptedBase64 = userInfo["encrypted_metadata"] as? String,
           let metadata = decryptMetadata(encryptedBase64) {
            senderName = metadata.senderName
            channelName = metadata.channelName
            preview = metadata.preview
        }

        // Fallback to unencrypted sender_name if present
        if senderName == nil {
            senderName = userInfo["sender_name"] as? String
        }

        // Apply privacy level
        switch privacyLevel {
        case "full":
            let sender = senderName ?? "Someone"
            let body = preview ?? "sent a message"
            content.title = channelName.map { "#\($0)" } ?? "Accord"
            content.body = "\(sender): \(body)"

        case "sender_only":
            let sender = senderName ?? "Someone"
            content.title = "Accord"
            content.body = "Message from \(sender)"

        default: // "minimal"
            content.title = "Accord"
            content.body = "New message"
        }

        content.sound = .default

        // Badge count
        let badgeCount = incrementBadgeCount()
        content.badge = NSNumber(value: badgeCount)

        contentHandler(content)
    }

    override func serviceExtensionTimeWillExpire() {
        // Deliver whatever we have — fall back to minimal
        if let content = bestAttemptContent {
            content.title = "Accord"
            content.body = "New message"
            contentHandler?(content)
        }
    }

    // MARK: - Helpers

    private func loadPrivacyLevel() -> String {
        let defaults = UserDefaults(suiteName: "group.com.accord.shared")
        return defaults?.string(forKey: "accord.push.privacyLevel") ?? "minimal"
    }

    private func incrementBadgeCount() -> Int {
        let defaults = UserDefaults(suiteName: "group.com.accord.shared")
        let current = defaults?.integer(forKey: "accord.badgeCount") ?? 0
        let next = current + 1
        defaults?.set(next, forKey: "accord.badgeCount")
        return next
    }

    // MARK: - Crypto (duplicated from PushService for extension process isolation)

    private struct PushMetadata: Codable {
        let senderName: String?
        let channelName: String?
        let preview: String?

        enum CodingKeys: String, CodingKey {
            case senderName = "sender_name"
            case channelName = "channel_name"
            case preview
        }
    }

    private func decryptMetadata(_ base64Encoded: String) -> PushMetadata? {
        guard let data = Data(base64Encoded: base64Encoded), data.count > 44 else { return nil }

        let ephemeralPublicBytes = data[0..<32]
        let nonceBytes = data[32..<44]
        let ciphertext = data[44...]

        guard let privateKeyBytes = getIdentityPrivateKey() else { return nil }

        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes)
            let ephemeralPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPublicBytes)

            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: ephemeralPublic)
            let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
                using: SHA256.self,
                salt: Data(),
                sharedInfo: "accord-push-metadata-v1".data(using: .utf8)!,
                outputByteCount: 32
            )

            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonceBytes),
                ciphertext: ciphertext.dropLast(16),
                tag: ciphertext.suffix(16)
            )
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
            return try JSONDecoder().decode(PushMetadata.self, from: plaintext)
        } catch {
            return nil
        }
    }

    private func getIdentityPrivateKey() -> Data? {
        // Access shared keychain (app group) for the identity key
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.accord.identity",
            kSecAttrAccount as String: "private_key",
            kSecAttrAccessGroup as String: "group.com.accord.shared",
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }
}
