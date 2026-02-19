// User.swift — User identity model

import Foundation

struct User: Identifiable, Codable, Hashable {
    var id: String           // Public key hex or unique ID
    var displayName: String
    var avatarURL: URL?
    var isOnline: Bool = false

    /// The user's public identity key (32 bytes)
    var identityKeyData: Data?
}
