// Message.swift — An encrypted message

import Foundation

struct Message: Identifiable, Codable, Hashable {
    let id: String
    var channelId: String
    var authorId: String
    var content: String       // Decrypted plaintext
    var timestamp: Date
    var isEncrypted: Bool = true
    var isEdited: Bool = false

    /// Author display name (denormalized for display)
    var authorName: String?
}
