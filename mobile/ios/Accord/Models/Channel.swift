// Channel.swift — Text or voice channel within a Node

import Foundation

enum ChannelType: String, Codable {
    case text
    case voice
}

struct Channel: Identifiable, Codable, Hashable {
    let id: String
    var name: String
    var type: ChannelType
    var category: String?   // Grouping label
    var nodeId: String
    var topic: String?
    var isEncrypted: Bool = true
}
