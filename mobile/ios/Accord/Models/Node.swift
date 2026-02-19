// Node.swift — A community/server (called "Node" in Accord)

import Foundation

struct Node: Identifiable, Codable, Hashable {
    let id: String
    var name: String
    var iconURL: URL?
    var description: String?
    var ownerId: String
    var channels: [Channel] = []
    var members: [User] = []
}
