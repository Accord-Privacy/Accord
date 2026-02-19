// APIService.swift — REST API client for the Accord relay

import Foundation

/// REST client for relay HTTP endpoints (user registration, key upload, node management, etc.)
@Observable
final class APIService {
    private let baseURL: String
    private let session = URLSession.shared
    private var authToken: String?

    init(baseURL: String) {
        self.baseURL = baseURL
    }

    func setAuthToken(_ token: String) {
        self.authToken = token
    }

    // MARK: - Generic Request

    private func request<T: Decodable>(_ method: String, path: String, body: (any Encodable)? = nil) async throws -> T {
        guard let url = URL(string: "\(baseURL)\(path)") else {
            throw URLError(.badURL)
        }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token = authToken {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.httpBody = try JSONEncoder().encode(body)
        }
        let (data, _) = try await session.data(for: req)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - Identity

    /// Upload our publishable key bundle to the relay.
    func uploadKeyBundle(_ bundle: Data) async throws {
        // TODO: POST /keys with bundle data
    }

    /// Fetch a peer's key bundle for initiating a session.
    func fetchKeyBundle(userId: String) async throws -> Data {
        // TODO: GET /keys/{userId}
        fatalError("Not implemented")
    }

    // MARK: - Nodes

    func fetchNodes() async throws -> [Node] {
        // TODO: GET /nodes
        return []
    }

    func fetchChannels(nodeId: String) async throws -> [Channel] {
        // TODO: GET /nodes/{nodeId}/channels
        return []
    }

    // MARK: - Messages

    func fetchMessages(channelId: String, before: String? = nil, limit: Int = 50) async throws -> [Message] {
        // TODO: GET /channels/{channelId}/messages
        return []
    }

    func sendMessage(channelId: String, encryptedContent: Data) async throws {
        // TODO: POST /channels/{channelId}/messages
    }

    // MARK: - DMs

    func fetchDMConversations() async throws -> [(User, Message?)] {
        // TODO: GET /dms
        return []
    }

    // MARK: - Users

    func fetchUser(id: String) async throws -> User {
        // TODO: GET /users/{id}
        fatalError("Not implemented")
    }
}
