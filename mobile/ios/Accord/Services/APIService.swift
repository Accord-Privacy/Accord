// APIService.swift — REST API client for the Accord relay

import Foundation

// MARK: - API Errors

enum APIError: LocalizedError {
    case badURL
    case unauthorized
    case forbidden(String)
    case notFound
    case conflict(String)
    case rateLimited(retryAfter: Int)
    case serverError(String)
    case decodingError(Error)
    case networkError(Error)
    case unknown(statusCode: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .badURL: return "Invalid URL"
        case .unauthorized: return "Authentication required"
        case .forbidden(let msg): return msg
        case .notFound: return "Not found"
        case .conflict(let msg): return msg
        case .rateLimited(let s): return "Rate limited. Retry after \(s)s"
        case .serverError(let msg): return msg
        case .decodingError(let err): return "Decoding error: \(err.localizedDescription)"
        case .networkError(let err): return err.localizedDescription
        case .unknown(let code, let msg): return "Error \(code): \(msg)"
        }
    }
}

// MARK: - Response Types

struct AuthResponseDTO: Codable {
    let token: String
    let user_id: String
    let expires_at: Int?
}

struct RegisterResponseDTO: Codable {
    let user_id: String
    let message: String
}

struct NodeDTO: Codable {
    let id: String
    let name: String
    let owner_id: String
    let description: String?
    let created_at: Int?
    let icon_hash: String?
}

struct ChannelDTO: Codable {
    let id: String
    let name: String
    let node_id: String
    let created_at: Int?
    let unread_count: Int?
    let category_id: String?
    let category_name: String?
    let position: Int?
    let channel_type: Int?
}

struct MessageDTO: Codable {
    let id: String
    let channel_id: String?
    let sender_id: String?
    let sender_public_key_hash: String?
    let encrypted_payload: String?
    let encrypted_data: String?
    let content: String?
    let display_name: String?
    let created_at: Int?
    let timestamp: Int?
    let edited_at: Int?
    let pinned_at: Int?
    let pinned_by: String?
    let reply_to: String?
    let replied_message: RepliedMessageDTO?
    let reactions: [[String: Any]]?

    // Custom decoding to handle flexible reactions
    enum CodingKeys: String, CodingKey {
        case id, channel_id, sender_id, sender_public_key_hash
        case encrypted_payload, encrypted_data, content, display_name
        case created_at, timestamp, edited_at, pinned_at, pinned_by
        case reply_to, replied_message
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        channel_id = try c.decodeIfPresent(String.self, forKey: .channel_id)
        sender_id = try c.decodeIfPresent(String.self, forKey: .sender_id)
        sender_public_key_hash = try c.decodeIfPresent(String.self, forKey: .sender_public_key_hash)
        encrypted_payload = try c.decodeIfPresent(String.self, forKey: .encrypted_payload)
        encrypted_data = try c.decodeIfPresent(String.self, forKey: .encrypted_data)
        content = try c.decodeIfPresent(String.self, forKey: .content)
        display_name = try c.decodeIfPresent(String.self, forKey: .display_name)
        created_at = try c.decodeIfPresent(Int.self, forKey: .created_at)
        timestamp = try c.decodeIfPresent(Int.self, forKey: .timestamp)
        edited_at = try c.decodeIfPresent(Int.self, forKey: .edited_at)
        pinned_at = try c.decodeIfPresent(Int.self, forKey: .pinned_at)
        pinned_by = try c.decodeIfPresent(String.self, forKey: .pinned_by)
        reply_to = try c.decodeIfPresent(String.self, forKey: .reply_to)
        replied_message = try c.decodeIfPresent(RepliedMessageDTO.self, forKey: .replied_message)
        reactions = nil // Decoded separately if needed
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeIfPresent(channel_id, forKey: .channel_id)
        try c.encodeIfPresent(sender_id, forKey: .sender_id)
        try c.encodeIfPresent(encrypted_payload, forKey: .encrypted_payload)
        try c.encodeIfPresent(content, forKey: .content)
        try c.encodeIfPresent(display_name, forKey: .display_name)
    }
}

struct RepliedMessageDTO: Codable {
    let id: String
    let sender_id: String?
    let sender_public_key_hash: String?
    let encrypted_payload: String?
    let created_at: Int?
    let content: String?
}

struct MessagesResponseDTO: Codable {
    let messages: [MessageDTO]
    let has_more: Bool
    let next_cursor: String?
}

struct UserProfileDTO: Codable {
    let user_id: String
    let display_name: String?
    let avatar_url: String?
    let bio: String?
    let status: String?
    let custom_status: String?
    let updated_at: Int?
}

struct MemberDTO: Codable {
    let user_id: String
    let public_key_hash: String?
    let role: String?
    let joined_at: Int?
    let profile: UserProfileDTO?
}

struct KeyBundleDTO: Codable {
    let identity_key: String
    let signed_prekey: String
    let one_time_prekey: String?
}

struct InviteResponseDTO: Codable {
    let id: String
    let invite_code: String
    let max_uses: Int?
    let expires_at: Int?
    let created_at: Int?
}

struct UseInviteResponseDTO: Codable {
    let status: String
    let node_id: String
    let node_name: String
}

struct HealthResponseDTO: Codable {
    let status: String
    let version: String
    let uptime_seconds: Int?
    let build_hash: String?
}

struct SlowModeDTO: Codable {
    let slow_mode_seconds: Int
}

struct DMChannelDTO: Codable {
    let id: String
    let other_user_id: String?
    let other_user_display_name: String?
    let last_message: MessageDTO?
}

// MARK: - APIService

/// REST client for relay HTTP endpoints
@Observable
final class APIService {
    private let baseURL: String
    private let session: URLSession
    private(set) var authToken: String?

    init(baseURL: String) {
        self.baseURL = baseURL
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        self.session = URLSession(configuration: config)
    }

    func setAuthToken(_ token: String?) {
        self.authToken = token
    }

    // MARK: - Generic Request

    private func request<T: Decodable>(
        _ method: String,
        path: String,
        body: (any Encodable)? = nil,
        queryItems: [URLQueryItem]? = nil,
        authenticated: Bool = true
    ) async throws -> T {
        guard var components = URLComponents(string: "\(baseURL)\(path)") else {
            throw APIError.badURL
        }

        // Always include auth token as query param (server pattern)
        var items = queryItems ?? []
        if authenticated, let token = authToken {
            items.append(URLQueryItem(name: "token", value: token))
        }
        if !items.isEmpty {
            components.queryItems = items
        }

        guard let url = components.url else {
            throw APIError.badURL
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body {
            req.httpBody = try JSONEncoder().encode(body)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw APIError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.unknown(statusCode: 0, message: "Not an HTTP response")
        }

        try checkStatusCode(httpResponse, data: data)

        do {
            let decoder = JSONDecoder()
            return try decoder.decode(T.self, from: data)
        } catch {
            throw APIError.decodingError(error)
        }
    }

    /// Fire-and-forget request (no response body needed)
    private func requestVoid(
        _ method: String,
        path: String,
        body: (any Encodable)? = nil,
        queryItems: [URLQueryItem]? = nil,
        authenticated: Bool = true
    ) async throws {
        guard var components = URLComponents(string: "\(baseURL)\(path)") else {
            throw APIError.badURL
        }

        var items = queryItems ?? []
        if authenticated, let token = authToken {
            items.append(URLQueryItem(name: "token", value: token))
        }
        if !items.isEmpty {
            components.queryItems = items
        }

        guard let url = components.url else {
            throw APIError.badURL
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let body {
            req.httpBody = try JSONEncoder().encode(body)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw APIError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.unknown(statusCode: 0, message: "Not an HTTP response")
        }

        try checkStatusCode(httpResponse, data: data)
    }

    private func checkStatusCode(_ response: HTTPURLResponse, data: Data) throws {
        switch response.statusCode {
        case 200...299:
            return
        case 401:
            throw APIError.unauthorized
        case 403:
            let msg = extractErrorMessage(data) ?? "Forbidden"
            throw APIError.forbidden(msg)
        case 404:
            throw APIError.notFound
        case 409:
            let msg = extractErrorMessage(data) ?? "Conflict"
            throw APIError.conflict(msg)
        case 429:
            throw APIError.rateLimited(retryAfter: 60)
        case 500...599:
            let msg = extractErrorMessage(data) ?? "Server error"
            throw APIError.serverError(msg)
        default:
            let msg = extractErrorMessage(data) ?? "Unknown error"
            throw APIError.unknown(statusCode: response.statusCode, message: msg)
        }
    }

    private func extractErrorMessage(_ data: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return String(data: data, encoding: .utf8)
        }
        return json["error"] as? String ?? json["message"] as? String
    }

    // MARK: - Health

    func testConnection() async -> Bool {
        do {
            let _: HealthResponseDTO = try await request("GET", path: "/health", authenticated: false)
            return true
        } catch {
            return false
        }
    }

    // MARK: - Auth

    func register(publicKey: String, password: String, displayName: String? = nil) async throws -> RegisterResponseDTO {
        struct Req: Encodable {
            let public_key: String
            let password: String
            let display_name: String?
        }
        return try await request("POST", path: "/register", body: Req(public_key: publicKey, password: password, display_name: displayName), authenticated: false)
    }

    func login(publicKey: String, password: String) async throws -> AuthResponseDTO {
        struct Req: Encodable {
            let public_key: String
            let password: String
        }
        return try await request("POST", path: "/auth", body: Req(public_key: publicKey, password: password), authenticated: false)
    }

    // MARK: - Nodes

    func fetchNodes() async throws -> [NodeDTO] {
        return try await request("GET", path: "/nodes")
    }

    func createNode(name: String, description: String? = nil) async throws -> NodeDTO {
        struct Req: Encodable {
            let name: String
            let description: String?
        }
        return try await request("POST", path: "/nodes", body: Req(name: name, description: description))
    }

    func getNode(id: String) async throws -> NodeDTO {
        return try await request("GET", path: "/nodes/\(id)")
    }

    func joinNode(id: String) async throws {
        // Returns JSON but we don't always need it
        let _: [String: Any]? = try? await request("POST", path: "/nodes/\(id)/join")
    }

    func leaveNode(id: String) async throws {
        try await requestVoid("POST", path: "/nodes/\(id)/leave")
    }

    // MARK: - Channels

    func fetchChannels(nodeId: String) async throws -> [ChannelDTO] {
        return try await request("GET", path: "/nodes/\(nodeId)/channels")
    }

    func createChannel(nodeId: String, name: String) async throws -> ChannelDTO {
        struct Req: Encodable { let name: String }
        return try await request("POST", path: "/nodes/\(nodeId)/channels", body: Req(name: name))
    }

    func deleteChannel(id: String) async throws {
        try await requestVoid("DELETE", path: "/channels/\(id)")
    }

    // MARK: - Messages

    func fetchMessages(channelId: String, limit: Int = 50, before: String? = nil) async throws -> MessagesResponseDTO {
        var items: [URLQueryItem] = [URLQueryItem(name: "limit", value: "\(limit)")]
        if let before {
            items.append(URLQueryItem(name: "before", value: before))
        }
        return try await request("GET", path: "/channels/\(channelId)/messages", queryItems: items)
    }

    func editMessage(messageId: String, encryptedData: String) async throws {
        struct Req: Encodable { let encrypted_data: String }
        try await requestVoid("PATCH", path: "/messages/\(messageId)", body: Req(encrypted_data: encryptedData))
    }

    func deleteMessage(messageId: String) async throws {
        try await requestVoid("DELETE", path: "/messages/\(messageId)")
    }

    func markChannelRead(channelId: String, messageId: String) async throws {
        struct Req: Encodable { let message_id: String }
        try await requestVoid("POST", path: "/channels/\(channelId)/read", body: Req(message_id: messageId))
    }

    // MARK: - Reactions

    func addReaction(messageId: String, emoji: String) async throws {
        struct Req: Encodable { let emoji: String }
        try await requestVoid("POST", path: "/messages/\(messageId)/reactions", body: Req(emoji: emoji))
    }

    func removeReaction(messageId: String, emoji: String) async throws {
        try await requestVoid("DELETE", path: "/messages/\(messageId)/reactions", body: nil,
                              queryItems: [URLQueryItem(name: "emoji", value: emoji)])
    }

    // MARK: - Pins

    func pinMessage(messageId: String) async throws {
        try await requestVoid("PUT", path: "/messages/\(messageId)/pin")
    }

    func unpinMessage(messageId: String) async throws {
        try await requestVoid("DELETE", path: "/messages/\(messageId)/pin")
    }

    func fetchPinnedMessages(channelId: String) async throws -> [MessageDTO] {
        return try await request("GET", path: "/channels/\(channelId)/pins")
    }

    // MARK: - Members

    func fetchMembers(nodeId: String) async throws -> [MemberDTO] {
        return try await request("GET", path: "/nodes/\(nodeId)/members")
    }

    func kickMember(nodeId: String, userId: String) async throws {
        try await requestVoid("DELETE", path: "/nodes/\(nodeId)/members/\(userId)")
    }

    // MARK: - Invites

    func createInvite(nodeId: String, maxUses: Int? = nil, expiresInHours: Int? = nil) async throws -> InviteResponseDTO {
        struct Req: Encodable {
            let max_uses: Int?
            let expires_in_hours: Int?
        }
        return try await request("POST", path: "/nodes/\(nodeId)/invites",
                                 body: Req(max_uses: maxUses, expires_in_hours: expiresInHours))
    }

    func useInvite(code: String) async throws -> UseInviteResponseDTO {
        return try await request("POST", path: "/invites/\(code)/join")
    }

    // MARK: - User Profile

    func fetchUserProfile(userId: String) async throws -> UserProfileDTO {
        return try await request("GET", path: "/users/\(userId)/profile")
    }

    func updateProfile(displayName: String? = nil, bio: String? = nil, status: String? = nil, customStatus: String? = nil) async throws {
        struct Req: Encodable {
            let display_name: String?
            let bio: String?
            let status: String?
            let custom_status: String?
        }
        try await requestVoid("PATCH", path: "/users/me/profile",
                              body: Req(display_name: displayName, bio: bio, status: status, custom_status: customStatus))
    }

    // MARK: - Keys (E2EE)

    func publishKeyBundle(identityKey: String, signedPrekey: String, oneTimePrekeys: [String] = []) async throws {
        struct Req: Encodable {
            let identity_key: String
            let signed_prekey: String
            let one_time_prekeys: [String]
        }
        try await requestVoid("POST", path: "/keys/bundle",
                              body: Req(identity_key: identityKey, signed_prekey: signedPrekey, one_time_prekeys: oneTimePrekeys))
    }

    func fetchKeyBundle(userId: String) async throws -> KeyBundleDTO {
        return try await request("GET", path: "/keys/bundle/\(userId)")
    }

    // MARK: - Files

    func uploadFile(channelId: String, fileData: Data, filename: String, mimeType: String) async throws -> [String: Any] {
        guard var components = URLComponents(string: "\(baseURL)/channels/\(channelId)/files") else {
            throw APIError.badURL
        }
        if let token = authToken {
            components.queryItems = [URLQueryItem(name: "token", value: token)]
        }
        guard let url = components.url else { throw APIError.badURL }

        let boundary = UUID().uuidString
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        req.httpBody = body

        let (data, response) = try await session.data(for: req)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.unknown(statusCode: 0, message: "Not HTTP")
        }
        try checkStatusCode(httpResponse, data: data)
        return (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }

    func fetchChannelFiles(channelId: String) async throws -> [[String: Any]] {
        return try await request("GET", path: "/channels/\(channelId)/files")
    }

    // MARK: - DMs

    func createDMChannel(userId: String) async throws -> DMChannelDTO {
        return try await request("POST", path: "/dm/\(userId)")
    }

    func fetchDMChannels() async throws -> [DMChannelDTO] {
        return try await request("GET", path: "/dm")
    }

    // MARK: - Search

    func searchMessages(nodeId: String, query: String) async throws -> [MessageDTO] {
        return try await request("GET", path: "/nodes/\(nodeId)/search",
                                 queryItems: [URLQueryItem(name: "q", value: query)])
    }

    // MARK: - Slow Mode

    func getSlowMode(channelId: String) async throws -> SlowModeDTO {
        return try await request("GET", path: "/channels/\(channelId)/slow-mode")
    }

    // MARK: - Blocking

    func blockUser(userId: String) async throws {
        try await requestVoid("POST", path: "/users/\(userId)/block")
    }

    func unblockUser(userId: String) async throws {
        try await requestVoid("DELETE", path: "/users/\(userId)/block")
    }

    // MARK: - Presence

    func getNodePresence(nodeId: String) async throws -> [String: Any] {
        return try await request("GET", path: "/api/presence/\(nodeId)")
    }

    // MARK: - Friends

    func sendFriendRequest(userId: String) async throws {
        struct Req: Encodable { let user_id: String }
        try await requestVoid("POST", path: "/friends/request", body: Req(user_id: userId))
    }

    func acceptFriendRequest(userId: String) async throws {
        struct Req: Encodable { let user_id: String }
        try await requestVoid("POST", path: "/friends/accept", body: Req(user_id: userId))
    }

    func listFriends() async throws -> [[String: Any]] {
        return try await request("GET", path: "/friends")
    }

    // MARK: - Convenience: Convert DTOs to Model Types

    static func nodeFromDTO(_ dto: NodeDTO) -> Node {
        Node(
            id: dto.id,
            name: dto.name,
            iconURL: nil,
            description: dto.description,
            ownerId: dto.owner_id
        )
    }

    static func channelFromDTO(_ dto: ChannelDTO) -> Channel {
        Channel(
            id: dto.id,
            name: dto.name,
            type: dto.channel_type == 2 ? .voice : .text,
            category: dto.category_name,
            nodeId: dto.node_id,
            topic: nil,
            isEncrypted: true
        )
    }

    static func messageFromDTO(_ dto: MessageDTO) -> Message {
        Message(
            id: dto.id,
            channelId: dto.channel_id ?? "",
            authorId: dto.sender_id ?? "",
            content: dto.content ?? dto.encrypted_payload ?? dto.encrypted_data ?? "",
            timestamp: Date(timeIntervalSince1970: TimeInterval(dto.timestamp ?? dto.created_at ?? 0)),
            isEncrypted: true,
            isEdited: dto.edited_at != nil,
            authorName: dto.display_name
        )
    }
}
