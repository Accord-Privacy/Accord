// WebSocketService.swift — WebSocket connection to the Accord relay

import Foundation
import Combine

// MARK: - Connection State

enum ConnectionState: String {
    case disconnected
    case connecting
    case connected
    case reconnecting
}

// MARK: - Incoming WS Message Types

/// Parsed server→client WebSocket messages
enum WSIncomingMessage {
    case authenticated(userId: String)
    case channelMessage(ChannelMessagePayload)
    case presenceUpdate(userId: String, status: String)
    case presenceBulk(members: [[String: Any]])
    case typingStart(channelId: String, userId: String, publicKeyHash: String?)
    case messageEdit(messageId: String, channelId: String, encryptedData: String, editedAt: Int)
    case messageDelete(messageId: String, channelId: String)
    case reactionAdd(messageId: String, reactions: [[String: Any]])
    case reactionRemove(messageId: String, reactions: [[String: Any]])
    case messagePin(messageId: String, timestamp: Int, pinnedBy: String)
    case messageUnpin(messageId: String)
    case readReceipt(channelId: String, userId: String, messageId: String, timestamp: Int)
    case hello(serverVersion: String?, serverBuildHash: String?)
    case error(code: String?, message: String)
    case unknown(type: String, raw: [String: Any])
}

struct ChannelMessagePayload {
    let messageId: String
    let channelId: String
    let from: String?
    let encryptedData: String
    let timestamp: Int
    let isDM: Bool
    let replyTo: String?
    let repliedMessage: [String: Any]?
    let senderDisplayName: String?
}

// MARK: - WebSocketService

/// Handles persistent WebSocket connection to the relay for real-time events.
@Observable
final class WebSocketService {
    private let relayURL: String
    private var authToken: String?
    private var webSocketTask: URLSessionWebSocketTask?
    private let session: URLSession

    // Connection state
    private(set) var connectionState: ConnectionState = .disconnected
    var isConnected: Bool { connectionState == .connected }

    // Reconnection
    private var reconnectAttempt: Int = 0
    private let maxReconnectAttempts: Int = 20
    private var reconnectDelay: TimeInterval = 1.0
    private let maxReconnectDelay: TimeInterval = 30.0
    private var reconnectTask: Task<Void, Never>?
    private var isDestroyed: Bool = false

    // Ping keepalive
    private var pingTask: Task<Void, Never>?

    // MARK: - Callbacks

    var onMessage: ((WSIncomingMessage) -> Void)?
    var onRawText: ((String) -> Void)?
    var onConnectionStateChanged: ((ConnectionState) -> Void)?

    // Combine publishers (alternative to callbacks)
    let messagePublisher = PassthroughSubject<WSIncomingMessage, Never>()
    let connectionStatePublisher = PassthroughSubject<ConnectionState, Never>()

    init(relayURL: String) {
        self.relayURL = relayURL
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        self.session = URLSession(configuration: config)
    }

    // MARK: - Connection

    func connect(token: String) {
        guard !isDestroyed else { return }
        self.authToken = token

        // Build WS URL: replace http(s) with ws(s), append /ws
        var wsURLString = relayURL
        if wsURLString.hasPrefix("https") {
            wsURLString = "wss" + wsURLString.dropFirst(5)
        } else if wsURLString.hasPrefix("http") {
            wsURLString = "ws" + wsURLString.dropFirst(4)
        }
        if !wsURLString.hasSuffix("/ws") {
            wsURLString += "/ws"
        }

        guard let url = URL(string: wsURLString) else {
            print("[WS] Invalid URL: \(wsURLString)")
            return
        }

        setConnectionState(.connecting)

        let task = session.webSocketTask(with: url)
        self.webSocketTask = task
        task.resume()

        // Post-upgrade auth: send Authenticate message immediately
        sendAuthMessage(token: token)
    }

    func disconnect() {
        isDestroyed = true
        reconnectTask?.cancel()
        reconnectTask = nil
        pingTask?.cancel()
        pingTask = nil
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        setConnectionState(.disconnected)
    }

    func reconnectWithToken(_ token: String) {
        isDestroyed = false
        reconnectAttempt = 0
        reconnectDelay = 1.0
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        connect(token: token)
    }

    // MARK: - Send

    /// Send a typed WS message as JSON
    func send(_ messageType: [String: Any]) async throws {
        let envelope: [String: Any] = [
            "message_type": messageType,
            "message_id": UUID().uuidString,
            "timestamp": Int(Date().timeIntervalSince1970)
        ]
        let data = try JSONSerialization.data(withJSONObject: envelope)
        guard let text = String(data: data, encoding: .utf8) else { return }
        try await sendRaw(text)
    }

    /// Send a channel message
    func sendChannelMessage(channelId: String, encryptedData: String, replyTo: String? = nil) async throws {
        var msg: [String: Any] = [
            "ChannelMessage": [
                "channel_id": channelId,
                "encrypted_data": encryptedData,
            ] as [String: Any]
        ]
        if let replyTo {
            var inner = msg["ChannelMessage"] as! [String: Any]
            inner["reply_to"] = replyTo
            msg["ChannelMessage"] = inner
        }
        try await send(msg)
    }

    /// Send typing start indicator
    func sendTypingStart(channelId: String) async throws {
        try await send(["TypingStart": ["channel_id": channelId]])
    }

    /// Send ping
    func sendPing() async throws {
        try await send(["Ping": [:] as [String: Any]])
    }

    /// Send raw text
    func sendRaw(_ text: String) async throws {
        guard let task = webSocketTask else {
            throw URLError(.badServerResponse)
        }
        try await task.send(.string(text))
    }

    // MARK: - Private

    private func sendAuthMessage(token: String) {
        let authJSON = "{\"Authenticate\":{\"token\":\"\(token)\"}}"
        webSocketTask?.send(.string(authJSON)) { [weak self] error in
            if let error {
                print("[WS] Failed to send auth message: \(error)")
                self?.handleDisconnect()
            } else {
                // Start listening — server will send "authenticated" or "error"
                self?.listenForMessages()
            }
        }
    }

    private func listenForMessages() {
        webSocketTask?.receive { [weak self] result in
            guard let self, !self.isDestroyed else { return }
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    self.handleTextMessage(text)
                case .data(let data):
                    if let text = String(data: data, encoding: .utf8) {
                        self.handleTextMessage(text)
                    }
                @unknown default:
                    break
                }
                self.listenForMessages()
            case .failure(let error):
                print("[WS] Receive error: \(error)")
                self.handleDisconnect()
            }
        }
    }

    private func handleTextMessage(_ text: String) {
        onRawText?(text)

        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else {
            return
        }

        let parsed: WSIncomingMessage

        switch type {
        case "authenticated":
            let userId = json["user_id"] as? String ?? ""
            parsed = .authenticated(userId: userId)
            // Auth confirmed — we're truly connected
            reconnectAttempt = 0
            reconnectDelay = 1.0
            setConnectionState(.connected)
            startPingKeepalive()

        case "channel_message":
            parsed = .channelMessage(ChannelMessagePayload(
                messageId: json["message_id"] as? String ?? UUID().uuidString,
                channelId: json["channel_id"] as? String ?? "",
                from: json["from"] as? String,
                encryptedData: json["encrypted_data"] as? String ?? "",
                timestamp: json["timestamp"] as? Int ?? Int(Date().timeIntervalSince1970),
                isDM: json["is_dm"] as? Bool ?? false,
                replyTo: json["reply_to"] as? String,
                repliedMessage: json["replied_message"] as? [String: Any],
                senderDisplayName: json["sender_display_name"] as? String
            ))

        case "presence_update":
            parsed = .presenceUpdate(
                userId: json["user_id"] as? String ?? "",
                status: json["status"] as? String ?? "offline"
            )

        case "presence_bulk":
            parsed = .presenceBulk(members: json["members"] as? [[String: Any]] ?? [])

        case "typing_start":
            parsed = .typingStart(
                channelId: json["channel_id"] as? String ?? "",
                userId: json["user_id"] as? String ?? "",
                publicKeyHash: json["public_key_hash"] as? String
            )

        case "message_edit":
            parsed = .messageEdit(
                messageId: json["message_id"] as? String ?? "",
                channelId: json["channel_id"] as? String ?? "",
                encryptedData: json["encrypted_data"] as? String ?? "",
                editedAt: json["edited_at"] as? Int ?? 0
            )

        case "message_delete":
            parsed = .messageDelete(
                messageId: json["message_id"] as? String ?? "",
                channelId: json["channel_id"] as? String ?? ""
            )

        case "reaction_add":
            parsed = .reactionAdd(
                messageId: json["message_id"] as? String ?? "",
                reactions: json["reactions"] as? [[String: Any]] ?? []
            )

        case "reaction_remove":
            parsed = .reactionRemove(
                messageId: json["message_id"] as? String ?? "",
                reactions: json["reactions"] as? [[String: Any]] ?? []
            )

        case "message_pin":
            parsed = .messagePin(
                messageId: json["message_id"] as? String ?? "",
                timestamp: json["timestamp"] as? Int ?? 0,
                pinnedBy: json["pinned_by"] as? String ?? ""
            )

        case "message_unpin":
            parsed = .messageUnpin(messageId: json["message_id"] as? String ?? "")

        case "read_receipt":
            parsed = .readReceipt(
                channelId: json["channel_id"] as? String ?? "",
                userId: json["user_id"] as? String ?? "",
                messageId: json["message_id"] as? String ?? "",
                timestamp: json["timestamp"] as? Int ?? 0
            )

        case "hello":
            parsed = .hello(
                serverVersion: json["server_version"] as? String,
                serverBuildHash: json["server_build_hash"] as? String
            )

        case "error":
            let code = json["code"] as? String
            let message = json["message"] as? String ?? json["error"] as? String ?? "Unknown error"
            parsed = .error(code: code, message: message)

            // Handle auth errors
            if code == "auth_failed" {
                handleDisconnect()
                return
            }

        default:
            parsed = .unknown(type: type, raw: json)
        }

        onMessage?(parsed)
        messagePublisher.send(parsed)
    }

    private func handleDisconnect() {
        pingTask?.cancel()
        pingTask = nil
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil

        guard !isDestroyed else {
            setConnectionState(.disconnected)
            return
        }

        guard reconnectAttempt < maxReconnectAttempts else {
            setConnectionState(.disconnected)
            print("[WS] Max reconnect attempts reached")
            return
        }

        setConnectionState(.reconnecting)
        scheduleReconnect()
    }

    private func scheduleReconnect() {
        let delay = reconnectDelay
        reconnectAttempt += 1
        // Exponential backoff: 1, 2, 4, 8, ..., max 30s
        reconnectDelay = min(reconnectDelay * 2, maxReconnectDelay)

        print("[WS] Reconnecting in \(delay)s (attempt \(reconnectAttempt)/\(maxReconnectAttempts))")

        reconnectTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self, !self.isDestroyed, !Task.isCancelled else { return }
            guard let token = self.authToken else { return }
            self.connect(token: token)
        }
    }

    private func startPingKeepalive() {
        pingTask?.cancel()
        pingTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30s
                guard let self, self.isConnected else { break }
                try? await self.sendPing()
            }
        }
    }

    private func setConnectionState(_ state: ConnectionState) {
        guard connectionState != state else { return }
        connectionState = state
        onConnectionStateChanged?(state)
        connectionStatePublisher.send(state)
    }
}
