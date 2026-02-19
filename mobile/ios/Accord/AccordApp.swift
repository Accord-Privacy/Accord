// AccordApp.swift — SwiftUI App entry point
// Privacy-first: no analytics, no tracking, no telemetry.

import SwiftUI
import Combine

@main
struct AccordApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            if appState.isLoggedIn {
                ContentView()
                    .environment(appState)
            } else {
                LoginView()
                    .environment(appState)
            }
        }
    }
}

// MARK: - Global App State

@Observable
final class AppState {
    var isLoggedIn = false
    var currentUser: User?
    var relayURL: String = ""
    var authToken: String?

    // Services — initialized on login
    var cryptoService: CryptoService?
    var webSocketService: WebSocketService?
    var apiService: APIService?
    var voiceService: VoiceService?

    // Navigation state
    var selectedNode: Node?
    var selectedChannel: Channel?

    // Real-time message stream for views to observe
    var incomingMessages: [String: [Message]] = [:]  // channelId → messages

    // WS subscription
    private var cancellables = Set<AnyCancellable>()

    /// Full login flow: set services, store token, connect WS, wire message handler.
    func login(relayURL: String, token: String, userId: String, keyMaterial: KeyMaterial) {
        self.relayURL = relayURL
        self.authToken = token
        self.cryptoService = CryptoService(keyMaterial: keyMaterial)

        let api = APIService(baseURL: relayURL)
        api.setAuthToken(token)
        self.apiService = api

        let ws = WebSocketService(relayURL: relayURL)
        self.webSocketService = ws

        // Wire incoming WS messages to update views
        ws.messagePublisher
            .receive(on: DispatchQueue.main)
            .sink { [weak self] msg in
                self?.handleWSMessage(msg)
            }
            .store(in: &cancellables)

        ws.connect(token: token)

        self.currentUser = User(id: userId, displayName: "")
        self.isLoggedIn = true
    }

    func logout() {
        webSocketService?.disconnect()
        cancellables.removeAll()
        cryptoService?.clearChannelKeyCache()
        cryptoService = nil
        apiService = nil
        webSocketService = nil
        voiceService = nil
        currentUser = nil
        authToken = nil
        selectedNode = nil
        selectedChannel = nil
        incomingMessages.removeAll()
        isLoggedIn = false
    }

    // MARK: - WebSocket Message Routing

    private func handleWSMessage(_ msg: WSIncomingMessage) {
        switch msg {
        case .authenticated(let userId):
            currentUser?.id = userId

        case .channelMessage(let payload):
            let decryptedContent = decryptPayload(payload)
            let message = Message(
                id: payload.messageId,
                channelId: payload.channelId,
                authorId: payload.from ?? "",
                content: decryptedContent,
                timestamp: Date(timeIntervalSince1970: TimeInterval(payload.timestamp)),
                isEncrypted: true,
                authorName: payload.senderDisplayName
            )
            var msgs = incomingMessages[payload.channelId] ?? []
            msgs.append(message)
            incomingMessages[payload.channelId] = msgs

        case .messageEdit(let messageId, let channelId, _, _):
            // Views can observe incomingMessages for edits too — simplified for now
            _ = (messageId, channelId)

        case .messageDelete(let messageId, let channelId):
            incomingMessages[channelId]?.removeAll { $0.id == messageId }

        default:
            break
        }
    }

    /// Attempt to decrypt an incoming channel message payload.
    private func decryptPayload(_ payload: ChannelMessagePayload) -> String {
        guard let crypto = cryptoService, let token = authToken else {
            return payload.encryptedData
        }

        if payload.isDM, let senderId = payload.from {
            // DM: try Double Ratchet decryption
            do {
                if crypto.hasSession(peerUserId: senderId, channelId: payload.channelId) {
                    return try crypto.decryptDMMessage(
                        payload.encryptedData,
                        peerUserId: senderId,
                        channelId: payload.channelId
                    )
                } else {
                    // Initial message — receive and establish session
                    guard let ciphertext = Data(base64Encoded: payload.encryptedData) else {
                        return payload.encryptedData
                    }
                    let plaintext = try crypto.receiveInitialMessage(
                        peerUserId: senderId,
                        channelId: payload.channelId,
                        initialMessage: ciphertext
                    )
                    return String(data: plaintext, encoding: .utf8) ?? payload.encryptedData
                }
            } catch {
                print("[Crypto] DM decrypt failed: \(error)")
                return payload.encryptedData
            }
        } else {
            // Channel: symmetric AES-GCM
            do {
                return try crypto.decryptChannelMessage(
                    payload.encryptedData,
                    channelId: payload.channelId,
                    token: token
                )
            } catch {
                print("[Crypto] Channel decrypt failed: \(error)")
                return payload.encryptedData
            }
        }
    }
}
