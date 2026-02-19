// AccordApp.swift — SwiftUI App entry point
// Privacy-first: no analytics, no tracking, no telemetry.

import SwiftUI

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

    // Services — initialized on login
    var cryptoService: CryptoService?
    var webSocketService: WebSocketService?
    var apiService: APIService?
    var voiceService: VoiceService?

    func login(relayURL: String, keyMaterial: KeyMaterial) {
        self.relayURL = relayURL
        self.cryptoService = CryptoService(keyMaterial: keyMaterial)
        self.apiService = APIService(baseURL: relayURL)
        self.webSocketService = WebSocketService(relayURL: relayURL)
        // TODO: Derive user identity from key material
        self.isLoggedIn = true
    }

    func logout() {
        webSocketService?.disconnect()
        cryptoService = nil
        apiService = nil
        webSocketService = nil
        voiceService = nil
        currentUser = nil
        isLoggedIn = false
    }
}
