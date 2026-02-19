// ContentView.swift — Main tab-based navigation

import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        TabView {
            NodeListView()
                .tabItem {
                    Label("Nodes", systemImage: "server.rack")
                }

            DMListView()
                .tabItem {
                    Label("DMs", systemImage: "bubble.left.and.bubble.right")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
        }
    }
}
