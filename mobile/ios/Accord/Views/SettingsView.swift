// SettingsView.swift — Account, privacy, appearance, voice settings

import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var appState

    var body: some View {
        NavigationStack {
            List {
                // Account
                Section("Account") {
                    HStack {
                        Circle()
                            .fill(.blue)
                            .frame(width: 44, height: 44)
                            .overlay {
                                Text(String(appState.currentUser?.displayName.prefix(1) ?? "?"))
                                    .foregroundStyle(.white)
                                    .font(.headline)
                            }
                        VStack(alignment: .leading) {
                            Text(appState.currentUser?.displayName ?? "Unknown")
                                .font(.headline)
                            Text("Connected to \(appState.relayURL)")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    // TODO: Edit display name
                    // TODO: Export/backup keypair
                    Button("Export Identity Key") {
                        // TODO: Show key export sheet
                    }
                }

                // Privacy
                Section("Privacy & Security") {
                    Label("End-to-end encrypted", systemImage: "lock.shield.fill")
                        .foregroundStyle(.green)

                    // Push notification privacy
                    NavigationLink {
                        PushPrivacySettingsView()
                    } label: {
                        HStack {
                            Label("Push Notifications", systemImage: "bell.badge")
                            Spacer()
                            Text(PushService.shared.privacyLevel.displayName)
                                .foregroundStyle(.secondary)
                        }
                    }

                    // TODO: Session verification UI
                    NavigationLink("Active Sessions") {
                        // TODO: List active E2EE sessions
                        Text("TODO: Session management")
                    }
                    NavigationLink("Blocked Users") {
                        // TODO: Block list
                        Text("TODO: Block list")
                    }
                }

                // Appearance
                Section("Appearance") {
                    // TODO: Theme picker (system/light/dark)
                    // TODO: Font size
                    Text("TODO: Theme settings")
                        .foregroundStyle(.secondary)
                }

                // Voice
                Section("Voice & Audio") {
                    // TODO: Input/output device selection
                    // TODO: Noise suppression toggle
                    // TODO: Voice activity vs push-to-talk
                    Text("TODO: Voice settings")
                        .foregroundStyle(.secondary)
                }

                // Notifications
                Section("Notifications") {
                    Button("Enable Push Notifications") {
                        Task {
                            await PushService.shared.requestPermissionAndRegister()
                        }
                    }
                    .disabled(PushService.shared.isRegistered)

                    if PushService.shared.isRegistered {
                        Label("Push notifications active", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }

                // About
                Section {
                    Button("Log Out", role: .destructive) {
                        Task {
                            await PushService.shared.deregister()
                        }
                        appState.logout()
                    }
                } footer: {
                    Text("Accord — Privacy-first communication\nNo analytics. No tracking. No telemetry.")
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                        .padding(.top)
                }
            }
            .navigationTitle("Settings")
        }
    }
}

// MARK: - Push Privacy Settings

struct PushPrivacySettingsView: View {
    @State private var selectedLevel = PushService.shared.privacyLevel

    var body: some View {
        List {
            Section {
                ForEach(PushPrivacyLevel.allCases, id: \.self) { level in
                    Button {
                        selectedLevel = level
                        Task {
                            await PushService.shared.updatePrivacyLevel(level)
                        }
                    } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(level.displayName)
                                    .foregroundStyle(.primary)
                                Text(level.description)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if selectedLevel == level {
                                Image(systemName: "checkmark")
                                    .foregroundStyle(.blue)
                            }
                        }
                    }
                }
            } header: {
                Text("Notification Privacy")
            } footer: {
                Text("Controls how much information is shown in push notifications. \"Minimal\" is the most private — notifications only say \"New message\" with no sender or content details.")
            }
        }
        .navigationTitle("Push Notifications")
    }
}
