package com.accord.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen() {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
    ) {
        TopAppBar(title = { Text("Settings") })

        // ── Account ──────────────────────────────────────────────────
        SettingsSection("Account") {
            // TODO: Show public key fingerprint
            SettingsItem("Identity Key", "Tap to view your public key fingerprint")
            SettingsItem("Export Keys", "Back up your keypair securely")
            SettingsItem("Relay Server", "Change relay URL")
        }

        // ── Privacy ──────────────────────────────────────────────────
        SettingsSection("Privacy") {
            // TODO: Wire toggles to DataStore preferences
            SettingsToggle("Read receipts", checked = false, onToggle = {})
            SettingsToggle("Typing indicators", checked = false, onToggle = {})
            SettingsToggle("Link previews", checked = false, onToggle = {})
        }

        // ── Appearance ───────────────────────────────────────────────
        SettingsSection("Appearance") {
            SettingsItem("Theme", "Dark (default)")
            SettingsItem("Font size", "Medium")
        }

        // ── Voice ────────────────────────────────────────────────────
        SettingsSection("Voice") {
            SettingsItem("Input device", "Default microphone")
            SettingsItem("Noise suppression", "Enabled")
        }

        Spacer(Modifier.height(32.dp))

        TextButton(
            onClick = { /* TODO: Clear keys, disconnect, navigate to login */ },
            modifier = Modifier.padding(horizontal = 16.dp),
        ) {
            Text("Log out", color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, top = 24.dp, bottom = 8.dp),
    )
    Column { content() }
}

@Composable
private fun SettingsItem(title: String, subtitle: String) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle) },
    )
}

@Composable
private fun SettingsToggle(title: String, checked: Boolean, onToggle: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        trailingContent = {
            Switch(checked = checked, onCheckedChange = onToggle)
        },
    )
}
