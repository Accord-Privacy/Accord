package com.accord.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.accord.data.service.PushPrivacyLevel
import com.accord.data.service.PushService

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

            // Push notification privacy level
            PushPrivacyPicker()
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PushPrivacyPicker() {
    val context = LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf(PushService.getPrivacyLevel(context)) }

    ListItem(
        headlineContent = { Text("Push notification privacy") },
        supportingContent = { Text(selected.description) },
        trailingContent = {
            ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
                TextButton(
                    onClick = { expanded = true },
                    modifier = Modifier.menuAnchor(),
                ) {
                    Text(selected.displayName)
                }
                ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                    PushPrivacyLevel.entries.forEach { level ->
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(level.displayName)
                                    Text(
                                        level.description,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            },
                            onClick = {
                                selected = level
                                expanded = false
                                PushService.setPrivacyLevel(context, level)
                                // Server update happens on next sync or can be triggered explicitly
                            },
                        )
                    }
                }
            }
        },
    )
}
