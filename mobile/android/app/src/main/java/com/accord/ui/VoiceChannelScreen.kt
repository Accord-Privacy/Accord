package com.accord.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.accord.data.model.VoiceParticipant

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoiceChannelScreen(
    channelId: String,
    onDisconnect: () -> Unit,
) {
    // TODO: Wire to VoiceService state via ViewModel
    var isMuted by remember { mutableStateOf(false) }
    var isDeafened by remember { mutableStateOf(false) }
    val participants = remember { mutableStateListOf<VoiceParticipant>() }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("🔊 Voice") }) // TODO: Show channel name
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Participant list
            LazyColumn(
                Modifier
                    .weight(1f)
                    .fillMaxWidth(),
                contentPadding = PaddingValues(16.dp),
            ) {
                items(participants) { p ->
                    ListItem(
                        headlineContent = { Text(p.displayName) },
                        leadingContent = {
                            Icon(
                                if (p.isSpeaking) Icons.Default.RecordVoiceOver
                                else Icons.Default.Person,
                                contentDescription = null,
                                tint = if (p.isSpeaking) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurface,
                            )
                        },
                        trailingContent = {
                            if (p.isMuted) Icon(Icons.Default.MicOff, "Muted")
                        },
                    )
                }
            }

            // Controls
            Row(
                Modifier.padding(24.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                FilledIconToggleButton(
                    checked = isMuted,
                    onCheckedChange = {
                        isMuted = it
                        // TODO: VoiceService.toggleMute()
                    },
                ) {
                    Icon(
                        if (isMuted) Icons.Default.MicOff else Icons.Default.Mic,
                        "Toggle mute",
                    )
                }

                FilledIconToggleButton(
                    checked = isDeafened,
                    onCheckedChange = {
                        isDeafened = it
                        // TODO: VoiceService.toggleDeafen()
                    },
                ) {
                    Icon(
                        if (isDeafened) Icons.Default.HeadsetOff else Icons.Default.Headset,
                        "Toggle deafen",
                    )
                }

                FilledIconButton(
                    onClick = {
                        // TODO: VoiceService.leave()
                        onDisconnect()
                    },
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                    ),
                ) {
                    Icon(Icons.Default.CallEnd, "Disconnect")
                }
            }
        }
    }
}
