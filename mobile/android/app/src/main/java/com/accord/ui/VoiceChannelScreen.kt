package com.accord.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.accord.data.service.VoiceService

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoiceChannelScreen(
    channelId: String,
    channelName: String = "Voice",
    voiceService: VoiceService,
    onDisconnect: () -> Unit,
) {
    val state by voiceService.state.collectAsState()

    // Join on first composition
    LaunchedEffect(channelId) {
        voiceService.join(channelId)
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("🔊 $channelName") })
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            // Connection banner
            if (state.connectionState == VoiceService.ConnectionState.Connecting) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }

            // Participant list
            if (state.participants.isEmpty() && state.isConnected) {
                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    contentAlignment = Alignment.Center,
                ) {
                    Text("No one else is here yet", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                LazyColumn(
                    Modifier
                        .weight(1f)
                        .fillMaxWidth(),
                    contentPadding = PaddingValues(16.dp),
                ) {
                    items(state.participants, key = { it.userId }) { p ->
                        val borderColor by animateColorAsState(
                            if (p.isSpeaking) Color(0xFF4CAF50) else Color.Transparent,
                            label = "speaking",
                        )
                        ListItem(
                            modifier = Modifier
                                .padding(vertical = 2.dp)
                                .clip(MaterialTheme.shapes.medium)
                                .border(2.dp, borderColor, MaterialTheme.shapes.medium),
                            headlineContent = { Text(p.displayName.ifEmpty { p.userId }) },
                            leadingContent = {
                                Icon(
                                    if (p.isSpeaking) Icons.Default.RecordVoiceOver
                                    else Icons.Default.Person,
                                    contentDescription = null,
                                    tint = if (p.isSpeaking) Color(0xFF4CAF50)
                                    else MaterialTheme.colorScheme.onSurface,
                                )
                            },
                            trailingContent = {
                                if (p.isMuted) Icon(Icons.Default.MicOff, "Muted")
                            },
                        )
                    }
                }
            }

            // Controls
            Row(
                Modifier.padding(24.dp),
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                FilledIconToggleButton(
                    checked = state.isMuted,
                    onCheckedChange = { voiceService.toggleMute() },
                ) {
                    Icon(
                        if (state.isMuted) Icons.Default.MicOff else Icons.Default.Mic,
                        "Toggle mute",
                    )
                }

                FilledIconToggleButton(
                    checked = state.isDeafened,
                    onCheckedChange = { voiceService.toggleDeafen() },
                ) {
                    Icon(
                        if (state.isDeafened) Icons.Default.HeadsetOff else Icons.Default.Headset,
                        "Toggle deafen",
                    )
                }

                FilledIconButton(
                    onClick = {
                        voiceService.leave()
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
