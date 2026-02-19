package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.accord.data.model.Category
import com.accord.data.model.Channel
import com.accord.data.model.ChannelType

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListScreen(
    nodeId: String,
    onTextChannelClick: (String) -> Unit,
    onVoiceChannelClick: (String) -> Unit,
    onBack: () -> Unit,
) {
    // TODO: Load channels grouped by category from ApiService via ViewModel
    val channels = remember { mutableStateListOf<Channel>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Channels") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
            )
        }
    ) { padding ->
        LazyColumn(
            Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            items(channels, key = { it.id }) { channel ->
                ListItem(
                    headlineContent = {
                        Text(
                            "${if (channel.type == ChannelType.VOICE) "🔊" else "#"} ${channel.name}"
                        )
                    },
                    modifier = Modifier.clickable {
                        when (channel.type) {
                            ChannelType.VOICE -> onVoiceChannelClick(channel.id)
                            else -> onTextChannelClick(channel.id)
                        }
                    },
                )
            }
        }
    }
}
