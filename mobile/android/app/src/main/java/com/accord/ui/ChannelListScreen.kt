package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.accord.data.model.ChannelType
import com.accord.ui.viewmodel.ChannelListViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChannelListScreen(
    nodeId: String,
    onTextChannelClick: (String) -> Unit,
    onVoiceChannelClick: (String) -> Unit,
    onBack: () -> Unit,
    viewModel: ChannelListViewModel = viewModel(factory = ChannelListViewModel.Factory(nodeId)),
) {
    val grouped by viewModel.grouped.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val nodeName by viewModel.nodeName.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(nodeName.ifBlank { "Channels" }) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
            )
        }
    ) { padding ->
        if (isLoading && grouped.isEmpty()) {
            Box(
                Modifier.fillMaxSize().padding(padding),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        } else {
            LazyColumn(
                Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                grouped.forEach { group ->
                    item {
                        Text(
                            group.categoryName.uppercase(),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                        )
                    }
                    items(group.channels, key = { it.id }) { channel ->
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
    }
}
