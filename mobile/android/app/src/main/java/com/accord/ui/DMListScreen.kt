package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.accord.ui.viewmodel.DMListViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DMListScreen(onDMClick: (String) -> Unit) {
    val viewModel: DMListViewModel = viewModel()
    val conversations by viewModel.conversations.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()

    Column(Modifier.fillMaxSize()) {
        TopAppBar(title = { Text("Direct Messages") })

        if (isLoading && conversations.isEmpty()) {
            Box(
                Modifier.fillMaxSize(),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        } else if (conversations.isEmpty()) {
            Box(
                Modifier.fillMaxSize().padding(24.dp),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text("No conversations yet.", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(conversations, key = { it.channelId }) { convo ->
                    ListItem(
                        headlineContent = { Text(convo.peerDisplayName) },
                        modifier = Modifier.clickable { onDMClick(convo.channelId) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}
