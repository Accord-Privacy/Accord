package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.accord.ui.viewmodel.NodeListViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeListScreen(
    onNodeClick: (String) -> Unit,
    viewModel: NodeListViewModel = viewModel(),
) {
    val nodes by viewModel.nodes.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val error by viewModel.error.collectAsState()

    Column(Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text("Nodes") },
            actions = {
                IconButton(onClick = { viewModel.loadNodes() }) {
                    Icon(Icons.Default.Refresh, "Refresh")
                }
            },
        )

        if (isLoading && nodes.isEmpty()) {
            Box(
                Modifier.fillMaxSize(),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                CircularProgressIndicator()
            }
        } else if (nodes.isEmpty()) {
            Box(
                Modifier.fillMaxSize().padding(24.dp),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text("No nodes yet. Join or create one!", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(nodes, key = { it.id }) { node ->
                    ListItem(
                        headlineContent = { Text(node.name) },
                        supportingContent = {
                            if (node.description.isNotBlank()) Text(node.description)
                        },
                        modifier = Modifier.clickable { onNodeClick(node.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}
