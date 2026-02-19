package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.accord.data.model.Node

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeListScreen(onNodeClick: (String) -> Unit) {
    // TODO: Replace with real data from ApiService via ViewModel
    val nodes = remember { mutableStateListOf<Node>() }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(title = { Text("Nodes") })

        if (nodes.isEmpty()) {
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
                        trailingContent = { Text("${node.memberCount} members") },
                        modifier = Modifier.clickable { onNodeClick(node.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}
