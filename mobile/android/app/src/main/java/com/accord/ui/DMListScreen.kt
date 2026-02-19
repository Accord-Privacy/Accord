package com.accord.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.accord.data.model.Channel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DMListScreen(onDMClick: (String) -> Unit) {
    // TODO: Load DM channels from ApiService via ViewModel
    val dms = remember { mutableStateListOf<Channel>() }

    Column(Modifier.fillMaxSize()) {
        TopAppBar(title = { Text("Direct Messages") })

        if (dms.isEmpty()) {
            Box(
                Modifier.fillMaxSize().padding(24.dp),
                contentAlignment = androidx.compose.ui.Alignment.Center,
            ) {
                Text("No conversations yet.", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(dms, key = { it.id }) { dm ->
                    ListItem(
                        headlineContent = { Text(dm.name) },
                        modifier = Modifier.clickable { onDMClick(dm.id) },
                    )
                    HorizontalDivider()
                }
            }
        }
    }
}
