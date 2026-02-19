package com.accord.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier

enum class MainTab(val label: String) {
    NODES("Nodes"), DMS("DMs"), SETTINGS("Settings")
}

@Composable
fun MainScreen(
    onNodeClick: (String) -> Unit,
    onDMClick: (String) -> Unit,
) {
    var selectedTab by remember { mutableStateOf(MainTab.NODES) }

    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = selectedTab == MainTab.NODES,
                    onClick = { selectedTab = MainTab.NODES },
                    icon = { Icon(Icons.Default.Hub, contentDescription = "Nodes") },
                    label = { Text("Nodes") },
                )
                NavigationBarItem(
                    selected = selectedTab == MainTab.DMS,
                    onClick = { selectedTab = MainTab.DMS },
                    icon = { Icon(Icons.Default.Chat, contentDescription = "DMs") },
                    label = { Text("DMs") },
                )
                NavigationBarItem(
                    selected = selectedTab == MainTab.SETTINGS,
                    onClick = { selectedTab = MainTab.SETTINGS },
                    icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                    label = { Text("Settings") },
                )
            }
        }
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (selectedTab) {
                MainTab.NODES -> NodeListScreen(onNodeClick = onNodeClick)
                MainTab.DMS -> DMListScreen(onDMClick = onDMClick)
                MainTab.SETTINGS -> SettingsScreen()
            }
        }
    }
}
