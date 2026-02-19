package com.accord.navigation

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.accord.ui.*

object Routes {
    const val LOGIN = "login"
    const val MAIN = "main"
    const val CHANNELS = "node/{nodeId}/channels"
    const val CHAT = "channel/{channelId}/chat"
    const val VOICE = "channel/{channelId}/voice"

    fun channels(nodeId: String) = "node/$nodeId/channels"
    fun chat(channelId: String) = "channel/$channelId/chat"
    fun voice(channelId: String) = "channel/$channelId/voice"
}

@Composable
fun AccordNavGraph() {
    val navController = rememberNavController()

    // TODO: Check if user has existing keys → start at MAIN, else LOGIN
    val startDestination = Routes.LOGIN

    NavHost(navController = navController, startDestination = startDestination) {
        composable(Routes.LOGIN) {
            LoginScreen(
                onLoginComplete = {
                    navController.navigate(Routes.MAIN) {
                        popUpTo(Routes.LOGIN) { inclusive = true }
                    }
                }
            )
        }

        composable(Routes.MAIN) {
            MainScreen(
                onNodeClick = { nodeId -> navController.navigate(Routes.channels(nodeId)) },
                onDMClick = { channelId -> navController.navigate(Routes.chat(channelId)) },
            )
        }

        composable(
            Routes.CHANNELS,
            arguments = listOf(navArgument("nodeId") { type = NavType.StringType })
        ) { backStackEntry ->
            val nodeId = backStackEntry.arguments?.getString("nodeId") ?: return@composable
            ChannelListScreen(
                nodeId = nodeId,
                onTextChannelClick = { navController.navigate(Routes.chat(it)) },
                onVoiceChannelClick = { navController.navigate(Routes.voice(it)) },
                onBack = { navController.popBackStack() },
            )
        }

        composable(
            Routes.CHAT,
            arguments = listOf(navArgument("channelId") { type = NavType.StringType })
        ) { backStackEntry ->
            val channelId = backStackEntry.arguments?.getString("channelId") ?: return@composable
            ChatScreen(
                channelId = channelId,
                onBack = { navController.popBackStack() },
            )
        }

        composable(
            Routes.VOICE,
            arguments = listOf(navArgument("channelId") { type = NavType.StringType })
        ) { backStackEntry ->
            val channelId = backStackEntry.arguments?.getString("channelId") ?: return@composable
            VoiceChannelScreen(
                channelId = channelId,
                onDisconnect = { navController.popBackStack() },
            )
        }
    }
}
