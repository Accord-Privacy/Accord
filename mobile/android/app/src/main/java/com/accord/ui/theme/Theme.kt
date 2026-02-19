package com.accord.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Accord brand colors — dark-first, privacy-forward aesthetic
val AccordPurple = Color(0xFF7C4DFF)
val AccordPurpleLight = Color(0xFFB388FF)
val AccordSurface = Color(0xFF1A1A2E)
val AccordSurfaceVariant = Color(0xFF16213E)
val AccordBackground = Color(0xFF0F0F1A)
val AccordOnSurface = Color(0xFFE8E8F0)
val AccordError = Color(0xFFCF6679)
val AccordGreen = Color(0xFF4CAF50)

private val DarkColorScheme = darkColorScheme(
    primary = AccordPurple,
    onPrimary = Color.White,
    secondary = AccordPurpleLight,
    surface = AccordSurface,
    surfaceVariant = AccordSurfaceVariant,
    background = AccordBackground,
    onBackground = AccordOnSurface,
    onSurface = AccordOnSurface,
    error = AccordError,
)

@Composable
fun AccordTheme(
    darkTheme: Boolean = true, // Always dark by default — privacy vibes
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = Typography(),
        content = content,
    )
}
