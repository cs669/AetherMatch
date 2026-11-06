package com.aethermatch.p2p.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorPalette = darkColorScheme(
    primary = Color(0xFF00E5A3),
    onPrimary = Color(0xFF00291B),
    primaryContainer = Color(0xFF004D34),
    onPrimaryContainer = Color(0xFF7FFFD4),
    secondary = Color(0xFFFF5E7E),
    onSecondary = Color(0xFF3B0010),
    secondaryContainer = Color(0xFF5C1124),
    onSecondaryContainer = Color(0xFFFFD9DF),
    tertiary = Color(0xFF5CE1E6),
    background = Color(0xFF0B0F17),
    onBackground = Color(0xFFE6EDF7),
    surface = Color(0xFF131B26),
    onSurface = Color(0xFFE6EDF7),
    surfaceVariant = Color(0xFF1C2738),
    onSurfaceVariant = Color(0xFFB0C0D6)
)

@Composable
fun AetherMatchTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorPalette,
        content = content
    )
}
