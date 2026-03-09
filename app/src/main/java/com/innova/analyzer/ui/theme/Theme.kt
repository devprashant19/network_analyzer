package com.innova.analyzer.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val CyberColorScheme = darkColorScheme(
    primary = NeonCyan,
    onPrimary = DarkBackground,
    primaryContainer = CardSurface,
    onPrimaryContainer = NeonCyan,
    secondary = CyberPurple,
    onSecondary = TextPrimary,
    secondaryContainer = CardSurface,
    onSecondaryContainer = CyberPurple,
    tertiary = NeonCyan, // Optional extra accent
    onTertiary = DarkBackground,
    background = DarkBackground,
    onBackground = TextPrimary,
    surface = DarkBackground,
    onSurface = TextPrimary,
    surfaceVariant = CardSurface,
    onSurfaceVariant = TextSecondary,
    error = CyberRed,
    onError = TextPrimary,
    errorContainer = CardSurface,
    onErrorContainer = CyberRed
)

private val CyberLightColorScheme = lightColorScheme(
    primary = NeonCyan,
    onPrimary = DarkBackground,
    primaryContainer = CardSurfaceLightUI,
    onPrimaryContainer = NeonCyan,
    secondary = CyberPurple,
    onSecondary = TextPrimaryLight,
    secondaryContainer = CardSurfaceLightUI,
    onSecondaryContainer = CyberPurple,
    tertiary = NeonCyan,
    onTertiary = LightBackground,
    background = LightBackground,
    onBackground = TextPrimaryLight,
    surface = LightBackground,
    onSurface = TextPrimaryLight,
    surfaceVariant = CardSurfaceLightUI,
    onSurfaceVariant = TextSecondaryLight,
    error = CyberRed,
    onError = TextPrimaryLight,
    errorContainer = CardSurfaceLightUI,
    onErrorContainer = CyberRed
)

@Composable
fun InnovaTheme(
    // We now respect the parameter for the toggle!
    darkTheme: Boolean = isSystemInDarkTheme(),
    // We disable dynamic color by default to strictly enforce brand colors
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> CyberColorScheme
        else -> CyberLightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}