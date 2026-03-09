package com.innova.analyzer.ui.dashboard.components

import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent

@Composable
fun NetworkRowItem(event: NetworkEvent) {
    val protocolColor = when (event.protocol) {
        ConnectionProtocol.TCP -> MaterialTheme.colorScheme.primary // Cyan
        ConnectionProtocol.UDP -> MaterialTheme.colorScheme.secondary // Purple
        ConnectionProtocol.HTTPS -> Color(0xFF00FF7F) // Spring Green for HTTPS
        else -> MaterialTheme.colorScheme.onSurfaceVariant // Grey
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            // Glassmorphic transparency allows background orbs to bleed through
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        ),
        elevation = CardDefaults.cardElevation(0.dp),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(
            width = 1.dp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f) // Extremely subtle thin line
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 1. App Icon / Protocol Badge
            val appIcon = rememberAppIcon(packageName = event.packageName)

            Box(
                modifier = Modifier
                    .size(46.dp)
                    .background(
                        color = if (appIcon == null) protocolColor.copy(alpha = 0.15f) else Color.Transparent,
                        shape = CircleShape
                    ),
                contentAlignment = Alignment.Center
            ) {
                if (appIcon != null) {
                    // Show the real app icon!
                    Image(
                        bitmap = appIcon,
                        contentDescription = event.appName,
                        modifier = Modifier
                            .fillMaxSize()
                            .clip(CircleShape)
                    )
                } else {
                    // Fallback to your elegant protocol text if it's a system app
                    Text(
                        text = event.protocol.name,
                        color = protocolColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )
                }
            }

            Spacer(modifier = Modifier.width(16.dp))

            // 2. Info Column
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.domain ?: "${event.destIp}:${event.destPort}",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    // Added protocol to the subtitle so it's always visible even with the app icon
                    text = "${event.appName ?: "Unknown Process"} • ${event.protocol.name} • ${event.payloadSize} B",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                )
            }

            // 3. Threat Indicator
            if (event.isSuspicious) {
                Spacer(modifier = Modifier.width(12.dp))

                // Elegant Soft Pulsing/Static Red Dot
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(
                            color = MaterialTheme.colorScheme.error,
                            shape = CircleShape
                        )
                )
            }
        }
    }
}

/**
 * Helper function to safely extract an Android App Icon from the PackageManager
 * and convert it into a Compose-friendly ImageBitmap.
 */
@Composable
fun rememberAppIcon(packageName: String?): ImageBitmap? {
    val context = LocalContext.current

    // remember ensures we only do this expensive lookup ONCE per app name
    return remember(packageName) {
        if (packageName == null) return@remember null

        try {
            val drawable = context.packageManager.getApplicationIcon(packageName)
            drawableToImageBitmap(drawable)
        } catch (e: PackageManager.NameNotFoundException) {
            null
        }
    }
}

/** Converts an old-school Java Drawable into a Jetpack Compose ImageBitmap */
private fun drawableToImageBitmap(drawable: Drawable): ImageBitmap {
    if (drawable is BitmapDrawable) {
        return drawable.bitmap.asImageBitmap()
    }

    val width = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else 1
    val height = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else 1

    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    drawable.setBounds(0, 0, canvas.width, canvas.height)
    drawable.draw(canvas)

    return bitmap.asImageBitmap()
}