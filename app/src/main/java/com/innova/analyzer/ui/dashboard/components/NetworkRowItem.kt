package com.innova.analyzer.ui.dashboard.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
            // Elegant Circular Protocol Badge
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .background(
                        color = protocolColor.copy(alpha = 0.15f),
                        shape = androidx.compose.foundation.shape.CircleShape // Perfect circle
                    ),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = event.protocol.name,
                    color = protocolColor,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            // Info Column
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
                    text = "${event.appName ?: "Unknown Process"} • ${event.payloadSize} B",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f) // Softer
                )
            }

            if (event.isSuspicious) {
                Spacer(modifier = Modifier.width(12.dp))
                
                // Elegant Soft Pulsing/Static Red Dot 
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(
                            color = MaterialTheme.colorScheme.error,
                            shape = androidx.compose.foundation.shape.CircleShape
                        )
                )
            }
        }
    }
}