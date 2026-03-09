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
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(4.dp),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Protocol Badge (Pill Shaped)
            Box(
                modifier = Modifier
                    .background(
                        color = protocolColor.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(50) // Pill shape
                    )
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = event.protocol.name,
                    color = protocolColor,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.ExtraBold,
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
                    fontWeight = FontWeight.Bold,
                    maxLines = 1
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "${event.appName ?: "Unknown Process"} • ${event.payloadSize} B",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (event.isSuspicious) {
                Spacer(modifier = Modifier.width(8.dp))
                Box(
                    modifier = Modifier
                        .background(MaterialTheme.colorScheme.error.copy(alpha = 0.2f), RoundedCornerShape(8.dp))
                        .padding(8.dp)
                ) {
                    Text("⚠️", fontSize = 16.sp)
                }
            }
        }
    }
}