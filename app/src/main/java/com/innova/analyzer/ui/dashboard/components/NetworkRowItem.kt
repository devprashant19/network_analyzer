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
        ConnectionProtocol.TCP -> Color(0xFF2196F3) // Blue
        ConnectionProtocol.UDP -> Color(0xFF4CAF50) // Green
        ConnectionProtocol.HTTPS -> Color(0xFF9C27B0) // Purple
        else -> Color.Gray
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(2.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Protocol Badge
            Box(
                modifier = Modifier
                    .size(width = 60.dp, height = 24.dp)
                    .background(protocolColor, RoundedCornerShape(4.dp)),
                contentAlignment = Alignment.Center
            ) {
                Text(event.protocol.name, color = Color.White, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            }

            Spacer(modifier = Modifier.width(12.dp))

            // Info Column
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.domain ?: "${event.destIp}:${event.destPort}",
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "${event.appName ?: "Unknown App"} • ${event.payloadSize} bytes",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color.Gray
                )
            }

            if (event.isSuspicious) {
                Text("⚠️", fontSize = 20.sp)
            }
        }
    }
}