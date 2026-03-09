package com.innova.analyzer.ui.dashboard

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.innova.analyzer.data.models.NetworkEvent
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import com.innova.analyzer.ui.dashboard.components.NetworkRowItem

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = viewModel(), // Connects to our ViewModel
    isDarkTheme: Boolean = true,
    onThemeToggle: () -> Unit = {}
) {
    // Collect the Flow from Room as a State that Compose understands
    val logs by viewModel.trafficLogs.collectAsState()

    Column(modifier = Modifier.fillMaxSize()) {
        // 1. Header Area (Status)
        DashboardHeader(logs.size, isDarkTheme, onThemeToggle)

        // 2. The Live Feed
        if (logs.isEmpty()) {
            EmptyState()
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(logs) { event ->
                    NetworkRowItem(event)
                }
            }
        }
    }
}

@Composable
fun DashboardHeader(count: Int, isDarkTheme: Boolean, onThemeToggle: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
        shape = androidx.compose.foundation.shape.RoundedCornerShape(16.dp),
        elevation = CardDefaults.cardElevation(8.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = androidx.compose.ui.graphics.Brush.linearGradient(
                        colors = listOf(
                            MaterialTheme.colorScheme.primary.copy(alpha = 0.8f),
                            MaterialTheme.colorScheme.secondary.copy(alpha = 0.8f)
                        )
                    )
                )
        ) {
            // Theme Toggle Button in Top Right
            IconButton(
                onClick = onThemeToggle,
                modifier = Modifier.align(Alignment.TopEnd).padding(8.dp)
            ) {
                Icon(
                    imageVector = if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode,
                    contentDescription = "Toggle Theme",
                    tint = Color.White
                )
            }

            Column(
                modifier = Modifier.padding(24.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "SYSTEM ACTIVE",
                    style = MaterialTheme.typography.titleLarge,
                    color = Color.White,
                    fontWeight = androidx.compose.ui.text.font.FontWeight.Black,
                    letterSpacing = 2.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "$count PACKETS INTERCEPTED",
                    style = MaterialTheme.typography.labelLarge,
                    color = Color.White.copy(alpha = 0.9f),
                    letterSpacing = 1.sp
                )
            }
        }
    }
}

@Composable
fun EmptyState() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Terminal,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
        )
        Spacer(modifier = Modifier.height(24.dp))
        Text(
            text = "AWAITING TRAFFIC...",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.titleMedium,
            letterSpacing = 2.sp
        )
    }
}
