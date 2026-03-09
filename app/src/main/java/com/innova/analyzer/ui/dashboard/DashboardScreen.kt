package com.innova.analyzer.ui.dashboard

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
import com.innova.analyzer.ui.dashboard.components.NetworkRowItem // We will create this next

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = viewModel() // Connects to our ViewModel
) {
    // Collect the Flow from Room as a State that Compose understands
    val logs by viewModel.trafficLogs.collectAsState()

    Column(modifier = Modifier.fillMaxSize()) {
        // 1. Header Area (Status)
        DashboardHeader(logs.size)

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
fun DashboardHeader(count: Int) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("VPN Status: ACTIVE", style = MaterialTheme.typography.titleMedium)
            Text("Total Packets Intercepted: $count", style = MaterialTheme.typography.bodyMedium)
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
        Icon(Icons.Default.Terminal, contentDescription = null, modifier = Modifier.size(64.dp), tint = Color.Gray)
        Spacer(modifier = Modifier.height(16.dp))
        Text("Waiting for traffic...", color = Color.Gray)
    }
}
