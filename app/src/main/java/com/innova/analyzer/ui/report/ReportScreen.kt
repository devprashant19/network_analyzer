package com.innova.analyzer.ui.report

import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent
import com.innova.analyzer.ui.dashboard.DashboardViewModel
import com.innova.analyzer.ui.dashboard.NativeAppIcon
import com.innova.analyzer.ui.dashboard.NetworkRow

// 🟢 The Data Structure for our Intelligence Dossier
data class AppSummary(
    val appName: String,
    val uid: Int,
    val totalPackets: Int,
    val threats: Int,
    val tcpCount: Int,
    val udpCount: Int,
    val otherCount: Int,
    val logs: List<NetworkEvent>
)

@Composable
fun ReportScreen(viewModel: DashboardViewModel) {
    // Steal the live logs from the Shared DashboardViewModel!
    val rawLogs by viewModel.trafficLogs.collectAsStateWithLifecycle()

    // State to track if we are looking at the main list or a specific app
    var selectedApp by remember { mutableStateOf<AppSummary?>(null) }

    // 🟢 The Aggregation Engine: Groups raw packets into App Summaries
    val appSummaries = remember(rawLogs) {
        rawLogs.groupBy { it.appName ?: "System Process" }
            .map { (name, packets) ->
                AppSummary(
                    appName = name,
                    uid = packets.first().uid,
                    totalPackets = packets.size,
                    threats = packets.count { it.isSuspicious },
                    tcpCount = packets.count { it.protocol == ConnectionProtocol.TCP },
                    udpCount = packets.count { it.protocol == ConnectionProtocol.UDP },
                    otherCount = packets.count { it.protocol != ConnectionProtocol.TCP && it.protocol != ConnectionProtocol.UDP },
                    logs = packets
                )
            }
            // Sort so the most dangerous/active apps are at the top
            .sortedByDescending { it.threats * 1000 + it.totalPackets }
    }

    // Handle Android system back button to close the detail view
    BackHandler(enabled = selectedApp != null) {
        selectedApp = null
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        // Crossfade gives a beautiful, smooth transition between the list and the details
        Crossfade(targetState = selectedApp, label = "ReportTransition") { currentSelectedApp ->
            if (currentSelectedApp == null) {
                // Show the Main Leaderboard
                AppListReport(appSummaries) { clickedApp ->
                    selectedApp = clickedApp
                }
            } else {
                // Show the specific App's Intelligence Dossier
                val liveAppSummary = appSummaries.find { it.appName == currentSelectedApp.appName } ?: currentSelectedApp
                AppDetailReport(liveAppSummary) {
                    selectedApp = null // Go back
                }
            }
        }
    }
}

@Composable
fun AppListReport(summaries: List<AppSummary>, onAppClick: (AppSummary) -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text(
            text = "Security Audit Report",
            color = MaterialTheme.colorScheme.onBackground,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(top = 8.dp, bottom = 4.dp)
        )
        Text(
            text = "Tap any application to view its network dossier.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 14.sp,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        if (summaries.isEmpty()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No traffic recorded yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(summaries, key = { it.appName }) { summary ->
                    AppSummaryCard(summary) { onAppClick(summary) }
                }
            }
        }
    }
}

@Composable
fun AppSummaryCard(summary: AppSummary, onClick: () -> Unit) {
    val isDangerous = summary.threats > 0

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isDangerous) MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f)
            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        ),
        border = androidx.compose.foundation.BorderStroke(
            width = if (isDangerous) 1.dp else 0.5.dp,
            color = if (isDangerous) MaterialTheme.colorScheme.error.copy(alpha = 0.6f)
            else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f)
        ),
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp)
            .clickable { onClick() }
    ) {
        Row(
            modifier = Modifier.padding(16.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.surface),
                contentAlignment = Alignment.Center
            ) {
                NativeAppIcon(uid = summary.uid, modifier = Modifier.size(32.dp))
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = summary.appName,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("${summary.totalPackets} Total Packets", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                    if (isDangerous) {
                        Spacer(modifier = Modifier.width(8.dp))
                        Icon(Icons.Default.BugReport, contentDescription = "Threats", tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(12.dp))
                        Text(" ${summary.threats} Blocked", color = MaterialTheme.colorScheme.error, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
fun AppDetailReport(summary: AppSummary, onBackClick: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        // --- Header & Back Button ---
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp, bottom = 16.dp)) {
            IconButton(onClick = onBackClick) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = MaterialTheme.colorScheme.onBackground)
            }
            Spacer(modifier = Modifier.width(8.dp))
            Box(
                modifier = Modifier.size(40.dp).clip(CircleShape).background(MaterialTheme.colorScheme.surface),
                contentAlignment = Alignment.Center
            ) {
                NativeAppIcon(uid = summary.uid, modifier = Modifier.size(24.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = summary.appName,
                color = MaterialTheme.colorScheme.onBackground,
                fontSize = 22.sp,
                fontWeight = FontWeight.Bold,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        // --- The Stats Grid ---
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatBox(title = "Total Intercepts", value = summary.totalPackets.toString(), color = Color(0xFF29B6F6), modifier = Modifier.weight(1f))
            StatBox(title = "Threats Blocked", value = summary.threats.toString(), color = if (summary.threats > 0) MaterialTheme.colorScheme.error else Color(0xFF00E676), modifier = Modifier.weight(1f))
        }
        Spacer(modifier = Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatBox(title = "TCP (Standard)", value = summary.tcpCount.toString(), color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
            StatBox(title = "UDP (Hidden)", value = summary.udpCount.toString(), color = Color(0xFFFF9100), modifier = Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text("Raw Connection Log", color = MaterialTheme.colorScheme.onBackground, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Spacer(modifier = Modifier.height(8.dp))

        // --- The Raw Logs List ---
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            // 🟢 FIXED: 'key' is removed here to prevent crashes from rapid duplicate UDP packets!
            items(summary.logs) { event ->
                NetworkRow(event)
            }
        }
    }
}

@Composable
fun StatBox(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)),
        modifier = modifier
    ) {
        Column(modifier = Modifier.padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(text = value, color = color, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text(text = title, color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)
        }
    }
}