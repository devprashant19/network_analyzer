package com.innova.analyzer.ui.report

import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
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
import com.patrykandpatrick.vico.compose.axis.horizontal.rememberBottomAxis
import com.patrykandpatrick.vico.compose.axis.vertical.rememberStartAxis
import com.patrykandpatrick.vico.compose.chart.Chart
import com.patrykandpatrick.vico.compose.chart.column.columnChart
import com.patrykandpatrick.vico.core.entry.entryModelOf

sealed class ReportScreenState {
    object MainList : ReportScreenState()
    data class AppDetails(val appName: String) : ReportScreenState()
    object ThreatDetails : ReportScreenState()
}

data class AppSummary(
    val appName: String,
    val uid: Int,
    val totalPackets: Int,
    val threats: Int,
    val tcpCount: Int,
    val udpCount: Int,
    val dnsCount: Int,
    val httpsCount: Int,
    val httpCount: Int,
    val otherCount: Int,
    val logs: List<NetworkEvent>
)

@Composable
fun ReportScreen(viewModel: DashboardViewModel) {
    val rawLogs by viewModel.trafficLogs.collectAsStateWithLifecycle()
    var currentScreen by remember { mutableStateOf<ReportScreenState>(ReportScreenState.MainList) }
    val context = LocalContext.current

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
                    dnsCount = packets.count { it.protocol == ConnectionProtocol.DNS },
                    httpsCount = packets.count { it.protocol == ConnectionProtocol.HTTPS },
                    httpCount = packets.count { it.protocol == ConnectionProtocol.HTTP },
                    otherCount = packets.count { it.protocol != ConnectionProtocol.TCP && it.protocol != ConnectionProtocol.UDP && it.protocol != ConnectionProtocol.DNS && it.protocol != ConnectionProtocol.HTTPS && it.protocol != ConnectionProtocol.HTTP },
                    logs = packets
                )
            }.sortedByDescending { it.threats * 1000 + it.totalPackets }
    }

    val protocolCounts = remember(rawLogs) {
        listOf(
            rawLogs.count { it.protocol == ConnectionProtocol.TCP },
            rawLogs.count { it.protocol == ConnectionProtocol.UDP },
            rawLogs.count { it.protocol == ConnectionProtocol.DNS },
            rawLogs.count { it.protocol == ConnectionProtocol.HTTPS },
            rawLogs.count { it.protocol == ConnectionProtocol.HTTP }
        )
    }

    val totalBlocked = remember(rawLogs) { rawLogs.count { it.isSuspicious } }
    val topApp = appSummaries.firstOrNull()?.appName ?: "N/A"

    BackHandler(enabled = currentScreen !is ReportScreenState.MainList) {
        currentScreen = ReportScreenState.MainList
    }

    Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)) {
        Crossfade(targetState = currentScreen, label = "ReportTransition") { state ->
            when (state) {
                is ReportScreenState.MainList -> {
                    AppListReport(
                        summaries = appSummaries,
                        protocolCounts = protocolCounts,
                        totalBlocked = totalBlocked,
                        topApp = topApp,
                        onAppClick = { currentScreen = ReportScreenState.AppDetails(it.appName) },
                        onThreatClick = { currentScreen = ReportScreenState.ThreatDetails },
                        onShare = { sharePrivacyReport(context, totalBlocked, topApp) },
                        onClearData = { viewModel.clearSessionData() }
                    )
                }
                is ReportScreenState.AppDetails -> {
                    val liveAppSummary = appSummaries.find { it.appName == state.appName }
                    if (liveAppSummary != null) {
                        AppDetailReport(liveAppSummary) { currentScreen = ReportScreenState.MainList }
                    } else {
                        currentScreen = ReportScreenState.MainList
                    }
                }
                is ReportScreenState.ThreatDetails -> {
                    ThreatDetailReport(allLogs = rawLogs, onBackClick = { currentScreen = ReportScreenState.MainList })
                }
            }
        }
    }
}

@Composable
fun AppListReport(
    summaries: List<AppSummary>,
    protocolCounts: List<Int>,
    totalBlocked: Int,
    topApp: String,
    onAppClick: (AppSummary) -> Unit,
    onThreatClick: () -> Unit,
    onShare: () -> Unit,
    onClearData: () -> Unit
) {
    LazyColumn(modifier = Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Security Report", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                IconButton(onClick = onShare) { Icon(Icons.Default.Share, contentDescription = "Share", tint = MaterialTheme.colorScheme.primary) }
            }
        }

        item { ClickableThreatRow(totalBlocked, onThreatClick) }

        if (summaries.isNotEmpty()) {
            item { TopAppsChartCard(summaries.take(5)) }
            item { ProtocolPieChartCard(protocolCounts) }
        }

        item { Text("Detailed Application Breakdown", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp)) }

        if (summaries.isEmpty()) {
            item { Box(Modifier.fillMaxWidth().height(100.dp), contentAlignment = Alignment.Center) { Text("No session data found", color = MaterialTheme.colorScheme.onSurfaceVariant) } }
        } else {
            items(summaries, key = { it.appName }) { summary -> AppSummaryCard(summary) { onAppClick(summary) } }
        }

        item {
            Button(onClick = onClearData, modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp), colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.errorContainer, contentColor = MaterialTheme.colorScheme.onErrorContainer), shape = RoundedCornerShape(12.dp)) {
                Icon(Icons.Default.DeleteSweep, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("End Session & Clear Database")
            }
            Spacer(Modifier.height(80.dp))
        }
    }
}

// 🟢 NEW: Anchored to (0,0) Origin
@Composable
fun TrafficTrendGraph(logs: List<NetworkEvent>, modifier: Modifier = Modifier) {
    if (logs.isEmpty()) return

    val trendPoints = remember(logs) {
        val orderedLogs = logs.reversed() // Oldest to newest
        val chunkSize = maxOf(1, orderedLogs.size / 20)

        // 🟢 FIX: We artificially inject a '0f' at the very beginning of both lists
        // This forces the Canvas Path to start drawing exactly at the (0,0) origin!
        val safeCounts = mutableListOf<Float>(0f)
        val threatCounts = mutableListOf<Float>(0f)

        orderedLogs.chunked(chunkSize).forEach { chunk ->
            safeCounts.add(chunk.count { !it.isSuspicious }.toFloat())
            threatCounts.add(chunk.count { it.isSuspicious }.toFloat())
        }
        Pair(safeCounts, threatCounts)
    }

    val safeData = trendPoints.first
    val threatData = trendPoints.second
    val overallMax = maxOf(safeData.maxOrNull() ?: 1f, threatData.maxOrNull() ?: 1f, 1f)

    val safeColor = MaterialTheme.colorScheme.primary
    val threatColor = MaterialTheme.colorScheme.error
    val axisColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)

    Canvas(modifier = modifier) {
        val width = size.width
        val height = size.height

        val paddingBottom = 20f
        val paddingLeft = 20f
        val paddingTop = 10f

        val graphWidth = width - paddingLeft
        val graphHeight = height - paddingBottom - paddingTop

        // Draw the Y-Axis
        drawLine(
            color = axisColor,
            start = Offset(paddingLeft, paddingTop),
            end = Offset(paddingLeft, height - paddingBottom),
            strokeWidth = 3f
        )
        // Draw the X-Axis
        drawLine(
            color = axisColor,
            start = Offset(paddingLeft, height - paddingBottom),
            end = Offset(width, height - paddingBottom),
            strokeWidth = 3f
        )

        val safePath = Path()
        val threatPath = Path()
        val stepX = graphWidth / maxOf(1, safeData.size - 1).toFloat()

        safeData.forEachIndexed { index, value ->
            val x = paddingLeft + (index * stepX)
            val y = (height - paddingBottom) - ((value / overallMax) * graphHeight)
            // Because index 0 is the 0f we injected, it starts exactly at the axis intersection!
            if (index == 0) safePath.moveTo(x, y) else safePath.lineTo(x, y)
        }

        threatData.forEachIndexed { index, value ->
            val x = paddingLeft + (index * stepX)
            val y = (height - paddingBottom) - ((value / overallMax) * graphHeight)
            if (index == 0) threatPath.moveTo(x, y) else threatPath.lineTo(x, y)
        }

        // Draw the Lines
        drawPath(path = safePath, color = safeColor, style = Stroke(width = 4f, cap = StrokeCap.Round))
        drawPath(path = threatPath, color = threatColor, style = Stroke(width = 4f, cap = StrokeCap.Round))
    }
}

@Composable
fun AppSummaryCard(summary: AppSummary, onClick: () -> Unit) {
    val isDangerous = summary.threats > 0

    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isDangerous) MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        ),
        border = androidx.compose.foundation.BorderStroke(
            width = if (isDangerous) 1.dp else 0.5.dp,
            color = if (isDangerous) MaterialTheme.colorScheme.error.copy(alpha = 0.6f) else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f)
        ),
        modifier = Modifier.fillMaxWidth().clickable { onClick() }
    ) {
        Row(modifier = Modifier.padding(16.dp).fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(48.dp).clip(CircleShape).background(MaterialTheme.colorScheme.surface), contentAlignment = Alignment.Center) {
                NativeAppIcon(uid = summary.uid, modifier = Modifier.size(32.dp))
            }
            Spacer(modifier = Modifier.width(16.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(summary.appName, color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold, fontSize = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${summary.totalPackets} pkts", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text("TCP: ${summary.tcpCount} | UDP: ${summary.udpCount} | DNS: ${summary.dnsCount}", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp)

                if (isDangerous) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.BugReport, contentDescription = "Threats", tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(12.dp))
                        Text(" ${summary.threats} connection(s) blocked", color = MaterialTheme.colorScheme.error, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
    }
}

@Composable
fun AppDetailReport(summary: AppSummary, onBackClick: () -> Unit) {
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 16.dp)) {
            IconButton(onClick = onBackClick) { Icon(Icons.Default.ArrowBack, contentDescription = "Back") }
            Spacer(modifier = Modifier.width(8.dp))
            NativeAppIcon(uid = summary.uid, modifier = Modifier.size(32.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Text(text = summary.appName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatBox(title = "Packets", value = summary.totalPackets.toString(), color = MaterialTheme.colorScheme.primary, modifier = Modifier.weight(1f))
            StatBox(title = "Blocked", value = summary.threats.toString(), color = MaterialTheme.colorScheme.error, modifier = Modifier.weight(1f))
        }
        Spacer(modifier = Modifier.height(8.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            StatBox(title = "TCP", value = summary.tcpCount.toString(), color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
            StatBox(title = "UDP", value = summary.udpCount.toString(), color = MaterialTheme.colorScheme.secondary, modifier = Modifier.weight(1f))
            StatBox(title = "DNS", value = summary.dnsCount.toString(), color = MaterialTheme.colorScheme.tertiary, modifier = Modifier.weight(1f))
        }

        Spacer(modifier = Modifier.height(24.dp))

        if (summary.logs.isNotEmpty()) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text("Activity Timeline", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Circle, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(8.dp))
                    Text(" Safe  ", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Icon(Icons.Default.Circle, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(8.dp))
                    Text(" Blocked", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(modifier = Modifier.height(12.dp))

            // The X-Y Plane Line Graph (Anchored to 0,0)
            TrafficTrendGraph(
                logs = summary.logs,
                modifier = Modifier.fillMaxWidth().height(120.dp).padding(end = 8.dp)
            )
            Spacer(modifier = Modifier.height(24.dp))
        }

        Text("Full Connection History", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        LazyColumn(modifier = Modifier.fillMaxSize(), contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp)) {
            items(summary.logs) { event -> NetworkRow(event) }
        }
    }
}

@Composable
fun ClickableThreatRow(totalBlocked: Int, onClick: () -> Unit) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = if (totalBlocked > 0) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)),
        modifier = Modifier.fillMaxWidth().clickable { if (totalBlocked > 0) onClick() }
    ) {
        Row(modifier = Modifier.padding(16.dp).fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(imageVector = Icons.Default.BugReport, contentDescription = "Threats", tint = if (totalBlocked > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(modifier = Modifier.width(12.dp))
                Column {
                    Text(text = "$totalBlocked Trackers Blocked", fontWeight = FontWeight.Bold, color = if (totalBlocked > 0) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 18.sp)
                    if (totalBlocked > 0) {
                        Text("Tap to view isolated threat processes", fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
                    } else {
                        Text("Network is currently clean", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (totalBlocked > 0) { Icon(Icons.Default.ChevronRight, contentDescription = "View", tint = MaterialTheme.colorScheme.error) }
        }
    }
}

@Composable
fun ThreatDetailReport(allLogs: List<NetworkEvent>, onBackClick: () -> Unit) {
    val blockedLogs = remember(allLogs) { allLogs.filter { it.isSuspicious } }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 16.dp)) {
            IconButton(onClick = onBackClick) { Icon(Icons.Default.ArrowBack, contentDescription = "Back") }
            Spacer(modifier = Modifier.width(8.dp))
            Icon(Icons.Default.Security, contentDescription = "Threats", tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(32.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Text(text = "Isolated Threats", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        }
        Text("These packets were intercepted attempting to contact known privacy trackers. Innova Firewall has blocked the transmission.", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp, modifier = Modifier.padding(bottom = 16.dp))

        LazyColumn(modifier = Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 80.dp)) {
            items(blockedLogs) { event -> NetworkRow(event) }
        }
    }
}

@Composable
fun StatBox(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(shape = RoundedCornerShape(12.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)), modifier = modifier) {
        Column(modifier = Modifier.padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            Text(text = value, color = color, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text(text = title, style = MaterialTheme.typography.labelSmall)
        }
    }
}

fun sharePrivacyReport(context: Context, blocked: Int, topApp: String) {
    val message = "🛡️ Innova Security Audit 🛡️\n$blocked privacy trackers blocked.\nMost active network app: $topApp.\n\nSecured by Innova Analyzer."
    val intent = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, message) }
    context.startActivity(Intent.createChooser(intent, "Share Security Report"))
}

@Composable
fun TopAppsChartCard(topApps: List<AppSummary>) {
    Card(shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)), modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Top Data Consumers", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Spacer(modifier = Modifier.height(16.dp))
            val chartEntryModel = entryModelOf(*topApps.map { it.totalPackets.toFloat() }.toTypedArray())
            Chart(chart = columnChart(), model = chartEntryModel, startAxis = rememberStartAxis(label = null, guideline = null), bottomAxis = rememberBottomAxis(valueFormatter = { value, _ -> topApps.getOrNull(value.toInt())?.appName?.take(5) ?: "" }), modifier = Modifier.fillMaxWidth().height(140.dp))
        }
    }
}

@Composable
fun ProtocolPieChartCard(counts: List<Int>) {
    val labels = listOf("TCP", "UDP", "DNS", "HTTPS", "HTTP")
    val colors = listOf(
        MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha=0.6f),
        MaterialTheme.colorScheme.secondary,
        MaterialTheme.colorScheme.tertiary,
        MaterialTheme.colorScheme.primary,
        MaterialTheme.colorScheme.error
    )
    Card(shape = RoundedCornerShape(16.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)), modifier = Modifier.fillMaxWidth()) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(100.dp), contentAlignment = Alignment.Center) {
                val total = counts.sum().coerceAtLeast(1)
                var startAngle = -90f
                Canvas(modifier = Modifier.size(100.dp)) {
                    counts.forEachIndexed { index, count ->
                        val sweepAngle = (count.toFloat() / total) * 360f
                        if (sweepAngle > 0) { drawArc(color = colors[index], startAngle = startAngle, sweepAngle = sweepAngle, useCenter = true); startAngle += sweepAngle }
                    }
                }
            }
            Spacer(modifier = Modifier.width(24.dp))
            Column {
                Text("Protocol Map", fontWeight = FontWeight.Bold)
                counts.forEachIndexed { index, count ->
                    if (count > 0) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Circle, contentDescription = null, tint = colors[index], modifier = Modifier.size(10.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("${labels[index]}: $count", fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
