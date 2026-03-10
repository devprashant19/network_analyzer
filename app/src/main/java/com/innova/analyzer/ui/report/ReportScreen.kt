package com.innova.analyzer.ui.report

import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.animation.Crossfade
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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

// 🟢 NEW: Data class to hold the exact score breakdown
data class ScoreBreakdown(
    val finalScore: Int,
    val grade: String,
    val color: Color,
    val reasons: List<String>
)

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
    val logs: List<NetworkEvent>,
    val scoreBreakdown: ScoreBreakdown // 🟢 Attached the Score to the App!
)

// 🟢 NEW: The Core Scoring Algorithm
fun calculatePrivacyScore(packets: List<NetworkEvent>): ScoreBreakdown {
    var score = 100f
    val reasons = mutableListOf<String>()
    val total = packets.size.coerceAtLeast(1)

    // Factor 1: Trackers & Threats (High Penalty)
    val threats = packets.count { it.isSuspicious }
    if (threats > 0) {
        val threatRatio = threats.toFloat() / total
        val penalty = (threatRatio * 60f).coerceAtMost(60f)
        score -= penalty
        reasons.add("🚨 Lost ${penalty.toInt()} pts: $threats tracking/malicious attempts.")
    } else {
        reasons.add("✅ Perfect threat record (0 trackers).")
    }

    // Factor 2: Unencrypted HTTP Traffic (Medium Penalty)
    val httpCount = packets.count { it.protocol == ConnectionProtocol.HTTP || it.destPort == 80 }
    if (httpCount > 0) {
        val httpRatio = httpCount.toFloat() / total
        val penalty = (httpRatio * 30f).coerceAtMost(30f)
        score -= penalty
        reasons.add("🔓 Lost ${penalty.toInt()} pts: $httpCount unencrypted HTTP packets.")
    } else {
        reasons.add("🔒 100% Encrypted or secure traffic.")
    }

    // Factor 3: Domain Dispersion / Data Spreading (Low/Medium Penalty)
    val uniqueDomains = packets.mapNotNull { it.domain ?: it.destIp }.toSet().size
    if (uniqueDomains > 3) {
        val penalty = ((uniqueDomains - 3) * 2f).coerceAtMost(15f)
        score -= penalty
        reasons.add("🌐 Lost ${penalty.toInt()} pts: Contacted $uniqueDomains unique remote servers.")
    } else {
        reasons.add("🎯 Excellent server focus ($uniqueDomains domains contacted).")
    }

    val finalScore = score.toInt().coerceIn(0, 100)
    val (grade, color) = when (finalScore) {
        in 90..100 -> "A" to Color(0xFF4CAF50) // Green
        in 75..89 -> "B" to Color(0xFF2196F3)  // Blue
        in 60..74 -> "C" to Color(0xFFFFC107)  // Yellow
        in 40..59 -> "D" to Color(0xFFFF9800)  // Orange
        else -> "F" to Color(0xFFF44336)       // Red
    }

    return ScoreBreakdown(finalScore, grade, color, reasons)
}

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
                    httpCount = packets.count { it.protocol == ConnectionProtocol.HTTP || packets.any { it.destPort == 80 } },
                    otherCount = packets.count { it.protocol != ConnectionProtocol.TCP && it.protocol != ConnectionProtocol.UDP && it.protocol != ConnectionProtocol.DNS && it.protocol != ConnectionProtocol.HTTPS && it.protocol != ConnectionProtocol.HTTP },
                    logs = packets,
                    scoreBreakdown = calculatePrivacyScore(packets) // 🟢 Generate the Score!
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
                        summaries = appSummaries, protocolCounts = protocolCounts,
                        totalBlocked = totalBlocked, topApp = topApp,
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
                    } else currentScreen = ReportScreenState.MainList
                }
                is ReportScreenState.ThreatDetails -> ThreatDetailReport(rawLogs) { currentScreen = ReportScreenState.MainList }
            }
        }
    }
}

@Composable
fun AppListReport(
    summaries: List<AppSummary>, protocolCounts: List<Int>, totalBlocked: Int, topApp: String,
    onAppClick: (AppSummary) -> Unit, onThreatClick: () -> Unit, onShare: () -> Unit, onClearData: () -> Unit
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

        item { Text("Application Trust Scores", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 12.dp)) }

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

// 🟢 UPDATED: App Card now displays the Letter Grade
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

            Spacer(modifier = Modifier.width(12.dp))

            // 🟢 The Grade Badge!
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(summary.scoreBreakdown.color.copy(alpha = 0.2f))
                    .border(2.dp, summary.scoreBreakdown.color, CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = summary.scoreBreakdown.grade,
                    color = summary.scoreBreakdown.color,
                    fontWeight = FontWeight.ExtraBold,
                    fontSize = 20.sp
                )
            }
        }
    }
}

// 🟢 UPDATED: Detail Report now breaks down exactly WHY they got that score
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

        // 🟢 Score Header
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = summary.scoreBreakdown.color.copy(alpha = 0.1f)),
            shape = RoundedCornerShape(24.dp)
        ) {
            Row(modifier = Modifier.padding(24.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(80.dp).clip(CircleShape).background(summary.scoreBreakdown.color.copy(alpha = 0.2f)).border(4.dp, summary.scoreBreakdown.color, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(summary.scoreBreakdown.grade, fontSize = 42.sp, fontWeight = FontWeight.Black, color = summary.scoreBreakdown.color)
                }
                Spacer(modifier = Modifier.width(20.dp))
                Column {
                    Text("Privacy Score: ${summary.scoreBreakdown.finalScore}/100", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
                    Text("Security Assessment", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text("Why this score?", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        summary.scoreBreakdown.reasons.forEach { reason ->
            Text("• $reason", modifier = Modifier.padding(vertical = 4.dp), style = MaterialTheme.typography.bodyMedium)
        }

        Spacer(modifier = Modifier.height(24.dp))
        Text("Recent Activity", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)

        LazyColumn(modifier = Modifier.weight(1f)) {
            items(summary.logs.reversed()) { log -> NetworkRow(log) }
        }
    }
}

@Composable
fun ThreatDetailReport(logs: List<NetworkEvent>, onBackClick: () -> Unit) {
    val threats = remember(logs) { logs.filter { it.isSuspicious } }
    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBackClick) { Icon(Icons.Default.ArrowBack, contentDescription = "Back") }
            Text("Blocked Threats", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        }
        if (threats.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("No threats detected!") }
        } else {
            LazyColumn { items(threats.reversed()) { log -> NetworkRow(log) } }
        }
    }
}

@Composable
fun ClickableThreatRow(count: Int, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = if (count > 0) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.primaryContainer)
    ) {
        Row(modifier = Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(if (count > 0) Icons.Default.SecurityUpdateWarning else Icons.Default.Shield, contentDescription = null)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(if (count > 0) "$count Threats Blocked" else "Device is Secure", fontWeight = FontWeight.Bold)
                Text("Tap to view filtered security logs", fontSize = 12.sp)
            }
        }
    }
}

@Composable
fun ProtocolPieChartCard(counts: List<Int>) {
    val labels = listOf("TCP", "UDP", "DNS", "HTTPS", "HTTP")
    val total = counts.sum().coerceAtLeast(1)

    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Traffic Distribution", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(16.dp))
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(modifier = Modifier.size(120.dp), contentAlignment = Alignment.Center) {
                    Canvas(modifier = Modifier.fillMaxSize()) {
                        var startAngle = -90f
                        val colors = listOf(Color(0xFF2196F3), Color(0xFF4CAF50), Color(0xFFFFC107), Color(0xFF9C27B0), Color(0xFFF44336))
                        counts.forEachIndexed { index, count ->
                            val sweep = (count.toFloat() / total) * 360f
                            drawArc(colors[index % colors.size], startAngle, sweep, false, style = Stroke(20f, cap = StrokeCap.Round))
                            startAngle += sweep
                        }
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("${(counts.maxOrNull() ?: 0) * 100 / total}%", fontWeight = FontWeight.Black)
                        Text("Top", fontSize = 10.sp)
                    }
                }
                Spacer(Modifier.width(24.dp))
                Column {
                    labels.forEachIndexed { i, label ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(8.dp).background(listOf(Color(0xFF2196F3), Color(0xFF4CAF50), Color(0xFFFFC107), Color(0xFF9C27B0), Color(0xFFF44336))[i], CircleShape))
                            Text(" $label: ${counts[i]}", fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun TopAppsChartCard(summaries: List<AppSummary>) {
    val model = entryModelOf(*summaries.map { it.totalPackets.toFloat() }.toTypedArray())
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp)) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Top Bandwidth Users", fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Chart(
                chart = columnChart(),
                model = model,
                startAxis = rememberStartAxis(),
                bottomAxis = rememberBottomAxis(),
                modifier = Modifier.height(150.dp)
            )
        }
    }
}

fun sharePrivacyReport(context: Context, blocked: Int, topApp: String) {
    val text = "🛡️ My Device Privacy Report\n\n" +
            "✅ Threats Blocked: $blocked\n" +
            "📱 Most Active App: $topApp\n\n" +
            "Analyzing my network traffic with Innova Analyzer."
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, "Share Report"))
}
