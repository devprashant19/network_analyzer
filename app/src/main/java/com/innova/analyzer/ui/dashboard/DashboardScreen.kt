package com.innova.analyzer.ui.dashboard

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.widget.ImageView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.innova.analyzer.core.vpn.TrafficCaptureService
import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import androidx.compose.ui.zIndex
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.compose.animation.*
import androidx.compose.foundation.clickable
import androidx.compose.ui.text.font.FontFamily
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = viewModel(),
    isDarkTheme: Boolean = true,
    onThemeToggle: () -> Unit = {}
) {
    val logs by viewModel.trafficLogs.collectAsStateWithLifecycle()
    val isVpnActive by viewModel.isVpnActive.collectAsStateWithLifecycle()

    // 🟢 The Lifetime Counter (Goes past 1,000!)
    val totalPacketCount by viewModel.totalPacketCount.collectAsStateWithLifecycle()

    val context = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val intent = Intent(context, TrafficCaptureService::class.java)
            ContextCompat.startForegroundService(context, intent)
            viewModel.setVpnActive(true)
        }
    }

    val onToggleVpn = {
        if (isVpnActive) {
            val intent = Intent(context, TrafficCaptureService::class.java).apply {
                action = "STOP_VPN"
            }
            context.startService(intent)
            viewModel.setVpnActive(false)
        } else {
            val intent = VpnService.prepare(context)
            if (intent != null) {
                vpnPermissionLauncher.launch(intent)
            } else {
                val serviceIntent = Intent(context, TrafficCaptureService::class.java)
                ContextCompat.startForegroundService(context, serviceIntent)
                viewModel.setVpnActive(true)
            }
        }
    }

    val infiniteTransition = androidx.compose.animation.core.rememberInfiniteTransition(label = "bg_anim")
    val orbOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1000f,
        animationSpec = androidx.compose.animation.core.infiniteRepeatable(
            animation = androidx.compose.animation.core.tween(20000, easing = androidx.compose.animation.core.LinearEasing),
            repeatMode = androidx.compose.animation.core.RepeatMode.Reverse
        ),
        label = "orb_float"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        val primaryColor = MaterialTheme.colorScheme.primary
        val secondaryColor = MaterialTheme.colorScheme.secondary
        val alpha1 = if (isDarkTheme) 0.15f else 0.3f
        val alpha2 = if (isDarkTheme) 0.12f else 0.25f

        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val orbRadius = size.width * 0.8f

            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(primaryColor.copy(alpha = alpha1), Color.Transparent),
                    center = androidx.compose.ui.geometry.Offset(x = orbOffset, y = orbOffset * 0.5f),
                    radius = orbRadius
                ),
                center = androidx.compose.ui.geometry.Offset(x = orbOffset, y = orbOffset * 0.5f),
                radius = orbRadius
            )

            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(secondaryColor.copy(alpha = alpha2), Color.Transparent),
                    center = androidx.compose.ui.geometry.Offset(x = size.width - orbOffset, y = size.height - (orbOffset * 0.8f)),
                    radius = orbRadius * 1.2f
                ),
                center = androidx.compose.ui.geometry.Offset(x = size.width - orbOffset, y = size.height - (orbOffset * 0.8f)),
                radius = orbRadius * 1.2f
            )
        }

        Column(modifier = Modifier.fillMaxSize()) {
            // Keep the Header above the list
            Box(modifier = Modifier.zIndex(1f)) {
                // 🟢 Pass the true totalPacketCount to the UI here
                DashboardHeader(totalPacketCount, isDarkTheme, isVpnActive, onThemeToggle, onToggleVpn)
            }

            if (logs.isEmpty()) {
                EmptyState()
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(logs) { event ->
                        NetworkRow(event)
                    }
                }
            }
        }
    }
}

@Composable
fun DashboardHeader(
    count: Int,
    isDarkTheme: Boolean,
    isVpnActive: Boolean,
    onThemeToggle: () -> Unit,
    onToggleVpn: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
        ),
        elevation = CardDefaults.cardElevation(0.dp),
        border = androidx.compose.foundation.BorderStroke(
            width = 1.dp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f)
        )
    ) {
        Box(
            modifier = Modifier.fillMaxWidth()
        ) {
            val context = LocalContext.current

            // 🟢 Left side: Manual Anomaly Trigger for Demo purposes
            IconButton(
                onClick = {
                    val workRequest = OneTimeWorkRequestBuilder<com.innova.analyzer.core.threats.BaselineAnalysisWorker>().build()
                    WorkManager.getInstance(context).enqueue(workRequest)
                    android.widget.Toast.makeText(context, "Running Anomaly Scan...", android.widget.Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.align(Alignment.TopStart).padding(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.BugReport,
                    contentDescription = "Run Anomaly Scan",
                    tint = MaterialTheme.colorScheme.error
                )
            }

            // Right side: Theme Toggle
            IconButton(
                onClick = onThemeToggle,
                modifier = Modifier.align(Alignment.TopEnd).padding(12.dp)
            ) {
                Icon(
                    imageVector = if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode,
                    contentDescription = "Toggle Theme",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Column(
                modifier = Modifier.padding(32.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .background(
                                color = if (isVpnActive) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                shape = androidx.compose.foundation.shape.CircleShape
                            )
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isVpnActive) "MONITORING ACTIVE" else "MONITORING PAUSED",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = 2.sp
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "$count", // This will now accurately reflect the full lifetime count
                    fontSize = 48.sp,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Light,
                    letterSpacing = (-1).sp
                )
                Text(
                    text = "PACKETS",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    letterSpacing = 4.sp
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = onToggleVpn,
                    modifier = Modifier.height(48.dp).fillMaxWidth(0.6f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isVpnActive) MaterialTheme.colorScheme.surface else MaterialTheme.colorScheme.primary,
                        contentColor = if (isVpnActive) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onPrimary
                    ),
                    shape = RoundedCornerShape(50)
                ) {
                    Text(
                        text = if (isVpnActive) "DISCONNECT" else "CONNECT",
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.5.sp
                    )
                }
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

@Composable
fun NativeAppIcon(uid: Int, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val packageManager = context.packageManager

    val appIconDrawable = remember(uid) {
        try {
            if (uid <= 0) null
            else {
                val packages = packageManager.getPackagesForUid(uid)
                if (!packages.isNullOrEmpty()) {
                    packageManager.getApplicationIcon(packages[0])
                } else null
            }
        } catch (e: Exception) {
            null
        }
    }

    if (appIconDrawable != null) {
        AndroidView(
            factory = { ctx ->
                ImageView(ctx).apply {
                    scaleType = ImageView.ScaleType.FIT_CENTER
                }
            },
            update = { imageView ->
                imageView.setImageDrawable(appIconDrawable)
            },
            modifier = modifier
        )
    } else {
        Icon(
            imageVector = Icons.Default.Android,
            contentDescription = "Unknown App",
            tint = MaterialTheme.colorScheme.primary,
            modifier = modifier
        )
    }
}

// 🟢 Upgraded NetworkRow with Timestamps and Threat Indicators
@Composable
fun NetworkRow(event: NetworkEvent) {
    val isDangerous = event.isSuspicious
    var expanded by remember { mutableStateOf(false) }

    // Format the timestamp (e.g., 14:32:05)
    val timeString = remember(event.timestamp) {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        sdf.format(Date(event.timestamp))
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isDangerous) MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.15f)
            else MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
        ),
        border = if (isDangerous) {
            androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.5f))
        } else null
    ) {
        Column {
            Row(
                modifier = Modifier.padding(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(40.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.surface)
                        .padding(8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    if (event.appName != null) {
                        NativeAppIcon(uid = event.uid, modifier = Modifier.fillMaxSize())
                    } else {
                        Icon(
                            imageVector = Icons.Default.Public,
                            contentDescription = "Web",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = event.appName ?: event.packageName ?: "System Process",
                        style = MaterialTheme.typography.bodyLarge,
                        color = if (isDangerous) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = event.domain ?: "${event.destIp}:${event.destPort}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // Right side: Protocol, Timestamp, and Icons
                Column(horizontalAlignment = Alignment.End) {
                    val protocolColor = when (event.protocol) {
                        ConnectionProtocol.TCP -> Color(0xFF4CAF50)
                        ConnectionProtocol.UDP -> Color(0xFF2196F3)
                        ConnectionProtocol.DNS -> Color(0xFFFF9800)
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            color = protocolColor.copy(alpha = 0.1f),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = event.protocol.name,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                style = MaterialTheme.typography.labelSmall,
                                color = protocolColor,
                                fontWeight = FontWeight.Bold
                            )
                        }

                        Spacer(modifier = Modifier.width(6.dp))

                        if (isDangerous) {
                            Icon(
                                imageVector = Icons.Default.BugReport,
                                contentDescription = "Threat",
                                tint = MaterialTheme.colorScheme.error,
                                modifier = Modifier.size(16.dp)
                            )
                        } else if (event.destPort == 443) {
                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = "Secure",
                                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.7f),
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "$timeString • ${event.totalBytes} B • ${event.packetCount} pkts",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // ==========================================
            // 2. THE DROPDOWN DETAILS (Animated)
            // ==========================================
            AnimatedVisibility(
                visible = expanded,
                enter = fadeIn() + expandVertically(animationSpec = androidx.compose.animation.core.tween(300)),
                exit = fadeOut() + shrinkVertically(animationSpec = androidx.compose.animation.core.tween(300))
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f))
                        .padding(16.dp)
                ) {
                    Text("Packet Inspection Details", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = MaterialTheme.colorScheme.primary)
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.weight(1f)) {
                            PacketDetailItem("Time", timeString)
                            PacketDetailItem("Source IP", event.sourceIp)
                            PacketDetailItem("Source Port", event.sourcePort.toString())
                            PacketDetailItem("UID", event.uid.toString())
                        }
                        Column(modifier = Modifier.weight(1f)) {
                            PacketDetailItem("Total Size", "${event.totalBytes} Bytes")
                            PacketDetailItem("Remote IP", event.destIp)
                            PacketDetailItem("Remote Port", event.destPort.toString())
                            PacketDetailItem("Remote Host", event.domain ?: "Unknown/Direct IP")
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    HorizontalDivider(color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f))
                    Spacer(modifier = Modifier.height(8.dp))

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = if (isDangerous) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = if (isDangerous) "Threat Engine: BLOCKED (Known Tracker/Malware)" else "Threat Engine: SAFE (No flags detected)",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (isDangerous) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary
                        )
                    }
                }
            }
        }
    }
}

// Helper composable for the dropdown items
@Composable
fun PacketDetailItem(label: String, value: String) {
    Column(modifier = Modifier.padding(bottom = 8.dp)) {
        Text(text = label, fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            text = value,
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.Medium,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}