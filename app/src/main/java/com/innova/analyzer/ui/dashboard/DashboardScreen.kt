package com.innova.analyzer.ui.dashboard

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.animateFloat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.innova.analyzer.core.vpn.TrafficCaptureService
import com.innova.analyzer.data.models.NetworkEvent
import com.innova.analyzer.ui.dashboard.components.NetworkRowItem

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = viewModel(),
    isDarkTheme: Boolean = true,
    onThemeToggle: () -> Unit = {}
) {
    val logs by viewModel.trafficLogs.collectAsState()
    val isVpnActive by viewModel.isVpnActive.collectAsState()
    val context = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val intent = Intent(context, TrafficCaptureService::class.java)
            context.startService(intent)
            viewModel.setVpnActive(true)
        }
    }

    // 🚨 The Updated Button Click Handler (With Poison Pill)
    val onToggleVpn = {
        if (isVpnActive) {
            // FIRE THE POISON PILL!
            // Notice we use startService() to send a message INTO the running service
            val intent = Intent(context, TrafficCaptureService::class.java).apply {
                action = "STOP_VPN"
            }
            context.startService(intent)
            viewModel.setVpnActive(false)

        } else {
            // Ask Android OS for permission to turn it on
            val intent = VpnService.prepare(context)
            if (intent != null) {
                vpnPermissionLauncher.launch(intent)
            } else {
                val serviceIntent = Intent(context, TrafficCaptureService::class.java)
                context.startService(serviceIntent)
                viewModel.setVpnActive(true)
            }
        }
    }

    // Elegant Animated Background Orbs
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
        // Render 2 soft glowing orbs to create a dynamic aesthetic
        val primaryColor = MaterialTheme.colorScheme.primary
        val secondaryColor = MaterialTheme.colorScheme.secondary
        val alpha1 = if (isDarkTheme) 0.15f else 0.3f
        val alpha2 = if (isDarkTheme) 0.12f else 0.25f

        androidx.compose.foundation.Canvas(modifier = Modifier.fillMaxSize()) {
            val orbRadius = size.width * 0.8f

            // Orb 1 (Cyan)
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        primaryColor.copy(alpha = alpha1),
                        Color.Transparent
                    ),
                    center = androidx.compose.ui.geometry.Offset(x = orbOffset, y = orbOffset * 0.5f),
                    radius = orbRadius
                ),
                center = androidx.compose.ui.geometry.Offset(x = orbOffset, y = orbOffset * 0.5f),
                radius = orbRadius
            )

            // Orb 2 (Purple)
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(
                        secondaryColor.copy(alpha = alpha2),
                        Color.Transparent
                    ),
                    center = androidx.compose.ui.geometry.Offset(x = size.width - orbOffset, y = size.height - (orbOffset * 0.8f)),
                    radius = orbRadius * 1.2f
                ),
                center = androidx.compose.ui.geometry.Offset(x = size.width - orbOffset, y = size.height - (orbOffset * 0.8f)),
                radius = orbRadius * 1.2f
            )
        }

        Column(modifier = Modifier.fillMaxSize()) {
            DashboardHeader(logs.size, isDarkTheme, isVpnActive, onThemeToggle, onToggleVpn)

            if (logs.isEmpty()) {
                EmptyState()
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(logs) { event ->
                        NetworkRowItem(event)
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
        shape = RoundedCornerShape(24.dp), // More modern, pill-like rounding
        colors = CardDefaults.cardColors(
            // Glassmorphism effect
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
        ),
        elevation = CardDefaults.cardElevation(0.dp), // Flat integration, relies on stroke and background
        border = androidx.compose.foundation.BorderStroke(
            width = 1.dp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.08f)
        )
    ) {
        Box(
            modifier = Modifier.fillMaxWidth()
        ) {
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
                // Elegant Status Dot
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
                    text = "$count",
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

                // Elegant Pill Button
                Button(
                    onClick = onToggleVpn,
                    modifier = Modifier.height(48.dp).fillMaxWidth(0.6f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isVpnActive) MaterialTheme.colorScheme.surface else MaterialTheme.colorScheme.primary,
                        contentColor = if (isVpnActive) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onPrimary
                    ),
                    shape = RoundedCornerShape(50) // Perfect pill
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