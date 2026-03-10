package com.innova.analyzer.ui.alerts

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AddModerator
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.NotificationsActive
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent
import com.innova.analyzer.ui.dashboard.DashboardViewModel
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AlertsScreen(viewModel: DashboardViewModel) {
    val context = LocalContext.current

    var pushNotificationsEnabled by remember { mutableStateOf(true) }
    var strictModeEnabled by remember { mutableStateOf(false) }
    var customDomainInput by remember { mutableStateOf("") }

    // 🟢 Grab the persistent history from the shared ViewModel!
    val rawLogs by viewModel.trafficLogs.collectAsStateWithLifecycle()

    // Filter the history to ONLY show threats (or UDP if strict mode is on)
    val blockedLogs = remember(rawLogs, strictModeEnabled) {
        rawLogs.filter { event ->
            event.isSuspicious || (strictModeEnabled && event.protocol == ConnectionProtocol.UDP)
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted: Boolean ->
        if (isGranted) {
            Toast.makeText(context, "Permission Granted! Click Add again to test.", Toast.LENGTH_LONG).show()
        } else {
            Toast.makeText(context, "Notifications Blocked by Android.", Toast.LENGTH_SHORT).show()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(16.dp)
    ) {
        Text(
            text = "Threat Alerts & Rules",
            color = MaterialTheme.colorScheme.onBackground,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(bottom = 16.dp, top = 8.dp)
        )

        // --- SECTION 1: System Toggles ---
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.NotificationsActive, contentDescription = "Alerts", tint = MaterialTheme.colorScheme.primary)
                        Spacer(modifier = Modifier.width(12.dp))
                        Text("Push Notifications", color = MaterialTheme.colorScheme.onSurface, fontSize = 16.sp)
                    }
                    Switch(
                        checked = pushNotificationsEnabled,
                        onCheckedChange = { pushNotificationsEnabled = it }
                    )
                }

                HorizontalDivider(color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f), modifier = Modifier.padding(vertical = 12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Security, contentDescription = "Strict Mode", tint = MaterialTheme.colorScheme.error)
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("Strict Mode", color = MaterialTheme.colorScheme.onSurface, fontSize = 16.sp)
                            Text("Drop unknown UDP traffic", color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 12.sp)
                        }
                    }
                    Switch(
                        checked = strictModeEnabled,
                        onCheckedChange = { strictModeEnabled = it },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = MaterialTheme.colorScheme.onError,
                            checkedTrackColor = MaterialTheme.colorScheme.error
                        )
                    )
                }
            }
        }

        // --- SECTION 2: Custom Blocklist Input ---
        Card(
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)),
            modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = customDomainInput,
                    onValueChange = { customDomainInput = it },
                    label = { Text("Add Custom Rule (e.g., evil.com)", color = MaterialTheme.colorScheme.onSurfaceVariant) },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                        focusedTextColor = MaterialTheme.colorScheme.onSurface,
                        unfocusedTextColor = MaterialTheme.colorScheme.onSurface
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        if (customDomainInput.isNotBlank() && pushNotificationsEnabled) {
                            Toast.makeText(context, "Adding $customDomainInput to blocklist...", Toast.LENGTH_SHORT).show()
                            val fireNotification = {
                                val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                                val channelId = "innova_alerts"

                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                                    val channel = NotificationChannel(channelId, "Threat Alerts", NotificationManager.IMPORTANCE_HIGH)
                                    notificationManager.createNotificationChannel(channel)
                                }

                                val builder = NotificationCompat.Builder(context, channelId)
                                    .setSmallIcon(android.R.drawable.ic_secure)
                                    .setContentTitle("🛡️ Threat Blocked!")
                                    .setContentText("$customDomainInput has been added to the Strict Blocklist.")
                                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                                    .setAutoCancel(true)

                                notificationManager.notify(System.currentTimeMillis().toInt(), builder.build())
                                customDomainInput = ""
                            }

                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                                    fireNotification()
                                } else {
                                    permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                                }
                            } else {
                                fireNotification()
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.AddModerator, contentDescription = "Add Rule", tint = MaterialTheme.colorScheme.onPrimary)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Add Rule", color = MaterialTheme.colorScheme.onPrimary, fontWeight = FontWeight.Bold)
                }

                // 🟢 HACKATHON DEMO BUTTON
                Spacer(modifier = Modifier.height(16.dp))
                Button(
                    onClick = {
                        val fakeThreat = NetworkEvent(
                            uid = 10115,
                            packageName = "com.suspicious.tracker",
                            appName = "Suspicious Tracker App",
                            destIp = "192.168.1.100",
                            destPort = 443,
                            protocol = ConnectionProtocol.UDP,
                            domain = "api.malicious-tracker.com",
                            connectionKey = "test",
                            totalBytes = 512L,
                            timestamp = System.currentTimeMillis(),
                            isSuspicious = true, // Triggers the UI and logic
                            sourceIp = "10.0.0.1",
                            sourcePort = 12345
                        )

                        // Emit to the live stream so it runs through the whole architecture!
                        GlobalScope.launch {
                            TrafficStream.emitEvent(fakeThreat)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(Icons.Default.Security, contentDescription = "Simulate", tint = MaterialTheme.colorScheme.onError)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Simulate Live Threat (Demo)", color = MaterialTheme.colorScheme.onError, fontWeight = FontWeight.Bold)
                }
            }
        }

        // --- SECTION 3: Live Blocked Feed ---
        Text(
            text = "Live Blocked Feed",
            color = MaterialTheme.colorScheme.onBackground,
            fontSize = 18.sp,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(bottom = 8.dp)
        )

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
            contentPadding = PaddingValues(top = 8.dp, bottom = 80.dp) // Keep clear of the bottom nav bar!
        ) {
            if (blockedLogs.isEmpty()) {
                item {
                    Box(modifier = Modifier.fillMaxWidth().height(100.dp), contentAlignment = Alignment.Center) {
                        Text("No threats detected.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            } else {
                items(blockedLogs) { event ->
                    BlockedTrafficCard(event)
                }
            }
        }
    }
}

// 🟢 Upgraded with Timestamps!
@Composable
fun BlockedTrafficCard(event: NetworkEvent) {
    val timeString = remember(event.timestamp) {
        val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
        sdf.format(Date(event.timestamp))
    }

    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth(),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.3f))
    ) {
        Row(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.appName ?: "Background Process",
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = event.domain ?: event.destIp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 12.sp,
                    maxLines = 1
                )
            }

            Column(horizontalAlignment = Alignment.End) {
                Text(
                    text = timeString,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .background(MaterialTheme.colorScheme.error.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                        .padding(horizontal = 8.dp, vertical = 4.dp)
                ) {
                    Icon(Icons.Default.Block, contentDescription = "Blocked", tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(12.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = event.protocol.name,
                        color = MaterialTheme.colorScheme.error,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}