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
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.compose.ui.platform.LocalContext
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.launch
import kotlinx.coroutines.GlobalScope // Required for the demo button simulation

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AlertsScreen() {
    val context = LocalContext.current

    var pushNotificationsEnabled by remember { mutableStateOf(true) }
    var strictModeEnabled by remember { mutableStateOf(false) }
    var customDomainInput by remember { mutableStateOf("") }

    val blockedLogs = remember { mutableStateListOf<NetworkEvent>() }

    // 🟢 The Live Memory List + Smart Notification Debouncer
    LaunchedEffect(strictModeEnabled, pushNotificationsEnabled) {
        val lastNotifiedTime = mutableMapOf<String, Long>()

        TrafficStream.trafficFlow.collect { event ->
            val isThreat = event.isSuspicious
            val isStrictUdpDrop = strictModeEnabled && event.protocol == ConnectionProtocol.UDP

            if (isThreat || isStrictUdpDrop) {
                // 1. Update visual list
                blockedLogs.add(0, event)
                if (blockedLogs.size > 50) {
                    blockedLogs.removeLast()
                }

                // 2. Handle Push Notifications with Spam Filter
                if (pushNotificationsEnabled && isStrictUdpDrop) {
                    val appName = event.appName ?: "Background Process"
                    val currentTime = System.currentTimeMillis()

                    // Only notify once every 5 seconds per app
                    if (currentTime - (lastNotifiedTime[appName] ?: 0L) > 5000L) {
                        lastNotifiedTime[appName] = currentTime

                        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                        val channelId = "innova_alerts"

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            val channel = NotificationChannel(
                                channelId,
                                "Threat Alerts",
                                NotificationManager.IMPORTANCE_HIGH
                            )
                            notificationManager.createNotificationChannel(channel)
                        }

                        val notificationId = appName.hashCode()

                        val builder = NotificationCompat.Builder(context, channelId)
                            .setSmallIcon(android.R.drawable.ic_secure)
                            .setContentTitle("🛡️ Strict Mode Active")
                            .setContentText("Blocked hidden UDP traffic from $appName.")
                            .setPriority(NotificationCompat.PRIORITY_HIGH)
                            .setAutoCancel(true)

                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            if (ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                                notificationManager.notify(notificationId, builder.build())
                            }
                        } else {
                            notificationManager.notify(notificationId, builder.build())
                        }
                    }
                }
            }
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

                // 🟢 NEW: HACKATHON DEMO BUTTON
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
                            payloadSize = 512,
                            timestamp = System.currentTimeMillis(),
                            isSuspicious = true, // Triggers the UI and logic
                            sourceIp = "10.0.0.1",
                            sourcePort = 12345
                        )

                        // Emit to the live stream
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
            modifier = Modifier.fillMaxSize()
        ) {
            items(blockedLogs) { event ->
                BlockedTrafficCard(event)
            }
        }
    }
}

@Composable
fun BlockedTrafficCard(event: NetworkEvent) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)),
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
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
                Text(
                    text = event.domain ?: event.destIp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 12.sp,
                    maxLines = 1
                )
            }

            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .background(MaterialTheme.colorScheme.error.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp)
            ) {
                Icon(Icons.Default.Block, contentDescription = "Blocked", tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(14.dp))
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