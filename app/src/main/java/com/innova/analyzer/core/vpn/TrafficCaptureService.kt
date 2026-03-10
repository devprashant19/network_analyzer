package com.innova.analyzer.core.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.innova.analyzer.MainActivity // Make sure this matches your package name
import com.innova.analyzer.core.network.PacketParser
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.attribution.AppAttributionHelper
import com.innova.analyzer.data.local.TrafficDatabase
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.util.concurrent.ConcurrentHashMap

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnInputStream: FileInputStream? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    // 🟢 THE ENTERPRISE CACHE: Prevents the CPU from melting during heavy traffic
    private val uidCache = ConcurrentHashMap<String, Int>()

    companion object {
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "vpn_monitoring_channel"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP_VPN") {
            Log.d("InnovaVPN", "Kill switch received. Committing system shutdown.")
            stopVpn()
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }

        setupVpn()
        return START_STICKY // Tells Android: "If you kill me for RAM, restart me immediately!"
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Threat Interception Active",
                NotificationManager.IMPORTANCE_LOW // Low = No annoying buzzing
            ).apply {
                description = "Actively monitoring background network traffic."
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        // 🟢 POLISH: Tapping the notification opens the app!
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡️ Innova Firewall Active")
            .setContentText("Monitoring traffic for privacy threats...")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentIntent(pendingIntent) // Links the notification to the app
            .setOngoing(true) // Cannot be swiped away
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun setupVpn() {
        if (vpnInterface != null) return

        try {
            val builder = Builder()
            builder.addAddress(VpnConfig.LOCAL_IP, VpnConfig.LOCAL_PREFIX_LENGTH)
            builder.addRoute(VpnConfig.ROUTE_ADDRESS, VpnConfig.ROUTE_PREFIX_LENGTH)
            builder.setSession(VpnConfig.SESSION_NAME)
            builder.setMtu(VpnConfig.MTU_SIZE)
            builder.setBlocking(true)

            builder.addDnsServer(VpnConfig.PRIMARY_DNS)
            builder.addDnsServer(VpnConfig.SECONDARY_DNS)

            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                Log.d("InnovaVPN", "VPN Tunnel established successfully.")
                startIntercepting()
            } else {
                Log.e("InnovaVPN", "Failed to establish VPN.")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error setting up VPN: ${e.message}")
            stopSelf()
        }
    }

    private fun startIntercepting() {
        Log.d("InnovaVPN", "Traffic interception started.")

        val fd = vpnInterface?.fileDescriptor ?: return
        val dao = TrafficDatabase.getDatabase(this).trafficDao()
        val attributionHelper = AppAttributionHelper(this)

        serviceScope.launch {
            vpnInputStream = FileInputStream(fd)
            val packet = ByteArray(VpnConfig.MTU_SIZE)

            try {
                while (isActive) {
                    val stream = vpnInputStream ?: break
                    val length = stream.read(packet)

                    if (length > 0) {
                        // 1. Lightning fast byte extraction
                        val parsedEvent = PacketParser.parseIPv4Packet(packet, length)

                        if (parsedEvent != null) {

                            // 🟢 2. THE CACHE LOOKUP ($O(1)$ Time Complexity)
                            val connectionKey = "${parsedEvent.protocol.ordinal}:${parsedEvent.sourceIp}:${parsedEvent.sourcePort}:${parsedEvent.destIp}:${parsedEvent.destPort}"

                            val realUid = uidCache.getOrPut(connectionKey) {
                                // Only ask the slow OS if we haven't seen this connection before!
                                attributionHelper.getConnectionUid(
                                    protocolNum = parsedEvent.protocol.ordinal,
                                    sourceIp = parsedEvent.sourceIp,
                                    sourcePort = parsedEvent.sourcePort,
                                    destIp = parsedEvent.destIp,
                                    destPort = parsedEvent.destPort
                                )
                            }

                            val realAppName = attributionHelper.getAppName(realUid)
                            val realPackageName = attributionHelper.getPackageName(realUid)

                            val finalizedEvent = parsedEvent.copy(
                                uid = realUid,
                                appName = realAppName,
                                packageName = realPackageName
                            )

                            // 3. Emit to the UI instantly (Flow handles its own async)
                            TrafficStream.emitEvent(finalizedEvent)

                            // 🟢 4. ASYNC DATABASE WRITE (Prevents VPN from lagging)
                            launch {
                                dao.insertEvent(finalizedEvent)
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.d("InnovaVPN", "Interception loop cleanly terminated.")
            }
        }
    }

    private fun stopVpn() {
        try {
            Log.d("InnovaVPN", "Shutting down VPN and cleaning up resources...")
            serviceScope.cancel()
            uidCache.clear() // Free up RAM when VPN turns off

            vpnInputStream?.close()
            vpnInputStream = null

            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}