package com.innova.analyzer.core.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.innova.analyzer.core.network.PacketParser
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.attribution.AppAttributionHelper
import com.innova.analyzer.data.local.TrafficDatabase
import kotlinx.coroutines.*
import java.io.FileInputStream

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnInputStream: FileInputStream? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

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
            stopSelf()
            return START_NOT_STICKY
        }

        setupVpn()
        return START_STICKY // 🟢 Re-run if killed by OS
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Monitoring",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows that Innova is monitoring your network traffic"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Innova Network Monitor")
            .setContentText("Monitoring traffic for privacy threats...")
            .setSmallIcon(android.R.drawable.ic_menu_compass) // Replace with your app icon
            .setOngoing(true)
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
                        val parsedEvent = PacketParser.parseIPv4Packet(packet, length)

                        if (parsedEvent != null) {
                            val realUid = attributionHelper.getConnectionUid(
                                protocolNum = parsedEvent.protocol.ordinal,
                                sourceIp = parsedEvent.sourceIp,
                                sourcePort = parsedEvent.sourcePort,
                                destIp = parsedEvent.destIp,
                                destPort = parsedEvent.destPort
                            )

                            val realAppName = attributionHelper.getAppName(realUid)
                            val realPackageName = attributionHelper.getPackageName(realUid)

                            val finalizedEvent = parsedEvent.copy(
                                uid = realUid,
                                appName = realAppName,
                                packageName = realPackageName
                            )

                            TrafficStream.emitEvent(finalizedEvent)
                            dao.insertEvent(finalizedEvent)
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

            vpnInputStream?.close()
            vpnInputStream = null

            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}