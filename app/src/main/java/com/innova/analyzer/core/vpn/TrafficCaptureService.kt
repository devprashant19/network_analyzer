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
import android.system.Os
import android.system.OsConstants
import android.util.Log
import androidx.core.app.NotificationCompat
import com.innova.analyzer.MainActivity
import com.innova.analyzer.core.network.PacketParser
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.core.network.nio.ByteBufferPool
import com.innova.analyzer.core.network.nio.Packet
import com.innova.analyzer.core.network.nio.TCPInput
import com.innova.analyzer.core.network.nio.TCPOutput
import com.innova.analyzer.core.network.nio.Tcb
import com.innova.analyzer.core.network.nio.UDPInput
import com.innova.analyzer.core.network.nio.UDPOutput
import com.innova.analyzer.core.threats.ThreatEngine
import com.innova.analyzer.data.attribution.AppAttributionHelper
import com.innova.analyzer.data.local.TrafficDatabase
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executors

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

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
            Log.d("InnovaVPN", "Kill switch received. Shutting down.")
            stopVpn()
            stopForeground(true)
            stopSelf()
            return START_NOT_STICKY
        }
        setupVpn()
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Threat Interception Active", NotificationManager.IMPORTANCE_LOW
            ).apply { description = "Actively monitoring background network traffic." }
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🛡️ Innova Firewall Active")
            .setContentText("Monitoring traffic for privacy threats...")
            .setSmallIcon(android.R.drawable.ic_secure)
            .setContentIntent(pendingIntent)
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
            // setBlocking(true) requires API 29+ — skip it; FileInputStream.read() blocks natively
            // on the tun fd via the read() syscall. setBlocking would use the ioctl FIONBIO approach.
            builder.addDnsServer(VpnConfig.PRIMARY_DNS)
            builder.addDnsServer(VpnConfig.SECONDARY_DNS)
            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                // Set the tun fd to BLOCKING mode using fcntl (works API 21+).
                // VpnService.Builder always sets the fd non-blocking by default.
                // Without this, FileInputStream.read() spins on EAGAIN and packets are delivered
                // unreliably. This is the API 21-compatible equivalent of setBlocking(true).
                try {
                    val tunFd = vpnInterface!!.fileDescriptor
                    val flags = Os.fcntlInt(tunFd, OsConstants.F_GETFL, 0)
                    Os.fcntlInt(tunFd, OsConstants.F_SETFL, flags and OsConstants.O_NONBLOCK.inv())
                    Log.d("InnovaVPN", "tun fd set to blocking mode (flags=${flags and OsConstants.O_NONBLOCK.inv()})")
                } catch (e: Exception) {
                    Log.w("InnovaVPN", "fcntl blocking failed (continuing): ${e.message}")
                }
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
        Log.d("InnovaVPN", "Starting NIO traffic interception.")

        val fd = vpnInterface?.fileDescriptor ?: return
        val dao = TrafficDatabase.getDatabase(this).trafficDao()
        val attributionHelper = AppAttributionHelper(this)
        val threatEngine = ThreatEngine(this).also { it.loadBlocklist() }

        // Three queues that connect the 5 workers
        val deviceToNetworkUDPQueue = ConcurrentLinkedQueue<Packet>()
        val deviceToNetworkTCPQueue = ConcurrentLinkedQueue<Packet>()
        val networkToDeviceQueue = ConcurrentLinkedQueue<ByteArray>()

        val udpSelector = Selector.open()
        val tcpSelector = Selector.open()

        // Thread pool for the 4 NIO worker threads
        val executor = Executors.newFixedThreadPool(4)
        executor.submit(UDPOutput(deviceToNetworkUDPQueue, udpSelector, this))
        executor.submit(UDPInput(networkToDeviceQueue, udpSelector))
        executor.submit(TCPOutput(deviceToNetworkTCPQueue, networkToDeviceQueue, tcpSelector, this))
        executor.submit(TCPInput(networkToDeviceQueue, tcpSelector))

        // Plain FileOutputStream — uses write() syscall directly on the tun character device.
        // DO NOT use .channel here: NIO FileChannel calls pwrite() which fails with ESPIPE
        // on a non-seekable character device like the tun fd.
        val vpnOutput = FileOutputStream(fd)
        serviceScope.launch {
            try {
                while (isActive) {
                    val outPkt = networkToDeviceQueue.poll()
                    if (outPkt != null) {
                        vpnOutput.write(outPkt)
                        Log.v("InnovaVPN", "tun write ${outPkt.size} bytes")
                    } else {
                        delay(1) // Yield CPU when nothing to write
                    }
                }
            } catch (e: Exception) {
                Log.d("InnovaVPN", "Write loop terminated: ${e.message}")
            } finally {
                vpnOutput.close()
            }
        }

        // Plain FileInputStream — uses read() syscall directly on the tun character device.
        // DO NOT use .channel: NIO FileChannel calls pread() which fails with ESPIPE.
        serviceScope.launch {
            val vpnInput = FileInputStream(fd)
            val rawBuf = ByteArray(VpnConfig.MTU_SIZE)
            try {
                while (isActive) {
                    val length = vpnInput.read(rawBuf)
                    if (length <= 0) { Thread.yield(); continue }
                    Log.v("InnovaVPN", "tun read $length bytes proto=${rawBuf[9].toInt() and 0xFF}")

                    // ----- Monitoring path (PacketParser → ThreatEngine → DB) -----
                    try {
                        val parsedEvent = PacketParser.parseIPv4Packet(rawBuf, length)
                        if (parsedEvent != null) {
                            val connectionKey = "${parsedEvent.protocol.ordinal}:${parsedEvent.sourceIp}:" +
                                    "${parsedEvent.sourcePort}:${parsedEvent.destIp}:${parsedEvent.destPort}"
                            val realUid = uidCache.getOrPut(connectionKey) {
                                attributionHelper.getConnectionUid(
                                    parsedEvent.protocol.ordinal,
                                    parsedEvent.sourceIp, parsedEvent.sourcePort,
                                    parsedEvent.destIp, parsedEvent.destPort
                                )
                            }
                            val finalizedEvent = parsedEvent.copy(
                                uid = realUid,
                                appName = attributionHelper.getAppName(realUid),
                                packageName = attributionHelper.getPackageName(realUid)
                            )
                            val evaluatedEvent = threatEngine.evaluatePacket(finalizedEvent)
                            TrafficStream.emitEvent(evaluatedEvent)
                            launch { 
                                dao.upsertEvent(
                                    key = evaluatedEvent.connectionKey,
                                    time = System.currentTimeMillis(),
                                    uid = evaluatedEvent.uid,
                                    pkg = evaluatedEvent.packageName,
                                    app = evaluatedEvent.appName,
                                    proto = evaluatedEvent.protocol.name,
                                    srcIp = evaluatedEvent.sourceIp,
                                    srcPort = evaluatedEvent.sourcePort,
                                    dstIp = evaluatedEvent.destIp,
                                    dstPort = evaluatedEvent.destPort,
                                    domain = evaluatedEvent.domain,
                                    bytes = evaluatedEvent.totalBytes,
                                    susp = evaluatedEvent.isSuspicious
                                ) 
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("InnovaVPN", "Monitoring error (packet forwarded anyway): ${e.message}")
                    }

                    // ----- Forwarding path (NIO queues) -----
                    val packetBuffer = ByteBufferPool.acquire()
                    packetBuffer.put(rawBuf, 0, length)
                    packetBuffer.flip()
                    try {
                        val packet = Packet(packetBuffer)
                        when {
                            packet.isUDP() -> deviceToNetworkUDPQueue.offer(packet)
                            packet.isTCP() -> deviceToNetworkTCPQueue.offer(packet)
                            else -> ByteBufferPool.release(packetBuffer)
                        }
                    } catch (e: Exception) {
                        Log.e("InnovaVPN", "Packet parse error: ${e.message}", e)
                        ByteBufferPool.release(packetBuffer)
                    }
                }
            } catch (e: Exception) {
                Log.d("InnovaVPN", "Read loop terminated: ${e.message}")
            } finally {
                executor.shutdownNow()
                udpSelector.close()
                tcpSelector.close()
                ByteBufferPool.clear()
                Tcb.closeAll()
                vpnInput.close()
            }
        }
    }


    private fun stopVpn() {
        try {
            Log.d("InnovaVPN", "Shutting down VPN and cleaning up resources...")
            serviceScope.cancel()
            uidCache.clear()
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}