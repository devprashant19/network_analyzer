package com.innova.analyzer.core.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.innova.analyzer.core.network.PacketParser
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.attribution.AppAttributionHelper
import com.innova.analyzer.data.local.TrafficDatabase
import kotlinx.coroutines.*
import java.io.FileInputStream

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnInputStream: FileInputStream? = null // 🟢 Track the stream directly

    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 🚨 THE POISON PILL 🚨
        if (intent?.action == "STOP_VPN") {
            Log.d("InnovaVPN", "Kill switch received. Committing system shutdown.")
            stopVpn()   // Close the sockets and streams
            stopSelf()  // Tell Android: "I am officially killing myself, do not restart me."
            return START_NOT_STICKY
        }

        // If it's not a stop command, start it up normally
        setupVpn()
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
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
            // Assign to our global variable so we can assassinate it later
            vpnInputStream = FileInputStream(fd)
            val packet = ByteArray(VpnConfig.MTU_SIZE)

            try {
                while (isActive) {
                    val stream = vpnInputStream ?: break
                    val length = stream.read(packet) // This blocking call will now be interrupted!

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
                // When we close the stream, it throws an exception here and safely exits the loop
                Log.d("InnovaVPN", "Interception loop cleanly terminated.")
            }
        }
    }

    private fun stopVpn() {
        try {
            Log.d("InnovaVPN", "Shutting down VPN and cleaning up resources...")
            serviceScope.cancel()

            // Violently close the InputStream to instantly wake up the blocking `read()` call
            vpnInputStream?.close()
            vpnInputStream = null

            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}