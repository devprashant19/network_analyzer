package com.innova.analyzer.core.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import com.innova.analyzer.core.network.PacketParser
import com.innova.analyzer.core.network.TrafficStream
import com.innova.analyzer.data.local.TrafficDatabase
import kotlinx.coroutines.*
import java.io.FileInputStream

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    // Create a dedicated background thread for reading the non-stop flow of packets
    private val serviceScope = CoroutineScope(Dispatchers.IO + Job())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        setupVpn()
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
    }

    private fun setupVpn() {
        if (vpnInterface != null) return // Prevent duplicate tunnels

        try {
            val builder = Builder()

            // Apply configurations from our VpnConfig object
            builder.addAddress(VpnConfig.LOCAL_IP, VpnConfig.LOCAL_PREFIX_LENGTH)
            builder.addRoute(VpnConfig.ROUTE_ADDRESS, VpnConfig.ROUTE_PREFIX_LENGTH)
            builder.setSession(VpnConfig.SESSION_NAME)
            builder.setMtu(VpnConfig.MTU_SIZE)
            builder.setBlocking(true) // Crucial: Block the read thread until data arrives

            // Add DNS servers so we can capture domain lookups
            builder.addDnsServer(VpnConfig.PRIMARY_DNS)
            builder.addDnsServer(VpnConfig.SECONDARY_DNS)

            // 2. Establish the connection
            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                Log.d("InnovaVPN", "VPN Tunnel established successfully with MTU: ${VpnConfig.MTU_SIZE}")
                startIntercepting()
            } else {
                Log.e("InnovaVPN", "Failed to establish VPN. Permission not granted?")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error setting up VPN: ${e.message}")
            stopSelf()
        }
    }

    private fun startIntercepting() {
        Log.d("InnovaVPN", "Traffic interception started.")

        // Grab the raw file descriptor from the Android OS
        val fd = vpnInterface?.fileDescriptor ?: return

        // 1. Get our Room Database DAO so we can save the packets permanently
        val dao = TrafficDatabase.getDatabase(this).trafficDao()

        // Launch our background packet reader
        serviceScope.launch {
            val inputStream = FileInputStream(fd)
            // We use MTU_SIZE because a single packet will never be larger than the tunnel's MTU
            val packet = ByteArray(VpnConfig.MTU_SIZE)

            try {
                while (isActive) {
                    // This will pause (block) until a new packet arrives from the OS
                    val length = inputStream.read(packet)

                    if (length > 0) {
                        // 2. Send the raw bytes to the Parser
                        val parsedEvent = PacketParser.parseIPv4Packet(packet, length)

                        if (parsedEvent != null) {
                            // 3. Emit to the SharedFlow for instant UI updates!
                            TrafficStream.emitEvent(parsedEvent)

                            // 4. Save to Room Database for the history/report screen
                            dao.insertEvent(parsedEvent)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("InnovaVPN", "Interception loop interrupted: ${e.message}")
            }
        }
    }

    private fun stopVpn() {
        try {
            Log.d("InnovaVPN", "Shutting down VPN and cleaning up resources...")
            serviceScope.cancel() // Stop the infinite while-loop
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}