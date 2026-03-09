package com.innova.analyzer.core.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class TrafficCaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

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
            }
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error setting up VPN: ${e.message}")
        }
    }

    private fun startIntercepting() {
        // TODO: Implement packet interception logic
        Log.d("InnovaVPN", "Traffic interception started.")
    }

    private fun stopVpn() {
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e("InnovaVPN", "Error stopping VPN: ${e.message}")
        }
    }
}
