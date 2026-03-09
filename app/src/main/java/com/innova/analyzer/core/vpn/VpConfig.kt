package com.innova.analyzer.core.vpn

/**
 * Centralized configuration for the VPN Tunnel.
 * Isolating this makes tweaking network parameters during the hackathon much easier.
 */
object VpnConfig {
    // The name that appears in the Android System settings
    const val SESSION_NAME = "InnovaAnalyzer"

    // The dummy local IPv4 address assigned to our VPN interface
    const val LOCAL_IP = "10.0.0.2"
    const val LOCAL_PREFIX_LENGTH = 32

    // Route 0.0.0.0/0 forces ALL IPv4 traffic on the phone to flow through our app
    const val ROUTE_ADDRESS = "0.0.0.0"
    const val ROUTE_PREFIX_LENGTH = 0

    // MTU (Maximum Transmission Unit)
    // 1500 is the standard ethernet size. This ensures packets aren't fragmented unnecessarily.
    const val MTU_SIZE = 1500

    // Optional: Intercept DNS Requests (Port 53)
    // By routing to Google's public DNS through our tunnel, we can parse DNS packets later
    const val PRIMARY_DNS = "8.8.8.8"
    const val SECONDARY_DNS = "8.8.4.4"
}