package com.innova.analyzer.data.models

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Enum for clean UI state management and database storage.
 * Makes it easy to color-code protocols in the Jetpack Compose Dashboard.
 */
enum class ConnectionProtocol {
    TCP, UDP, DNS, HTTP, HTTPS, UNKNOWN
}

/**
 * THE CONTRACT: This represents a single network connection or packet intercept.
 * It doubles as our Room Database table to save hackathon development time.
 */
@Entity(tableName = "network_events")
data class NetworkEvent(
    // 1. Connection Identity (Stable hash of protocol/ips/ports)
    @PrimaryKey val connectionKey: String,
    
    // 2. Time & Identity
    val timestamp: Long = System.currentTimeMillis(),
    val lastActive: Long = System.currentTimeMillis(),
    val uid: Int,
    val packageName: String?,
    val appName: String?,

    // 2. Network Layer
    val protocol: ConnectionProtocol, // Room needs a TypeConverter for this!
    val sourceIp: String,
    val sourcePort: Int,
    val destIp: String,
    val destPort: Int,

    // 3. Application Layer (The Magic)
    val domain: String?,
    // The total traffic for this entire connection flow
    val totalBytes: Long,
    val packetCount: Int = 1,

    // 4. Threat Analytics
    val isSuspicious: Boolean = false
)