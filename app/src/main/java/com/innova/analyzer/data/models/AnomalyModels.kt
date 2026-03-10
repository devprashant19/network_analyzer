package com.innova.analyzer.data.models

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Tracks the "normal" behavior of an application over time.
 * Calculates standard moving averages for connections and uploads to detect anomalies.
 */
@Entity(tableName = "app_profiles")
data class AppProfile(
    @PrimaryKey val uid: Int,
    val packageName: String,
    val appName: String,
    
    // Baseline Metrics
    val avgConnectionsPerHour: Double = 0.0,
    val avgBytesUploadedPerHour: Long = 0L,
    
    // Tracking History
    val totalHoursTracked: Int = 0,
    val lastUpdated: Long = System.currentTimeMillis()
)

/**
 * Maps an application to a server it has historically contacted.
 * Used for "Unknown Server" detection.
 */
@Entity(tableName = "known_servers", primaryKeys = ["uid", "domain"])
data class KnownServer(
    val uid: Int,
    val domain: String,
    val firstSeen: Long = System.currentTimeMillis()
)
