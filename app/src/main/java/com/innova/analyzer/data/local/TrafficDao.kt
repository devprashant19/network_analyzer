package com.innova.analyzer.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface TrafficDao {
    // 🥷 Backend Ninja uses this to save packets via UPSERT aggregation
    @Query("""
        INSERT INTO network_events (connectionKey, timestamp, lastActive, uid, packageName, appName, protocol, sourceIp, sourcePort, destIp, destPort, domain, totalBytes, packetCount, isSuspicious)
        VALUES (:key, :time, :time, :uid, :pkg, :app, :proto, :srcIp, :srcPort, :dstIp, :dstPort, :domain, :bytes, 1, :susp)
        ON CONFLICT(connectionKey) DO UPDATE SET
            totalBytes = totalBytes + :bytes,
            packetCount = packetCount + 1,
            lastActive = :time
    """)
    suspend fun upsertEvent(
        key: String, time: Long, uid: Int, pkg: String?, app: String?, proto: String,
        srcIp: String, srcPort: Int, dstIp: String, dstPort: Int, domain: String?,
        bytes: Long, susp: Boolean
    )

    // 🟢 The Boot Loader: Grabs history instantly when the app opens!
    @Query("SELECT * FROM network_events ORDER BY lastActive DESC LIMIT 1000")
    suspend fun getRecentLogs(): List<NetworkEvent>

    // 🟢 The True Counter: Gets the actual all-time total across app restarts!
    @Query("SELECT COUNT(*) FROM network_events")
    suspend fun getTotalCount(): Int

    // 🧹 Wipes the database to free up phone storage
    @Query("DELETE FROM network_events")
    suspend fun clearAll()

    // 🎨 Frontend Wrangler uses this to auto-update the UI (Legacy Flow)
    @Query("SELECT * FROM network_events ORDER BY lastActive DESC")
    fun getLiveTraffic(): Flow<List<NetworkEvent>>
}