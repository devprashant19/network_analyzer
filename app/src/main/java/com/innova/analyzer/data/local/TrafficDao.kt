package com.innova.analyzer.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.flow.Flow

@Dao
interface TrafficDao {
    // 🥷 Backend Ninja uses this to save packets
    @Insert
    suspend fun insertEvent(event: NetworkEvent)

    // 🎨 Frontend Wrangler uses this to auto-update the UI
    @Query("SELECT * FROM network_events ORDER BY timestamp DESC")
    fun getLiveTraffic(): Flow<List<NetworkEvent>>

    @Query("DELETE FROM network_events")
    suspend fun clearAll()
}