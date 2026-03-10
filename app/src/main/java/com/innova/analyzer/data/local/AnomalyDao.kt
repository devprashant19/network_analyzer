package com.innova.analyzer.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.innova.analyzer.data.models.AppProfile
import com.innova.analyzer.data.models.KnownServer

@Dao
interface AnomalyDao {

    // --- Known Servers ---

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertServerIgnoreConflict(server: KnownServer): Long

    @Query("SELECT COUNT(*) > 0 FROM known_servers WHERE uid = :uid AND domain = :domain")
    suspend fun isServerKnown(uid: Int, domain: String): Boolean

    // --- App Profiles ---

    @Query("SELECT * FROM app_profiles WHERE uid = :uid")
    suspend fun getAppProfile(uid: Int): AppProfile?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAppProfile(profile: AppProfile)

    @Query("SELECT * FROM app_profiles ORDER BY avgBytesUploadedPerHour DESC")
    suspend fun getAllProfiles(): List<AppProfile>
}
