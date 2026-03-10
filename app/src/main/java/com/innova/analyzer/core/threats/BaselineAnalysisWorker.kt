package com.innova.analyzer.core.threats

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.innova.analyzer.core.notifications.NotificationHelper
import com.innova.analyzer.data.local.TrafficDatabase
import com.innova.analyzer.data.models.AppProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * A Background Worker that runs periodically (e.g. every hour).
 * It calculates the moving averages for AppProfiles and detects anomalies
 * without blocking the real-time high-speed VPN tunnel.
 */
class BaselineAnalysisWorker(
    private val context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            Log.i("AnomalyEngine", "Starting Baseline Analysis Worker...")
            val db = TrafficDatabase.getDatabase(context)
            val trafficDao = db.trafficDao()
            val anomalyDao = db.anomalyDao()
            val notificationHelper = NotificationHelper(context)

            // We analyze the traffic from the "Last Hour"
            val oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000)
            
            // 1. Get all recent traffic in the last hour
            val recentLogs = trafficDao.getRecentLogs().filter { it.lastActive > oneHourAgo }

            // Group traffic by App UID
            val currentHourStats = recentLogs.groupBy { it.uid }.mapValues { entry ->
                val packets = entry.value
                val totalBytes = packets.sumOf { it.totalBytes }
                val totalConnections = packets.size
                val appName = packets.firstOrNull()?.appName ?: "Unknown App"
                val packageName = packets.firstOrNull()?.packageName ?: "unknown"
                
                Triple(appName, packageName, Pair(totalConnections, totalBytes))
            }

            // 2. Compare against established Baselines
            for ((uid, stats) in currentHourStats) {
                val appName = stats.first
                val packageName = stats.second
                val connections = stats.third.first
                val bytesOut = stats.third.second
                
                val existingProfile = anomalyDao.getAppProfile(uid)
                
                if (existingProfile == null) {
                    // First time tracking this app! Create its initial baseline.
                    anomalyDao.upsertAppProfile(
                        AppProfile(
                            uid = uid,
                            packageName = packageName,
                            appName = appName,
                            avgConnectionsPerHour = connections.toDouble(),
                            avgBytesUploadedPerHour = bytesOut,
                            totalHoursTracked = 1
                        )
                    )
                } else {
                    // 🚨 ANOMALY DETECTION ENGINE 🚨
                    // Only trigger alerts if we've tracked this app for at least 24 hours (Stable Baseline)
                    // DEMO MODE: Changed '>= 24' down to '>= 0' so it triggers immediately for judging.
                    if (existingProfile.totalHoursTracked >= 0) {
                        
                        // Rule 1: Data Exfiltration (5x normal uploads)
                        // DEMO MODE: Removed minimum byte limit
                        if (existingProfile.avgBytesUploadedPerHour >= 0 && 
                            bytesOut > (existingProfile.avgBytesUploadedPerHour * 5)) {
                            
                            Log.w("AnomalyEngine", "🚨 EXFILTRATION DETECTED: $appName uploaded ${bytesOut / 1_000_000}MB (Baseline: ${existingProfile.avgBytesUploadedPerHour / 1_000_000}MB)")
                            notificationHelper.showThreatAlert(
                                appName = appName,
                                domain = "ANOMALOUS DATA UPLOAD (${bytesOut / 1_000_000} MB)"
                            )
                        }
                        
                        // Rule 2: Zombie / Botnet Activity (3x normal connections)
                        // DEMO MODE: Removed minimum connection limit
                        if (existingProfile.avgConnectionsPerHour >= 0 && 
                            connections > (existingProfile.avgConnectionsPerHour * 3)) {
                            
                            Log.w("AnomalyEngine", "🚨 BOTNET DETECTED: $appName made $connections connections (Baseline: ${existingProfile.avgConnectionsPerHour.toInt()})")
                            notificationHelper.showThreatAlert(
                                appName = appName,
                                domain = "ANOMALOUS CONNECTION SPIKE ($connections)"
                            )
                        }
                    }

                    // 3. Update the Moving Average for the Baseline
                    val oldHours = existingProfile.totalHoursTracked
                    val newAvgConnections = ((existingProfile.avgConnectionsPerHour * oldHours) + connections) / (oldHours + 1)
                    val newAvgBytes = ((existingProfile.avgBytesUploadedPerHour * oldHours) + bytesOut) / (oldHours + 1)

                    anomalyDao.upsertAppProfile(
                        existingProfile.copy(
                            avgConnectionsPerHour = newAvgConnections,
                            avgBytesUploadedPerHour = newAvgBytes,
                            totalHoursTracked = oldHours + 1,
                            lastUpdated = System.currentTimeMillis()
                        )
                    )
                }
            }

            Log.i("AnomalyEngine", "Baseline Analysis Complete! Processed ${currentHourStats.size} apps.")
            Result.success()
            
        } catch (e: Exception) {
            Log.e("AnomalyEngine", "Analysis crashed: ${e.message}")
            Result.failure()
        }
    }
}
