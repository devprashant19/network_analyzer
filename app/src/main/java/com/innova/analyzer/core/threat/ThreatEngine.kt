package com.innova.analyzer.core.threats

import android.content.Context
import android.util.Log
import com.innova.analyzer.core.notifications.NotificationHelper
import com.innova.analyzer.data.models.NetworkEvent
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import com.innova.analyzer.data.local.AnomalyDao
import com.innova.analyzer.data.models.KnownServer

class TrieNode {
    val children = HashMap<String, TrieNode>()
    var isTerminal = false
}

class ThreatEngine(private val context: Context) {
    private val root = TrieNode()
    var isReady = false
        private set

    // 🟢 The Spam Filter & Notification Engine
    private val notificationHelper = NotificationHelper(context)
    private val notificationCooldown = ConcurrentHashMap<String, Long>()
    private val COOLDOWN_TIME_MS = 5 * 60 * 1000L // 5 minutes

    // 🟢 In-Memory Cache for rapid "Known Server" lookups without disk I/O
    private val knownServersCache = ConcurrentHashMap<String, Boolean>()

    // 🚨 THE HACKATHON FAILSAFE: Hardcoded worst offenders
    private val failsafeTrackers = listOf(
        "google-analytics.com", "graph.facebook.com", "app-measurement.com",
        "applovin.com", "unity3d.com", "vungle.com", "ad.doubleclick.net",
        "scorecardresearch.com", "flurry.com", "crashlytics.com", "branch.io",
        "doubleclick.net", "facebook.com", "mixpanel.com", "tiktok.com"
    )

    fun loadBlocklist() {
        try {
            // 1. Load the failsafe list first
            failsafeTrackers.forEach { insertDomain(it) }
            var count = failsafeTrackers.size

            // 2. Try to load the massive file from assets
            try {
                val inputStream = context.assets.open("trackers.txt")
                val reader = BufferedReader(InputStreamReader(inputStream))

                reader.forEachLine { line ->
                    val domain = line.trim().lowercase()
                    if (domain.isNotBlank() && !domain.startsWith("#")) {
                        insertDomain(domain)
                        count++
                    }
                }
            } catch (fileError: Exception) {
                Log.e("ThreatEngine", "Could not find trackers.txt! Falling back to failsafe list.")
            }

            isReady = true
            Log.d("ThreatEngine", "Successfully loaded $count malicious domains into the Suffix Trie!")
        } catch (e: Exception) {
            Log.e("ThreatEngine", "Critical error loading threats: ${e.message}")
            isReady = true // Set ready anyway so the failsafe works
        }
    }

    // 🟢 UPGRADED: Splits "api.tiktok.com" into ["com", "tiktok", "api"]
    private fun insertDomain(domain: String) {
        val parts = domain.trim().lowercase().split(".").reversed()
        var current = root

        for (part in parts) {
            if (!current.children.containsKey(part)) {
                current.children[part] = TrieNode()
            }
            current = current.children[part]!!
        }
        current.isTerminal = true
    }

    /**
     * Checks if the intercepted domain is in our blocklist (Supports *.domain.com)
     */
    private fun isSuspicious(domain: String?): Boolean {
        if (domain.isNullOrBlank() || !isReady) return false

        val cleanDomain = domain.trim().lowercase()
        val parts = cleanDomain.split(".").reversed()
        var current = root

        for (part in parts) {
            // If the part doesn't exist, the path is broken = Safe domain
            current = current.children[part] ?: return false

            // 🚨 WILDCARD MATCH: If we hit a terminal node (e.g. we reached "tiktok" in "com"->"tiktok")
            // we block it instantly. We don't care if the next part is "hi" or "api".
            if (current.isTerminal) {
                return true
            }
        }

        return current.isTerminal
    }

    // 🟢 NEW: The Main Processing Function that ties it all together!
    fun evaluatePacket(
        event: NetworkEvent,
        anomalyDao: AnomalyDao? = null,
        scope: CoroutineScope? = null
    ): NetworkEvent {
        val domainToCheck = event.domain

        // 1. Check if the domain triggers our Trie (Malware Blocklist)
        if (isSuspicious(domainToCheck)) {

            // 2. Flag it as a threat (Turns the UI row Red!)
            val flaggedEvent = event.copy(isSuspicious = true)

            // 3. Check the Spam Filter before notifying
            if (domainToCheck != null) {
                val currentTime = System.currentTimeMillis()
                val lastAlertTime = notificationCooldown[domainToCheck] ?: 0L

                if (currentTime - lastAlertTime > COOLDOWN_TIME_MS) {
                    notificationCooldown[domainToCheck] = currentTime
                    notificationHelper.showThreatAlert(
                        appName = event.appName ?: "Background Process",
                        domain = domainToCheck
                    )
                }
            }
            return flaggedEvent
        }

        // 4. Check for "New Unknown Server" Anomaly
        if (domainToCheck != null && anomalyDao != null && scope != null) {
            val cacheKey = "${event.uid}:$domainToCheck"
            
            // If it's not in our RAM cache, let's investigate asynchronously
            if (!knownServersCache.containsKey(cacheKey)) {
                // Mark it in RAM immediately so we don't spam queries for the same flow
                knownServersCache[cacheKey] = true 

                scope.launch {
                    val isKnownInDb = anomalyDao.isServerKnown(event.uid, domainToCheck)
                    if (!isKnownInDb) {
                        // 🚨 IT'S A NEW UNKNOWN SERVER FOR THIS APP!
                        Log.i("AnomalyEngine", "App ${event.appName} contacted NEW server: $domainToCheck")
                        
                        // Save it so it's "Known" from now on
                        val newServer = KnownServer(uid = event.uid, domain = domainToCheck)
                        anomalyDao.insertServerIgnoreConflict(newServer)
                        
                        // We do NOT block the packet for a "New" server (could just be an update), 
                        // but we DO alert the user if it's notable!
                        // (Optional: You could trigger a specific 'Anomaly' notification here)
                    }
                }
            }
        }

        // If it's safe and known, return it unmodified
        return event
    }
}