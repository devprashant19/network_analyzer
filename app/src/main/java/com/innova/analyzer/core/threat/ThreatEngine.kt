package com.innova.analyzer.core.threats

import android.content.Context
import android.util.Log
import com.innova.analyzer.core.notifications.NotificationHelper
import com.innova.analyzer.data.models.NetworkEvent
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.ConcurrentHashMap

class TrieNode {
    val children = HashMap<Char, TrieNode>()
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

    // 🚨 THE HACKATHON FAILSAFE: Hardcoded worst offenders
    private val failsafeTrackers = listOf(
        "google-analytics.com", "graph.facebook.com", "app-measurement.com",
        "applovin.com", "unity3d.com", "vungle.com", "ad.doubleclick.net",
        "scorecardresearch.com", "flurry.com", "crashlytics.com", "branch.io",
        "doubleclick.net", "facebook.com", "mixpanel.com"
    )

    fun loadBlocklist() {
        try {
            // 1. Load the failsafe list first
            failsafeTrackers.forEach { insert(it.trim().lowercase().reversed()) }
            var count = failsafeTrackers.size

            // 2. Try to load the massive file from assets
            try {
                val inputStream = context.assets.open("trackers.txt")
                val reader = BufferedReader(InputStreamReader(inputStream))

                reader.forEachLine { domain ->
                    if (domain.isNotBlank() && !domain.startsWith("#")) {
                        insert(domain.trim().lowercase().reversed())
                        count++
                    }
                }
            } catch (fileError: Exception) {
                Log.e("ThreatEngine", "Could not find trackers.txt! Falling back to failsafe list.")
            }

            isReady = true
            Log.d("ThreatEngine", "Successfully loaded $count malicious domains into the Engine!")
        } catch (e: Exception) {
            Log.e("ThreatEngine", "Critical error loading threats: ${e.message}")
            isReady = true // Set ready anyway so the failsafe works
        }
    }

    private fun insert(reversedDomain: String) {
        var current = root
        for (char in reversedDomain) {
            if (!current.children.containsKey(char)) {
                current.children[char] = TrieNode()
            }
            current = current.children[char]!!
        }
        current.isTerminal = true
    }

    /**
     * Checks if the intercepted domain is in our blocklist.
     */
    private fun isSuspicious(domain: String?): Boolean {
        if (domain.isNullOrBlank() || !isReady) return false

        // FIX: Force lowercase because DNS domains are often mixed-case
        val cleanDomain = domain.trim().lowercase()
        var current = root

        for (char in cleanDomain.reversed()) {
            // If we hit the end of a blocked word, AND the next char is a dot, it's a subdomain!
            if (current.isTerminal && char == '.') {
                return true
            }

            if (!current.children.containsKey(char)) {
                return false // Path broke before finishing
            }
            current = current.children[char]!!
        }

        // Exact match
        return current.isTerminal
    }

    // 🟢 NEW: The Main Processing Function that ties it all together!
    fun evaluatePacket(event: NetworkEvent): NetworkEvent {
        val domainToCheck = event.domain

        // 1. Check if the domain triggers our Trie
        if (isSuspicious(domainToCheck)) {

            // 2. Flag it as a threat (Turns the UI row Red!)
            val flaggedEvent = event.copy(isSuspicious = true)

            // 3. Check the Spam Filter before notifying
            if (domainToCheck != null) {
                val currentTime = System.currentTimeMillis()
                val lastAlertTime = notificationCooldown[domainToCheck] ?: 0L

                if (currentTime - lastAlertTime > COOLDOWN_TIME_MS) {
                    // Update cooldown map and fire notification
                    notificationCooldown[domainToCheck] = currentTime

                    notificationHelper.showThreatAlert(
                        appName = event.appName ?: "Background Process",
                        domain = domainToCheck
                    )
                }
            }

            return flaggedEvent
        }

        // If it's safe, return it unmodified
        return event
    }
}