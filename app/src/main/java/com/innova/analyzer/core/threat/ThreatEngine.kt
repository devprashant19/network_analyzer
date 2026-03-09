package com.innova.analyzer.core.threats

import android.content.Context
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

class TrieNode {
    val children = HashMap<Char, TrieNode>()
    var isTerminal = false
}

class ThreatEngine(private val context: Context) {
    private val root = TrieNode()
    var isReady = false
        private set

    // 🚨 THE HACKATHON FAILSAFE: Hardcoded worst offenders
    // If the text file fails to load, these will guarantee your demo works!
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
    fun isSuspicious(domain: String?): Boolean {
        if (domain.isNullOrBlank() || !isReady) return false
        
        // FIX: Force lowercase because DNS domains are often mixed-case
        val cleanDomain = domain.trim().lowercase()
        var current = root

        for (char in cleanDomain.reversed()) {
            // If we hit the end of a blocked word, AND the next char is a dot, it's a subdomain!
            // Example: Blocked "facebook.com", checking "graph.facebook.com"
            if (current.isTerminal && char == '.') {
                return true 
            }
            
            if (!current.children.containsKey(char)) {
                return false // Path broke before finishing
            }
            current = current.children[char]!!
        }
        
        // Exact match (e.g., checking "google-analytics.com" against "google-analytics.com")
        return current.isTerminal
    }
}