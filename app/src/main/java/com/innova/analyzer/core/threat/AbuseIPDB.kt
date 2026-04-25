package com.innova.analyzer.core.threat

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

object AbuseIpdbClient {
    private const val API_KEY = "20378cc3a1a29c818ea7e27657475e76e0f006b882c5516233722ffdab52bf24d061fe6798da12f1"
    private const val BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    private val scoreCache = ConcurrentHashMap<String, Int>()

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()
    suspend fun checkIp(ipAddress: String): Int = withContext(Dispatchers.IO) {
        if (scoreCache.containsKey(ipAddress)) return@withContext scoreCache[ipAddress]!!
        if (isLocalIp(ipAddress)) return@withContext 0

        try {
            val request = Request.Builder()
                .url("$BASE_URL?ipAddress=$ipAddress&maxAgeInDays=90")
                .addHeader("Key", API_KEY)
                .addHeader("Accept", "application/json")
                .build()

            val response = client.newCall(request).execute()

            if (response.isSuccessful && response.body != null) {
                val jsonBody = response.body!!.string()
                val jsonObject = JSONObject(jsonBody)
                val score = jsonObject.getJSONObject("data").getInt("abuseConfidenceScore")

                // Update cache
                scoreCache[ipAddress] = score
                return@withContext score
            } else {
                Log.e("AbuseIPDB", "API Error Response: ${response.code}")
                return@withContext 0
            }
        } catch (e: Exception) {
            Log.e("AbuseIPDB", "Network Request Failed: ${e.message}")
            return@withContext 0
        }
    }

    private fun isLocalIp(ip: String): Boolean {
        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                ip.startsWith("172.16.") || // Range 172.16 - 172.31
                ip.startsWith("127.")
    }
}