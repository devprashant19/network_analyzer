package com.innova.analyzer.data.attribution

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import java.net.InetSocketAddress

class AppAttributionHelper(context: Context) {

    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager = context.packageManager

    // Caches to prevent CPU spikes during heavy packet floods
    private val appNameCache = mutableMapOf<Int, String>()
    private val packageNameCache = mutableMapOf<Int, String>()

    /**
     * Asks Android OS which app owns the specific source and destination ports.
     */
    fun getConnectionUid(protocolNum: Int, sourceIp: String, sourcePort: Int, destIp: String, destPort: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                val local = InetSocketAddress(sourceIp, sourcePort)
                val remote = InetSocketAddress(destIp, destPort)
                // This is the magic Android 10+ API that reveals the app
                return connectivityManager.getConnectionOwnerUid(protocolNum, local, remote)
            } catch (e: Exception) {
                Log.e("Attribution", "Failed to resolve UID: ${e.message}")
            }
        }
        return -1
    }

    /**
     * Translates a raw UID (e.g., 10245) into a human-readable name (e.g., "Instagram").
     */
    fun getAppName(uid: Int): String {
        if (uid == -1) return "Background Process" // Fallback for unresolved packets
        if (appNameCache.containsKey(uid)) return appNameCache[uid]!!

        val packages = packageManager.getPackagesForUid(uid)
        if (!packages.isNullOrEmpty()) {
            val packageName = packages[0]
            try {
                val appInfo = packageManager.getApplicationInfo(packageName, 0)
                val appName = packageManager.getApplicationLabel(appInfo).toString()

                appNameCache[uid] = appName
                packageNameCache[uid] = packageName
                return appName
            } catch (e: PackageManager.NameNotFoundException) {
                Log.e("Attribution", "App not found for UID: $uid")
            }
        }
        return "System ($uid)"
    }

    fun getPackageName(uid: Int): String? {
        return packageNameCache[uid]
    }
}