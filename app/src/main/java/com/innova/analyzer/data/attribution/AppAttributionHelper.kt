package com.innova.analyzer.data.attribution

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log
import java.net.InetAddress
import java.net.InetSocketAddress

class AppAttributionHelper(context: Context) {

    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val packageManager = context.packageManager

    private val appNameCache = mutableMapOf<Int, String>()
    private val packageNameCache = mutableMapOf<Int, String>()

    fun getConnectionUid(protocolNum: Int, sourceIp: String, sourcePort: Int, destIp: String, destPort: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                // 🟢 FIX: Ensure we use the correct protocol mapping (TCP=6, UDP=17)
                // Android OS uses the IP protocol numbers directly.
                val local = InetSocketAddress(InetAddress.getByName(sourceIp), sourcePort)
                val remote = InetSocketAddress(InetAddress.getByName(destIp), destPort)
                
                val protocol = when (protocolNum) {
                    0 -> 6  // TCP
                    1 -> 17 // UDP
                    else -> protocolNum
                }
                
                return connectivityManager.getConnectionOwnerUid(protocol, local, remote)
            } catch (e: Exception) {
                // Suppress logs for common failed resolutions to avoid overhead
            }
        }
        return -1
    }

    fun getAppName(uid: Int): String {
        if (uid <= 0) return "System Process"
        if (appNameCache.containsKey(uid)) return appNameCache[uid]!!

        val packages = try {
            packageManager.getPackagesForUid(uid)
        } catch (e: Exception) {
            null
        }
        
        if (!packages.isNullOrEmpty()) {
            val packageName = packages[0]
            try {
                val appInfo = packageManager.getApplicationInfo(packageName, 0)
                val appName = packageManager.getApplicationLabel(appInfo).toString()

                appNameCache[uid] = appName
                packageNameCache[uid] = packageName
                return appName
            } catch (e: PackageManager.NameNotFoundException) {
                // Fallback
            }
        }
        return "Process $uid"
    }

    fun getPackageName(uid: Int): String? {
        if (uid <= 0) return null
        if (packageNameCache.containsKey(uid)) return packageNameCache[uid]

        val packages = try {
            packageManager.getPackagesForUid(uid)
        } catch (e: Exception) {
            null
        }
        
        if (!packages.isNullOrEmpty()) {
            packageNameCache[uid] = packages[0]
            return packages[0]
        }
        return null
    }
}