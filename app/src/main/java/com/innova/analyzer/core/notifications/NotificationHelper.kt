package com.innova.analyzer.core.notifications

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.innova.analyzer.MainActivity
import kotlin.random.Random

class NotificationHelper(private val context: Context) {

    companion object {
        private const val CHANNEL_ID = "privacy_alerts_channel"
    }

    init {
        createChannel()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Privacy Alerts",
                NotificationManager.IMPORTANCE_HIGH // 🟢 HIGH importance = Heads-up pop-up!
            ).apply {
                description = "Alerts when apps contact known trackers."
            }
            val manager = context.getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    fun showThreatAlert(appName: String, domain: String) {
        val intent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("🛡️ Blocked Threat: $appName")
            .setContentText("Blocked connection to known tracker: $domain")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Innova VPN actively blocked $appName from sending data to a known tracker: $domain."))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // Use a random ID so multiple different alerts don't overwrite each other
        manager.notify(Random.nextInt(), notification)
    }
}