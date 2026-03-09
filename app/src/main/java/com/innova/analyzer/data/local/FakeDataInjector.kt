package com.innova.analyzer.data.local

import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent
import kotlinx.coroutines.delay
import kotlin.random.Random

object FakeDataInjector {
    suspend fun startInjecting(dao: TrafficDao) {
        val protocols = ConnectionProtocol.values()
        val domains = listOf("google.com", "facebook.com", "api.tracker.com", "ads.xyz")

        while (true) {
            val fakeEvent = NetworkEvent(
                uid = 1000,
                packageName = "com.android.chrome",
                appName = "Chrome",
                protocol = protocols.random(),
                sourceIp = "192.168.1.${Random.nextInt(1, 255)}",
                sourcePort = Random.nextInt(1024, 65535),
                destIp = "172.217.${Random.nextInt(1, 255)}.${Random.nextInt(1, 255)}",
                destPort = 443,
                domain = domains.random(),
                payloadSize = Random.nextInt(100, 5000),
                isSuspicious = Random.nextBoolean()
            )
            dao.insertEvent(fakeEvent)
            delay(2000) // 2-second heartbeat
        }
    }
}