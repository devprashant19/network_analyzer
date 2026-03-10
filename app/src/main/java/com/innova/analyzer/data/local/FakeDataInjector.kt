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
            val sourceIp = "192.168.1.${Random.nextInt(1, 255)}"
            val sourcePort = Random.nextInt(1024, 65535)
            val destIp = "172.217.${Random.nextInt(1, 255)}.${Random.nextInt(1, 255)}"
            val destPort = 443
            val domain = domains.random()
            val totalBytes = Random.nextInt(100, 5000).toLong()
            val protocol = protocols.random()
            val connKey = "${protocol.ordinal}:$sourceIp:$sourcePort:$destIp:$destPort"

            dao.upsertEvent(
                key = connKey,
                time = System.currentTimeMillis(),
                uid = 1000,
                pkg = "com.android.chrome",
                app = "Chrome",
                proto = protocol.name,
                srcIp = sourceIp,
                srcPort = sourcePort,
                dstIp = destIp,
                dstPort = destPort,
                domain = domain,
                bytes = totalBytes,
                susp = Random.nextBoolean()
            )
            delay(2000) // 2-second heartbeat
        }
    }
}