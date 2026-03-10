package com.innova.analyzer.core.network.nio

import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap

/**
 * TCP Control Block — tracks the state of each intercepted TCP connection.
 *
 * Each connection is identified by "dstIp:dstPort:srcPort".
 * The TCB stores:
 *   - The real SocketChannel opened to the internet (protect()-ed)
 *   - TCP sequence/acknowledgement numbers so we can synthesize valid headers
 *   - Connection state machine status
 *   - The original parsed Packet so we can build response headers
 */
data class Tcb(
    val key: String,
    var mySequenceNum: Long,         // Our (proxy) sequence number
    var theirSequenceNum: Long,      // Client's sequence number
    var myAcknowledgementNum: Long,  // Our ack number
    val channel: SocketChannel,
    val referencePacket: Packet,
    var status: TcbStatus = TcbStatus.SYN_SENT,
    var waitingForNetworkData: Boolean = false
) {
    enum class TcbStatus { SYN_SENT, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT, LAST_ACK, TIME_WAIT }

    companion object {
        private val map = ConcurrentHashMap<String, Tcb>()

        fun get(key: String): Tcb? = map[key]
        fun put(key: String, tcb: Tcb) { map[key] = tcb }
        fun remove(key: String) { map.remove(key) }

        fun closeAll() {
            map.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
            map.clear()
        }
    }
}
