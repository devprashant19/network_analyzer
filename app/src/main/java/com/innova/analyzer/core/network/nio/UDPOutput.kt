package com.innova.analyzer.core.network.nio

import android.net.VpnService
import android.util.Log
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.WritableByteChannel
import java.util.concurrent.ConcurrentLinkedQueue

class UDPOutput(
    private val inputQueue: ConcurrentLinkedQueue<Packet>,
    private val selector: Selector,
    private val vpnService: VpnService
) : Runnable {

    companion object {
        private const val TAG = "InnovaUDPO"
        private const val MAX_CACHE_SIZE = 50
    }

    private val channelCache = object : LinkedHashMap<String, DatagramChannel>(MAX_CACHE_SIZE, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, DatagramChannel>): Boolean {
            val evict = size > MAX_CACHE_SIZE
            if (evict) try { eldest.value.close() } catch (_: Exception) {}
            return evict
        }
    }

    override fun run() {
        Log.i(TAG, "UDPOutput started")
        val thread = Thread.currentThread()
        while (!thread.isInterrupted) {
            val packet = inputQueue.poll()
            if (packet == null) { Thread.sleep(10); continue }

            val udp = packet.udpHeader
            if (udp == null) {
                Log.w(TAG, "No UDP header, dropping")
                ByteBufferPool.release(packet.backingBuffer)
                continue
            }
            val dst = packet.ip4Header.destinationAddress
            val key = "${dst.hostAddress}:${udp.destinationPort}:${udp.sourcePort}"
            Log.d(TAG, "UDP packet → $key payload=${packet.backingBuffer.remaining()}B")

            var channel = channelCache[key]
            if (channel == null || !channel.isOpen) {
                try {
                    channel = DatagramChannel.open()
                    val ok = vpnService.protect(channel.socket())
                    Log.d(TAG, "protect($key) = $ok")
                    if (!ok) { channel.close(); ByteBufferPool.release(packet.backingBuffer); continue }
                    channel.connect(InetSocketAddress(dst, udp.destinationPort))
                    channel.configureBlocking(false)
                    packet.swapSourceAndDestination()
                    channelCache[key] = channel
                    UDPInput.pendingRegistrations.offer(UDPInput.PendingRegistration(channel, packet))
                    selector.wakeup()
                    Log.d(TAG, "Opened UDP channel $key")
                } catch (e: IOException) {
                    Log.e(TAG, "UDP open failed $key: ${e.message}")
                    ByteBufferPool.release(packet.backingBuffer)
                    continue
                }
            }

            try {
                val payload: ByteBuffer = packet.backingBuffer
                val before = payload.remaining()
                val writable = channel as WritableByteChannel
                while (payload.hasRemaining()) writable.write(payload)
                Log.d(TAG, "UDP sent $before bytes to $key")
            } catch (e: IOException) {
                Log.e(TAG, "UDP write error $key: ${e.message}")
                channelCache.remove(key)
                try { channel?.close() } catch (_: Exception) {}
            }
            ByteBufferPool.release(packet.backingBuffer)
        }
        Log.i(TAG, "UDPOutput stopped")
    }
}
