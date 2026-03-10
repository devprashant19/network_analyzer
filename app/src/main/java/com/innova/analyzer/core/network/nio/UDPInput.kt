package com.innova.analyzer.core.network.nio

import android.util.Log
import java.io.IOException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.concurrent.ConcurrentLinkedQueue

class UDPInput(
    private val outputQueue: ConcurrentLinkedQueue<ByteArray>,
    private val selector: Selector
) : Runnable {

    companion object {
        private const val TAG = "InnovaUDPI"
        val pendingRegistrations = ConcurrentLinkedQueue<PendingRegistration>()
    }

    class PendingRegistration(val channel: DatagramChannel, val packet: Packet)

    override fun run() {
        Log.i(TAG, "UDPInput started")
        val thread = Thread.currentThread()
        while (!thread.isInterrupted) {
            while (true) {
                val pending = pendingRegistrations.poll() ?: break
                try {
                    pending.channel.register(selector, SelectionKey.OP_READ, pending.packet)
                    Log.d(TAG, "Registered new UDP channel for ${pending.channel.remoteAddress}")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to register UDP channel: ${e.message}")
                }
            }
            
            val readyCount = try {
                selector.select()
            } catch (e: Exception) {
                Log.e(TAG, "Selector error: ${e.message}"); break
            }
            if (readyCount == 0) continue
            Log.d(TAG, "Selector ready: $readyCount keys")

            val keys = selector.selectedKeys().iterator()
            while (keys.hasNext()) {
                val key = keys.next()
                keys.remove()
                if (!key.isValid || !key.isReadable) continue

                val channel = key.channel() as DatagramChannel
                val referencePacket = key.attachment() as Packet
                val receiveBuffer = ByteBufferPool.acquire()
                receiveBuffer.position(Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE)

                try {
                    val readBytes = channel.read(receiveBuffer)
                    Log.d(TAG, "UDP response: $readBytes bytes from ${channel.remoteAddress}")
                    if (readBytes <= 0) { ByteBufferPool.release(receiveBuffer); continue }

                    referencePacket.updateUDPBuffer(receiveBuffer, readBytes)
                    receiveBuffer.position(0)
                    receiveBuffer.limit(Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE + readBytes)

                    val outBytes = ByteArray(receiveBuffer.limit())
                    receiveBuffer.get(outBytes)
                    outputQueue.offer(outBytes)
                    Log.d(TAG, "Enqueued UDP response ${outBytes.size}B for device")
                } catch (e: IOException) {
                    Log.e(TAG, "UDP read error: ${e.message}")
                } finally {
                    ByteBufferPool.release(receiveBuffer)
                }
            }
        }
        Log.i(TAG, "UDPInput stopped")
    }
}
