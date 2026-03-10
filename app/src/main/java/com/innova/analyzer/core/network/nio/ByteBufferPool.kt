package com.innova.analyzer.core.network.nio

import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Simple ByteBuffer pool to avoid GC pressure during heavy packet processing.
 * Each buffer is 16 KB — enough for any standard MTU packet.
 */
object ByteBufferPool {
    const val BUFFER_SIZE = 16_384
    private val pool = ConcurrentLinkedQueue<ByteBuffer>()

    fun acquire(): ByteBuffer = pool.poll() ?: ByteBuffer.allocate(BUFFER_SIZE)

    fun release(buffer: ByteBuffer) {
        buffer.clear()
        pool.offer(buffer)
    }

    fun clear() = pool.clear()
}
