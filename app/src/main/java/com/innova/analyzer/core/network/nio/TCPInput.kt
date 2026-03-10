package com.innova.analyzer.core.network.nio

import android.util.Log
import java.io.IOException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentLinkedQueue

class TCPInput(
    private val outputQueue: ConcurrentLinkedQueue<ByteArray>,
    private val selector: Selector
) : Runnable {

    companion object {
        private const val TAG = "InnovaTCPI"
        val pendingRegistrations = ConcurrentLinkedQueue<PendingRegistration>()
    }

    class PendingRegistration(val channel: SocketChannel, val ops: Int, val tcb: Tcb)

    override fun run() {
        Log.i(TAG, "TCPInput started")
        val thread = Thread.currentThread()
        while (!thread.isInterrupted) {
            while (true) {
                val pending = pendingRegistrations.poll() ?: break
                try {
                    pending.channel.register(selector, pending.ops, pending.tcb)
                    Log.d(TAG, "Registered TCP channel OP=${pending.ops} for ${pending.tcb.key}")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to register TCP channel: ${e.message}")
                }
            }

            val readyCount = try {
                selector.select()
            } catch (e: Exception) {
                Log.e(TAG, "Selector error: ${e.message}"); break
            }
            if (readyCount == 0) continue

            val keys = selector.selectedKeys().iterator()
            while (keys.hasNext()) {
                val key = keys.next()
                keys.remove()
                if (!key.isValid) continue
                if (key.isConnectable) processConnect(key)
                else if (key.isReadable) processInput(key)
            }
        }
        Log.i(TAG, "TCPInput stopped")
    }

    private fun processConnect(key: SelectionKey) {
        val tcb = key.attachment() as Tcb
        Log.d(TAG, "OP_CONNECT for ${tcb.key} status=${tcb.status}")
        val responseBuf = ByteBufferPool.acquire()
        try {
            if (tcb.channel.finishConnect()) {
                tcb.status = Tcb.TcbStatus.SYN_RECEIVED
                // BUG FIX: ack = myAcknowledgementNum (= theirSeq+1), NOT theirSequenceNum (= theirSeq)
                tcb.referencePacket.updateTCPBuffer(
                    responseBuf,
                    (Packet.TCPHeader.SYN.toInt() or Packet.TCPHeader.ACK.toInt()).toByte(),
                    tcb.mySequenceNum,
                    tcb.myAcknowledgementNum, // ← fixed: was tcb.theirSequenceNum
                    0
                )
                responseBuf.position(0)
                responseBuf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
                enqueue(responseBuf)
                tcb.mySequenceNum++
                Log.d(TAG, "Sent SYN-ACK for ${tcb.key} seq=${tcb.mySequenceNum-1} ack=${tcb.myAcknowledgementNum}")
                key.interestOps(SelectionKey.OP_READ)
            } else {
                ByteBufferPool.release(responseBuf)
                Log.d(TAG, "finishConnect() returned false for ${tcb.key}")
            }
        } catch (e: IOException) {
            Log.e(TAG, "finishConnect error ${tcb.key}: ${e.message}")
            ByteBufferPool.release(responseBuf)
            sendRst(tcb)
            Tcb.remove(tcb.key)
            try { tcb.channel.close() } catch (_: Exception) {}
        }
    }

    private fun processInput(key: SelectionKey) {
        val tcb = key.attachment() as Tcb
        val channel = key.channel() as SocketChannel
        val receiveBuf = ByteBufferPool.acquire()
        receiveBuf.position(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)

        val readBytes = try {
            channel.read(receiveBuf)
        } catch (e: IOException) {
            Log.e(TAG, "TCP read error ${tcb.key}: ${e.message}")
            ByteBufferPool.release(receiveBuf)
            sendRst(tcb); Tcb.remove(tcb.key)
            try { channel.close() } catch (_: Exception) {}
            return
        }

        when {
            readBytes == -1 -> {
                // Server closed → send FIN+ACK to device
                Log.d(TAG, "Server closed ${tcb.key}, sending FIN+ACK")
                ByteBufferPool.release(receiveBuf)
                val finBuf = ByteBufferPool.acquire()
                tcb.referencePacket.updateTCPBuffer(
                    finBuf,
                    (Packet.TCPHeader.FIN.toInt() or Packet.TCPHeader.ACK.toInt()).toByte(),
                    tcb.mySequenceNum,
                    tcb.myAcknowledgementNum, // ← fixed
                    0
                )
                finBuf.position(0)
                finBuf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
                enqueue(finBuf)
                tcb.mySequenceNum++
                tcb.status = Tcb.TcbStatus.CLOSE_WAIT
            }
            readBytes == 0 -> ByteBufferPool.release(receiveBuf)
            else -> {
                // Data from server → wrap in TCP packet and send to device
                Log.d(TAG, "Server data ${tcb.key}: $readBytes bytes, mySeq=${tcb.mySequenceNum} ack=${tcb.myAcknowledgementNum}")
                tcb.referencePacket.updateTCPBuffer(
                    receiveBuf,
                    (Packet.TCPHeader.PSH.toInt() or Packet.TCPHeader.ACK.toInt()).toByte(),
                    tcb.mySequenceNum,
                    tcb.myAcknowledgementNum, // ← fixed: was tcb.theirSequenceNum
                    readBytes
                )
                receiveBuf.position(0)
                receiveBuf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE + readBytes)
                tcb.mySequenceNum += readBytes
                enqueue(receiveBuf)
            }
        }
    }

    private fun sendRst(tcb: Tcb) {
        val buf = ByteBufferPool.acquire()
        tcb.referencePacket.updateTCPBuffer(buf, Packet.TCPHeader.RST, 0, 0, 0)
        buf.position(0)
        buf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
        enqueue(buf)
    }

    private fun enqueue(buf: java.nio.ByteBuffer) {
        val bytes = ByteArray(buf.limit())
        buf.position(0); buf.get(bytes)
        ByteBufferPool.release(buf)
        outputQueue.offer(bytes)
    }
}
