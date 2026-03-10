package com.innova.analyzer.core.network.nio

import android.net.VpnService
import android.util.Log
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.Random
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * TCPOutput — implements the TCP side of the VPN proxy.
 *
 * For each TCP packet from the device:
 *   SYN  → open a protect()-ed SocketChannel to the real server, handle 3-way handshake
 *   ACK  → forward application data to the real server
 *   FIN  → gracefully close the connection
 *   RST  → immediately close
 *
 * SYN-ACK responses back to the device are enqueued in networkToDeviceQueue.
 * Once ESTABLISHED, data responses are handled by TCPInput.
 *
 * Ported from hexene/LocalVPN (Apache 2.0).
 */
class TCPOutput(
    private val inputQueue: ConcurrentLinkedQueue<Packet>,
    private val outputQueue: ConcurrentLinkedQueue<ByteArray>,
    private val selector: Selector,
    private val vpnService: VpnService
) : Runnable {

    companion object {
        private const val TAG = "InnovaTCPO"
        private val random = Random()
    }

    override fun run() {
        Log.i(TAG, "TCPOutput started")
        val thread = Thread.currentThread()
        try {
            while (!thread.isInterrupted) {
                val packet = inputQueue.poll()
                if (packet == null) { Thread.sleep(10); continue }
                val tcp = packet.tcpHeader ?: continue
                val dst = packet.ip4Header.destinationAddress
                val key = "${dst.hostAddress}:${tcp.destinationPort}:${tcp.sourcePort}"

                val tcb = Tcb.get(key)
                if (tcb == null) {
                    // New connection — must start with SYN
                    if (tcp.isSYN()) initializeConnection(key, packet, tcp)
                    // else ignore stray packets with no TCB
                } else {
                    when {
                        tcp.isSYN() -> processDuplicateSyn(tcb, tcp)
                        tcp.isRST() -> closeCleanly(tcb)
                        tcp.isACK() -> processAck(tcb, tcp, packet)
                        else -> { /* ignore other flag combos */ }
                    }
                }
                ByteBufferPool.release(packet.backingBuffer)
            }
        } catch (e: InterruptedException) {
            Log.i(TAG, "TCPOutput stopping")
        } catch (e: Exception) {
            Log.e(TAG, "TCPOutput error: ${e.message}")
        } finally {
            Tcb.closeAll()
        }
    }

    private fun initializeConnection(key: String, packet: Packet, tcp: Packet.TCPHeader) {
        packet.swapSourceAndDestination()
        val mySeq = random.nextInt(Short.MAX_VALUE + 1).toLong()
        val theirSeq = tcp.sequenceNumber

        val channel = SocketChannel.open()
        channel.configureBlocking(false)
        val protected = vpnService.protect(channel.socket())
        Log.d(TAG, "protect($key) = $protected")
        if (!protected) {
            Log.e(TAG, "protect(Socket) failed for $key")
            channel.close()
            return
        }

        val tcb = Tcb(key, mySeq, theirSeq, theirSeq + 1, channel, packet)
        Tcb.put(key, tcb)

        val dst = packet.ip4Header.sourceAddress // swapped: dest is now the original src
        val dstPort = tcp.sourcePort               // swapped
        try {
            channel.connect(InetSocketAddress(dst, dstPort))
            if (channel.finishConnect()) {
                Log.d(TAG, "Connected immediately to $key")
                tcb.status = Tcb.TcbStatus.SYN_RECEIVED
                sendSynAck(tcb, mySeq, theirSeq + 1)
                tcb.mySequenceNum++
            } else {
                Log.d(TAG, "Async connect for $key, waiting OP_CONNECT")
                tcb.status = Tcb.TcbStatus.SYN_SENT
                TCPInput.pendingRegistrations.offer(TCPInput.PendingRegistration(channel, SelectionKey.OP_CONNECT, tcb))
                selector.wakeup()
            }
        } catch (e: IOException) {
            Log.e(TAG, "TCP connect error $key: ${e.message}")
            sendRst(tcb); Tcb.remove(key); channel.close()
        }
    }

    private fun processDuplicateSyn(tcb: Tcb, tcp: Packet.TCPHeader) {
        // Re-send SYN-ACK if we're still in the handshake phase
        if (tcb.status == Tcb.TcbStatus.SYN_SENT || tcb.status == Tcb.TcbStatus.SYN_RECEIVED) {
            sendSynAck(tcb, tcb.mySequenceNum, tcb.theirSequenceNum + 1)
        }
    }

    private fun processAck(tcb: Tcb, tcp: Packet.TCPHeader, packet: Packet) {
        when (tcb.status) {
            Tcb.TcbStatus.SYN_RECEIVED -> {
                // Device ACKed our SYN-ACK → connection ESTABLISHED
                tcb.status = Tcb.TcbStatus.ESTABLISHED
                TCPInput.pendingRegistrations.offer(TCPInput.PendingRegistration(tcb.channel, SelectionKey.OP_READ, tcb))
                selector.wakeup()
            }
            Tcb.TcbStatus.ESTABLISHED -> {
                // Forward any application payload to the real server
                val payload = packet.backingBuffer
                if (payload.hasRemaining()) {
                    try {
                        val payloadSize = payload.remaining()
                        while (payload.hasRemaining()) tcb.channel.write(payload)
                        tcb.myAcknowledgementNum += payloadSize
                    } catch (e: IOException) {
                        Log.e(TAG, "TCP write error ${tcb.key}: ${e.message}")
                        sendRst(tcb); closeCleanly(tcb)
                        return
                    }
                }
                if (tcp.isFIN()) processFin(tcb, tcp)
            }
            Tcb.TcbStatus.CLOSE_WAIT -> {
                // Device ACKed our FIN — half-closed
                sendFinAck(tcb)
                tcb.status = Tcb.TcbStatus.LAST_ACK
            }
            Tcb.TcbStatus.LAST_ACK -> {
                // Final ACK received — fully closed
                closeCleanly(tcb)
            }
            else -> { /* ignore */ }
        }
    }

    private fun processFin(tcb: Tcb, tcp: Packet.TCPHeader) {
        tcb.theirSequenceNum = tcp.sequenceNumber + 1
        sendFinAck(tcb)
        tcb.status = Tcb.TcbStatus.CLOSE_WAIT
    }

    private fun sendSynAck(tcb: Tcb, seq: Long, ack: Long) {
        val buf = ByteBufferPool.acquire()
        tcb.referencePacket.updateTCPBuffer(buf,
            (Packet.TCPHeader.SYN.toInt() or Packet.TCPHeader.ACK.toInt()).toByte(),
            seq, ack, 0)
        buf.position(0)
        buf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
        enqueue(buf)
    }

    private fun sendFinAck(tcb: Tcb) {
        val buf = ByteBufferPool.acquire()
        tcb.referencePacket.updateTCPBuffer(buf,
            (Packet.TCPHeader.FIN.toInt() or Packet.TCPHeader.ACK.toInt()).toByte(),
            tcb.mySequenceNum, tcb.theirSequenceNum, 0)
        buf.position(0)
        buf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
        enqueue(buf)
        tcb.mySequenceNum++
    }

    private fun sendRst(tcb: Tcb) {
        val buf = ByteBufferPool.acquire()
        tcb.referencePacket.updateTCPBuffer(buf, Packet.TCPHeader.RST, 0, 0, 0)
        buf.position(0)
        buf.limit(Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE)
        enqueue(buf)
    }

    private fun closeCleanly(tcb: Tcb) {
        Tcb.remove(tcb.key)
        try { tcb.channel.close() } catch (_: Exception) {}
    }

    private fun enqueue(buf: java.nio.ByteBuffer) {
        val bytes = ByteArray(buf.limit())
        buf.position(0)
        buf.get(bytes)
        ByteBufferPool.release(buf)
        outputQueue.offer(bytes)
    }
}
