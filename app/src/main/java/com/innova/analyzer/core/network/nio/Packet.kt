package com.innova.analyzer.core.network.nio

import java.net.InetAddress
import java.nio.ByteBuffer

class Packet @Throws(Exception::class) constructor(buffer: ByteBuffer) {

    companion object {
        const val IP4_HEADER_SIZE = 20
        const val TCP_HEADER_SIZE = 20
        const val UDP_HEADER_SIZE = 8
    }

    val ip4Header: IP4Header
    var tcpHeader: TCPHeader? = null
    var udpHeader: UDPHeader? = null
    var backingBuffer: ByteBuffer = buffer

    private val _isTCP: Boolean
    private val _isUDP: Boolean

    init {
        ip4Header = IP4Header(buffer)
        _isTCP = ip4Header.protocol == IP4Header.TransportProtocol.TCP
        _isUDP = ip4Header.protocol == IP4Header.TransportProtocol.UDP
        if (_isTCP) tcpHeader = TCPHeader(buffer)
        else if (_isUDP) udpHeader = UDPHeader(buffer)
    }

    fun isTCP() = _isTCP
    fun isUDP() = _isUDP

    fun swapSourceAndDestination() {
        val tmp = ip4Header.destinationAddress
        ip4Header.destinationAddress = ip4Header.sourceAddress
        ip4Header.sourceAddress = tmp
        if (_isUDP) {
            val p = udpHeader!!.destinationPort
            udpHeader!!.destinationPort = udpHeader!!.sourcePort
            udpHeader!!.sourcePort = p
        } else if (_isTCP) {
            val p = tcpHeader!!.destinationPort
            tcpHeader!!.destinationPort = tcpHeader!!.sourcePort
            tcpHeader!!.sourcePort = p
        }
    }

    fun updateTCPBuffer(buffer: ByteBuffer, flags: Byte, seqNum: Long, ackNum: Long, payloadSize: Int) {
        buffer.position(0)
        fillHeader(buffer)
        backingBuffer = buffer
        val tcp = tcpHeader!!
        tcp.flags = flags
        backingBuffer.put(IP4_HEADER_SIZE + 13, flags)
        tcp.sequenceNumber = seqNum
        backingBuffer.putInt(IP4_HEADER_SIZE + 4, seqNum.toInt())
        tcp.acknowledgementNumber = ackNum
        backingBuffer.putInt(IP4_HEADER_SIZE + 8, ackNum.toInt())
        val dataOffset = (TCP_HEADER_SIZE shl 2).toByte()
        tcp.dataOffsetAndReserved = dataOffset
        backingBuffer.put(IP4_HEADER_SIZE + 12, dataOffset)
        updateTCPChecksum(payloadSize)
        val totalLen = IP4_HEADER_SIZE + TCP_HEADER_SIZE + payloadSize
        backingBuffer.putShort(2, totalLen.toShort())
        ip4Header.totalLength = totalLen
        updateIP4Checksum()
    }

    fun updateUDPBuffer(buffer: ByteBuffer, payloadSize: Int) {
        buffer.position(0)
        fillHeader(buffer)
        backingBuffer = buffer
        val udpLen = UDP_HEADER_SIZE + payloadSize
        backingBuffer.putShort(IP4_HEADER_SIZE + 4, udpLen.toShort())
        udpHeader!!.length = udpLen
        backingBuffer.putShort(IP4_HEADER_SIZE + 6, 0.toShort())
        udpHeader!!.checksum = 0
        val totalLen = IP4_HEADER_SIZE + udpLen
        backingBuffer.putShort(2, totalLen.toShort())
        ip4Header.totalLength = totalLen
        updateIP4Checksum()
    }

    private fun fillHeader(buffer: ByteBuffer) {
        ip4Header.fillHeader(buffer)
        if (_isUDP) udpHeader!!.fillHeader(buffer)
        else if (_isTCP) tcpHeader!!.fillHeader(buffer)
    }

    private fun updateIP4Checksum() {
        val buf = backingBuffer
        buf.putShort(10, 0.toShort())
        var sum = 0
        for (i in 0 until IP4_HEADER_SIZE step 2) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
        }
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        buf.putShort(10, sum.inv().toShort())
        ip4Header.headerChecksum = sum.inv() and 0xFFFF
    }

    private fun updateTCPChecksum(payloadSize: Int) {
        val buf = backingBuffer
        val tcpLength = TCP_HEADER_SIZE + payloadSize
        buf.putShort(IP4_HEADER_SIZE + 16, 0.toShort())
        var sum = 0
        val src = ip4Header.sourceAddress.address
        val dst = ip4Header.destinationAddress.address
        sum += ((src[0].toInt() and 0xFF) shl 8) or (src[1].toInt() and 0xFF)
        sum += ((src[2].toInt() and 0xFF) shl 8) or (src[3].toInt() and 0xFF)
        sum += ((dst[0].toInt() and 0xFF) shl 8) or (dst[1].toInt() and 0xFF)
        sum += ((dst[2].toInt() and 0xFF) shl 8) or (dst[3].toInt() and 0xFF)
        sum += 6
        sum += tcpLength
        val start = IP4_HEADER_SIZE
        var i = start
        while (i < start + tcpLength - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (tcpLength % 2 != 0) sum += (buf[start + tcpLength - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        buf.putShort(IP4_HEADER_SIZE + 16, sum.inv().toShort())
        tcpHeader!!.checksum = sum.inv() and 0xFFFF
    }

    // ---- Nested header classes — use fully qualified outer companion constants -----

    class IP4Header(buffer: ByteBuffer) {
        enum class TransportProtocol {
            TCP, UDP, OTHER;
            companion object {
                fun fromNum(n: Int) = when (n) { 6 -> TCP; 17 -> UDP; else -> OTHER }
            }
        }

        // All primitives initialised to zero; reference types use lateinit.
        // init{} block sets the real values immediately.
        var version: Int = 0
        var ihl: Int = 0
        var typeOfService: Int = 0
        var totalLength: Int = 0
        var identificationAndFlagsAndFragmentOffset: Int = 0
        var ttl: Int = 0
        var protocolNum: Int = 0
        var protocol: TransportProtocol = TransportProtocol.OTHER
        var headerChecksum: Int = 0
        lateinit var sourceAddress: InetAddress
        lateinit var destinationAddress: InetAddress

        init {
            val vAndIHL = buffer.get().toInt() and 0xFF
            version = vAndIHL ushr 4
            ihl = (vAndIHL and 0x0F) * 4
            typeOfService = buffer.get().toInt() and 0xFF
            totalLength = buffer.short.toInt() and 0xFFFF
            identificationAndFlagsAndFragmentOffset = buffer.int
            ttl = buffer.get().toInt() and 0xFF
            protocolNum = buffer.get().toInt() and 0xFF
            protocol = TransportProtocol.fromNum(protocolNum)
            headerChecksum = buffer.short.toInt() and 0xFFFF
            sourceAddress = InetAddress.getByAddress(ByteArray(4).also { buffer.get(it) })
            destinationAddress = InetAddress.getByAddress(ByteArray(4).also { buffer.get(it) })
            if (ihl > 20) buffer.position(buffer.position() + (ihl - 20))
        }

        fun fillHeader(buf: ByteBuffer) {
            // IP4_HEADER_SIZE is in Packet companion — qualify fully from nested class
            buf.put(((version shl 4) or (Packet.IP4_HEADER_SIZE / 4)).toByte())
            buf.put(typeOfService.toByte())
            buf.putShort(totalLength.toShort())
            buf.putInt(identificationAndFlagsAndFragmentOffset)
            buf.put(ttl.toByte())
            buf.put(protocolNum.toByte())
            buf.putShort(headerChecksum.toShort())
            buf.put(sourceAddress.address)
            buf.put(destinationAddress.address)
        }
    }

    class TCPHeader(buffer: ByteBuffer) {
        companion object {
            const val FIN: Byte = 0x01
            const val SYN: Byte = 0x02
            const val RST: Byte = 0x04
            const val PSH: Byte = 0x08
            const val ACK: Byte = 0x10
        }

        var sourcePort: Int = 0
        var destinationPort: Int = 0
        var sequenceNumber: Long = 0L
        var acknowledgementNumber: Long = 0L
        var dataOffsetAndReserved: Byte = 0
        var headerLength: Int = 0
        var flags: Byte = 0
        var window: Int = 0
        var checksum: Int = 0
        var urgentPointer: Int = 0

        init {
            sourcePort = buffer.short.toInt() and 0xFFFF
            destinationPort = buffer.short.toInt() and 0xFFFF
            sequenceNumber = buffer.int.toLong() and 0xFFFFFFFFL
            acknowledgementNumber = buffer.int.toLong() and 0xFFFFFFFFL
            dataOffsetAndReserved = buffer.get()
            headerLength = ((dataOffsetAndReserved.toInt() and 0xF0) ushr 2)
            flags = buffer.get()
            window = buffer.short.toInt() and 0xFFFF
            checksum = buffer.short.toInt() and 0xFFFF
            urgentPointer = buffer.short.toInt() and 0xFFFF
            // TCP_HEADER_SIZE lives in Packet companion — must qualify from nested class
            val optLen = headerLength - Packet.TCP_HEADER_SIZE
            if (optLen > 0) buffer.position(buffer.position() + optLen)
        }

        fun isFIN() = (flags.toInt() and FIN.toInt()) != 0
        fun isSYN() = (flags.toInt() and SYN.toInt()) != 0
        fun isRST() = (flags.toInt() and RST.toInt()) != 0
        fun isACK() = (flags.toInt() and ACK.toInt()) != 0

        fun fillHeader(buf: ByteBuffer) {
            buf.putShort(sourcePort.toShort())
            buf.putShort(destinationPort.toShort())
            buf.putInt(sequenceNumber.toInt())
            buf.putInt(acknowledgementNumber.toInt())
            buf.put(dataOffsetAndReserved)
            buf.put(flags)
            buf.putShort(window.toShort())
            buf.putShort(checksum.toShort())
            buf.putShort(urgentPointer.toShort())
        }
    }

    class UDPHeader(buffer: ByteBuffer) {
        var sourcePort: Int = 0
        var destinationPort: Int = 0
        var length: Int = 0
        var checksum: Int = 0

        init {
            sourcePort = buffer.short.toInt() and 0xFFFF
            destinationPort = buffer.short.toInt() and 0xFFFF
            length = buffer.short.toInt() and 0xFFFF
            checksum = buffer.short.toInt() and 0xFFFF
        }

        fun fillHeader(buf: ByteBuffer) {
            buf.putShort(sourcePort.toShort())
            buf.putShort(destinationPort.toShort())
            buf.putShort(length.toShort())
            buf.putShort(checksum.toShort())
        }
    }
}
