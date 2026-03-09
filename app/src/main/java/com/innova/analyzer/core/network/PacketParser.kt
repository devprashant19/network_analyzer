package com.innova.analyzer.core.network

import com.innova.analyzer.data.models.ConnectionProtocol
import com.innova.analyzer.data.models.NetworkEvent

object PacketParser {

    /**
     * Translates a raw array of bytes from the VPN tunnel into a clean NetworkEvent object.
     */
    fun parseIPv4Packet(buffer: ByteArray, length: Int): NetworkEvent? {
        // Minimum IPv4 header size is 20 bytes. Ignore anything smaller.
        if (length < 20) return null 

        // 1. IP Header parsing
        val versionAndIhl = buffer[0].toInt()
        val version = (versionAndIhl shr 4) and 0x0F
        if (version != 4) return null // Drop IPv6 or malformed packets

        // Calculate IP Header Length (IHL is the bottom 4 bits, multiplied by 4 bytes)
        val ipHeaderLength = (versionAndIhl and 0x0F) * 4
        if (length < ipHeaderLength) return null

        // Byte 9 is the Protocol field in the IP header
        val protocolNum = buffer[9].toInt() and 0xFF
        
        // FILTER 1: Drop everything that isn't TCP (Protocol 6) to save battery
        if (protocolNum != 6) return null

        // Extract IPs (Bytes 12-15 for Source, 16-19 for Dest)
        val sourceIp = getIpAddress(buffer, 12)
        val destIp = getIpAddress(buffer, 16)

        // 2. TCP Header parsing (starts exactly after the IP header)
        if (length < ipHeaderLength + 20) return null // Minimum TCP header size is 20 bytes

        val sourcePort = getPort(buffer, ipHeaderLength)
        val destPort = getPort(buffer, ipHeaderLength + 2)

        // FILTER 2: Drop everything except HTTP (80) and HTTPS (443)
        if (destPort != 80 && destPort != 443) return null

        // 3. Calculate where the actual Payload (Application Data) starts
        // The Data Offset is a 4-bit field at byte 12 of the TCP header.
        val dataOffset = (buffer[ipHeaderLength + 12].toInt() shr 4) and 0x0F
        val tcpHeaderLength = dataOffset * 4
        
        val payloadOffset = ipHeaderLength + tcpHeaderLength
        val payloadSize = length - payloadOffset

        // We only care if there is actual data being sent (drop empty TCP ACKs)
        if (payloadSize <= 0) return null

        // 4. Hunt for the domain! (If it's HTTPS)
        var extractedDomain: String? = null
        if (destPort == 443) {
            extractedDomain = TlsSniExtractor.extractDomain(buffer, payloadOffset, payloadSize)
        }

        // 5. Construct and return the Contract!
        return NetworkEvent(
            uid = -1, // We will map this to an app UID later
            packageName = null,
            appName = null,
            protocol = ConnectionProtocol.TCP,
            sourceIp = sourceIp,
            sourcePort = sourcePort,
            destIp = destIp,
            destPort = destPort,
            domain = extractedDomain, 
            payloadSize = payloadSize,
            isSuspicious = false // Threat analytics happens in Phase 3
        )
    }

    /** Helper to translate 4 bytes into a standard "192.168.x.x" string */
    private fun getIpAddress(buffer: ByteArray, offset: Int): String {
        return "${buffer[offset].toUByte()}.${buffer[offset + 1].toUByte()}.${buffer[offset + 2].toUByte()}.${buffer[offset + 3].toUByte()}"
    }

    /** Helper to translate 2 bytes into a 16-bit port number */
    private fun getPort(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }
}