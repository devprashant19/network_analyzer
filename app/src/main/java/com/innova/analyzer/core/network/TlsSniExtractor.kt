package com.innova.analyzer.core.network

import android.util.Log

object TlsSniExtractor {

    /**
     * Parses the TLS Client Hello and extracts the Server Name Indication (SNI) string.
     */
    fun extractDomain(buffer: ByteArray, payloadOffset: Int, payloadSize: Int): String? {
        try {
            // 1. Basic TLS Validation
            if (payloadSize < 43) return null // Too small to even contain the fixed Client Hello headers
            if (buffer[payloadOffset].toInt() != 0x16) return null // Must be a Handshake record (0x16)
            if (buffer[payloadOffset + 5].toInt() != 0x01) return null // Must be a Client Hello (0x01)

            // 2. Set up our pointer to navigate the variable-length fields
            // We start our pointer exactly at the beginning of the Session ID (byte 43 of the payload)
            var pointer = payloadOffset + 43

            // --- Skip Session ID ---
            val sessionIdLength = buffer[pointer].toInt() and 0xFF
            pointer += 1 + sessionIdLength
            if (pointer >= payloadOffset + payloadSize) return null

            // --- Skip Cipher Suites ---
            val cipherSuitesLength = getInt16(buffer, pointer)
            pointer += 2 + cipherSuitesLength
            if (pointer >= payloadOffset + payloadSize) return null

            // --- Skip Compression Methods ---
            val compressionMethodsLength = buffer[pointer].toInt() and 0xFF
            pointer += 1 + compressionMethodsLength
            if (pointer >= payloadOffset + payloadSize) return null

            // 3. We have reached the Extensions Block!
            val extensionsTotalLength = getInt16(buffer, pointer)
            pointer += 2
            val extensionsEnd = pointer + extensionsTotalLength

            // 4. Iterate through Extensions looking for 0x0000 (SNI)
            while (pointer + 4 <= extensionsEnd && pointer + 4 <= payloadOffset + payloadSize) {
                val extensionType = getInt16(buffer, pointer)
                val extensionLength = getInt16(buffer, pointer + 2)
                pointer += 4

                if (extensionType == 0x0000) { // WE FOUND THE SNI EXTENSION!
                    // Bypass the SNI list headers (2 bytes for list length, 1 byte for type)
                    var sniPointer = pointer
                    val serverNameListLength = getInt16(buffer, sniPointer)
                    sniPointer += 2
                    
                    val serverNameType = buffer[sniPointer].toInt() and 0xFF
                    sniPointer += 1

                    // Type 0 is "host_name". If it's 0, extract the string!
                    if (serverNameType == 0) {
                        val serverNameLength = getInt16(buffer, sniPointer)
                        sniPointer += 2

                        // Validate we don't read out of bounds
                        if (sniPointer + serverNameLength <= payloadOffset + payloadSize) {
                            val domainBytes = buffer.copyOfRange(sniPointer, sniPointer + serverNameLength)
                            return String(domainBytes, Charsets.UTF_8)
                        }
                    }
                }

                // If this wasn't the SNI extension, jump over it and check the next one
                pointer += extensionLength
            }
        } catch (e: Exception) {
            // Network packets can be fragmented or malicious. 
            // If our pointer goes out of bounds, catch it gracefully and ignore the packet.
            Log.v("InnovaVPN", "Failed to parse SNI: ${e.message}")
        }

        return null // Domain not found
    }

    /** Helper to read 2 bytes as an integer */
    private fun getInt16(buffer: ByteArray, offset: Int): Int {
        return ((buffer[offset].toInt() and 0xFF) shl 8) or (buffer[offset + 1].toInt() and 0xFF)
    }
}   