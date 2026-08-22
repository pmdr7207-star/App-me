package com.aegis.sentinel.platform.net

/**
 * Minimal, defensive IP header parser.
 *
 * Extracts only routing metadata (addresses, ports, protocol) from an IPv4/IPv6 packet. Payload
 * bytes are never read, retained or interpreted — this is metadata analysis, not packet inspection.
 *
 * Every field access is bounds-checked: this parses attacker-influenced bytes, so a malformed
 * packet must return null rather than throw or read out of bounds.
 */
object PacketMetadataParser {

    data class Metadata(
        val version: Int,
        val protocol: Int,
        val protocolName: String,
        val sourceAddress: String,
        val destinationAddress: String,
        val sourcePort: Int,
        val destinationPort: Int,
        val totalLength: Int,
    )

    private const val PROTO_TCP = 6
    private const val PROTO_UDP = 17

    fun parse(buffer: ByteArray, length: Int): Metadata? {
        if (length < 1 || length > buffer.size) return null
        return when ((buffer[0].toInt() and 0xF0) ushr 4) {
            4 -> parseIpv4(buffer, length)
            6 -> parseIpv6(buffer, length)
            else -> null
        }
    }

    private fun parseIpv4(b: ByteArray, length: Int): Metadata? {
        if (length < 20) return null
        val ihl = (b[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return null

        val protocol = b[9].toInt() and 0xFF
        val src = ipv4(b, 12) ?: return null
        val dst = ipv4(b, 16) ?: return null

        var sport = 0
        var dport = 0
        if (protocol == PROTO_TCP || protocol == PROTO_UDP) {
            if (length < ihl + 4) return null
            sport = u16(b, ihl)
            dport = u16(b, ihl + 2)
        }

        return Metadata(
            version = 4,
            protocol = protocol,
            protocolName = protocolName(protocol),
            sourceAddress = src,
            destinationAddress = dst,
            sourcePort = sport,
            destinationPort = dport,
            totalLength = length,
        )
    }

    private fun parseIpv6(b: ByteArray, length: Int): Metadata? {
        if (length < 40) return null
        val nextHeader = b[6].toInt() and 0xFF
        val src = ipv6(b, 8) ?: return null
        val dst = ipv6(b, 24) ?: return null

        var sport = 0
        var dport = 0
        if (nextHeader == PROTO_TCP || nextHeader == PROTO_UDP) {
            if (length < 44) return null
            sport = u16(b, 40)
            dport = u16(b, 42)
        }

        return Metadata(
            version = 6,
            protocol = nextHeader,
            protocolName = protocolName(nextHeader),
            sourceAddress = src,
            destinationAddress = dst,
            sourcePort = sport,
            destinationPort = dport,
            totalLength = length,
        )
    }

    private fun protocolName(p: Int): String = when (p) {
        PROTO_TCP -> "TCP"
        PROTO_UDP -> "UDP"
        1 -> "ICMP"
        58 -> "ICMPv6"
        else -> "IP($p)"
    }

    private fun u16(b: ByteArray, offset: Int): Int {
        if (offset + 1 >= b.size) return 0
        return ((b[offset].toInt() and 0xFF) shl 8) or (b[offset + 1].toInt() and 0xFF)
    }

    private fun ipv4(b: ByteArray, offset: Int): String? {
        if (offset + 3 >= b.size) return null
        return "${b[offset].toInt() and 0xFF}.${b[offset + 1].toInt() and 0xFF}." +
            "${b[offset + 2].toInt() and 0xFF}.${b[offset + 3].toInt() and 0xFF}"
    }

    private fun ipv6(b: ByteArray, offset: Int): String? {
        if (offset + 15 >= b.size) return null
        val parts = ArrayList<String>(8)
        for (i in 0 until 8) {
            parts.add("%x".format(u16(b, offset + i * 2)))
        }
        return parts.joinToString(":")
    }
}
