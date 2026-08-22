package com.aegis.sentinel.platform.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * The parser reads attacker-influenced bytes, so malformed input must return null rather than
 * throw or read out of bounds. These tests exercise exactly that.
 */
class PacketMetadataParserTest {

    private fun ipv4Packet(
        protocol: Int = 6,
        srcPort: Int = 12345,
        dstPort: Int = 443,
        ihlWords: Int = 5,
        totalSize: Int = 40,
    ): ByteArray {
        val b = ByteArray(totalSize)
        b[0] = ((4 shl 4) or ihlWords).toByte()
        b[9] = protocol.toByte()
        // src 192.0.2.1
        b[12] = 192.toByte(); b[13] = 0; b[14] = 2; b[15] = 1
        // dst 198.51.100.7
        b[16] = 198.toByte(); b[17] = 51; b[18] = 100; b[19] = 7
        val hdr = ihlWords * 4
        b[hdr] = (srcPort ushr 8).toByte()
        b[hdr + 1] = (srcPort and 0xFF).toByte()
        b[hdr + 2] = (dstPort ushr 8).toByte()
        b[hdr + 3] = (dstPort and 0xFF).toByte()
        return b
    }

    @Test
    fun `parses a well formed ipv4 tcp packet`() {
        val m = PacketMetadataParser.parse(ipv4Packet(), 40)!!
        assertEquals(4, m.version)
        assertEquals("TCP", m.protocolName)
        assertEquals("192.0.2.1", m.sourceAddress)
        assertEquals("198.51.100.7", m.destinationAddress)
        assertEquals(12345, m.sourcePort)
        assertEquals(443, m.destinationPort)
    }

    @Test
    fun `parses udp`() {
        val m = PacketMetadataParser.parse(ipv4Packet(protocol = 17, dstPort = 53), 40)!!
        assertEquals("UDP", m.protocolName)
        assertEquals(53, m.destinationPort)
    }

    @Test
    fun `parses ipv6 header`() {
        val b = ByteArray(60)
        b[0] = (6 shl 4).toByte()
        b[6] = 6 // next header TCP
        b[40] = 0x1F; b[41] = 0x90 // sport 8080
        b[42] = 0x01; b[43] = 0xBB.toByte() // dport 443
        val m = PacketMetadataParser.parse(b, 60)!!
        assertEquals(6, m.version)
        assertEquals(8080, m.sourcePort)
        assertEquals(443, m.destinationPort)
    }

    @Test
    fun `rejects truncated packets`() {
        assertNull(PacketMetadataParser.parse(ipv4Packet(), 10))
        assertNull(PacketMetadataParser.parse(ByteArray(60).also { it[0] = (6 shl 4).toByte() }, 20))
    }

    @Test
    fun `rejects empty and oversized length claims`() {
        assertNull(PacketMetadataParser.parse(ByteArray(0), 0))
        assertNull(PacketMetadataParser.parse(ByteArray(10), 5000))
        assertNull(PacketMetadataParser.parse(ByteArray(40), -1))
    }

    @Test
    fun `rejects a bogus ip version`() {
        val b = ByteArray(40)
        b[0] = (9 shl 4).toByte()
        assertNull(PacketMetadataParser.parse(b, 40))
    }

    /** A lying IHL must not cause an out-of-bounds read. */
    @Test
    fun `rejects an impossible header length`() {
        assertNull(PacketMetadataParser.parse(ipv4Packet(ihlWords = 15, totalSize = 24), 24))
        assertNull(PacketMetadataParser.parse(ipv4Packet(ihlWords = 2, totalSize = 40), 40))
    }

    /** Fuzz: random bytes must never throw. */
    @Test
    fun `random input never throws`() {
        val rnd = java.util.Random(42)
        repeat(5000) {
            val size = 1 + rnd.nextInt(80)
            val b = ByteArray(size).also { rnd.nextBytes(it) }
            PacketMetadataParser.parse(b, size)
        }
    }
}
