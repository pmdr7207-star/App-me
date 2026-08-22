package com.aegis.sentinel.core.detect

import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkBehaviorDetectorTest {

    private fun flow(i: Int, ts: Long, endpoint: String = "198.51.100.10:443") = Event(
        id = "f$i",
        type = EventType.NETWORK_FLOW,
        timestamp = ts,
        packageName = "com.example.suspect",
        observability = Observability.PLATFORM_DIRECT,
        attributes = mapOf("endpoint" to endpoint),
    )

    private fun dns(i: Int, host: String) = Event(
        id = "d$i",
        type = EventType.DNS_QUERY,
        timestamp = i * 1000L,
        packageName = "com.example.suspect",
        observability = Observability.PLATFORM_DIRECT,
        attributes = mapOf("hostname" to host),
    )

    @Test
    fun `perfectly regular contact is flagged as beaconing`() {
        val d = NetworkBehaviorDetector()
        var last = emptyList<com.aegis.sentinel.core.model.Evidence>()
        for (i in 0..12) {
            last = d.onEvent(flow(i, ts = i * 60_000L))
        }
        assertTrue("expected beacon evidence", last.any { it.id.contains(":beacon:") })
    }

    /** Human-driven traffic is irregular and must not be flagged. */
    @Test
    fun `irregular human like traffic is not flagged as beaconing`() {
        val d = NetworkBehaviorDetector()
        val gaps = listOf(5_000L, 47_000, 12_000, 190_000, 8_000, 63_000, 240_000, 15_000, 92_000, 33_000, 410_000, 7_000)
        var ts = 0L
        val all = mutableListOf<com.aegis.sentinel.core.model.Evidence>()
        gaps.forEachIndexed { i, g ->
            ts += g
            all += d.onEvent(flow(i, ts))
        }
        assertTrue("irregular traffic must not beacon-flag: ${all.map { it.id }}",
            all.none { it.id.contains(":beacon:") })
    }

    @Test
    fun `high entropy hostname is flagged but only as weak untrusted evidence`() {
        val d = NetworkBehaviorDetector()
        val e = d.onEvent(dns(1, "x7q2mz9vbk3rt8w.example"))
        assertTrue(e.isNotEmpty())
        val dga = e.first { it.id.contains(":dga:") }
        assertEquals(Observability.UNTRUSTED_CONTENT, dga.observability)
        assertTrue("DGA alone must stay low severity", dga.severity.ordinal <= com.aegis.sentinel.core.model.Severity.LOW.ordinal)
    }

    @Test
    fun `ordinary hostnames are not flagged`() {
        val d = NetworkBehaviorDetector()
        listOf("update.example.com", "cdn.samsung.com", "www.google.com", "api.github.com")
            .forEachIndexed { i, h ->
                assertTrue("false positive on $h", d.onEvent(dns(i, h)).none { it.id.contains(":dga:") })
            }
    }

    @Test
    fun `endpoint tracking is bounded`() {
        val d = NetworkBehaviorDetector(NetworkBehaviorDetector.Config(maxEndpoints = 50))
        for (i in 0 until 2000) {
            d.onEvent(flow(i, ts = i * 1000L, endpoint = "10.0.0.$i:443"))
        }
        assertTrue("endpoints grew unbounded: ${d.trackedEndpoints()}", d.trackedEndpoints() <= 50)
    }

    @Test
    fun `entropy calculation is correct for known inputs`() {
        val d = NetworkBehaviorDetector()
        assertEquals(0.0, d.labelEntropyBits("aaaa"), 1e-9)
        assertEquals(1.0, d.labelEntropyBits("abab"), 1e-9)
        assertEquals(2.0, d.labelEntropyBits("abcd"), 1e-9)
    }

    @Test
    fun `malformed events are ignored safely`() {
        val d = NetworkBehaviorDetector()
        val noEndpoint = Event(
            id = "x", type = EventType.NETWORK_FLOW, timestamp = 1L,
            packageName = "p", observability = Observability.PLATFORM_DIRECT,
        )
        assertEquals(0, d.onEvent(noEndpoint).size)
    }
}
