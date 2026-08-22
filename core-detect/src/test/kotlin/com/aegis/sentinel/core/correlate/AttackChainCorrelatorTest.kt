package com.aegis.sentinel.core.correlate

import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AttackChainCorrelatorTest {

    private val hour = 60L * 60 * 1000
    private val pkg = "com.example.suspect"

    private fun install(ts: Long, trusted: Boolean = false) = Event(
        id = "i-$ts", type = EventType.APP_INSTALLED, timestamp = ts, packageName = pkg,
        observability = Observability.PLATFORM_DIRECT,
        attributes = mapOf("installer_trusted" to trusted.toString()),
    )

    private fun perm(ts: Long) = Event(
        id = "p-$ts", type = EventType.PERMISSION_GRANTED, timestamp = ts, packageName = pkg,
        observability = Observability.PLATFORM_DIRECT,
        attributes = mapOf("dangerous" to "true", "permission" to "READ_SMS"),
    )

    private fun upload(ts: Long, bytes: Double = 5_000_000.0) = Event(
        id = "n-$ts", type = EventType.NETWORK_FLOW, timestamp = ts, packageName = pkg,
        observability = Observability.PLATFORM_DIRECT,
        attributes = mapOf("endpoint" to "203.0.113.5:443"),
        numeric = mapOf("bytes_out" to bytes),
    )

    @Test
    fun `complete sideload to exfil chain produces high severity evidence`() {
        val c = AttackChainCorrelator()
        assertTrue(c.onEvent(install(0)).isEmpty())
        assertTrue(c.onEvent(perm(hour)).isEmpty())
        val ev = c.onEvent(upload(2 * hour))

        assertEquals(1, ev.size)
        assertEquals(Severity.HIGH, ev.first().severity)
        assertEquals(3, ev.first().sourceEventIds.size)
        assertTrue(ev.first().summary.contains("Sideloaded install"))
    }

    /** Order matters: the same events out of sequence must not complete the chain. */
    @Test
    fun `out of order events do not complete a chain`() {
        val c = AttackChainCorrelator()
        assertTrue(c.onEvent(upload(0)).isEmpty())
        assertTrue(c.onEvent(perm(hour)).isEmpty())
        // Install last: the chain restarts at stage 1 rather than completing.
        assertTrue(c.onEvent(install(2 * hour)).isEmpty())
    }

    /** A chain that drags on beyond its window is not a chain. */
    @Test
    fun `stale partial chains expire`() {
        val c = AttackChainCorrelator()
        c.onEvent(install(0))
        c.onEvent(perm(hour))
        // 48h later, far outside the 24h window.
        val ev = c.onEvent(upload(48 * hour))
        assertTrue("chain should have expired", ev.isEmpty())
    }

    @Test
    fun `trusted store install does not start the sideload chain`() {
        val c = AttackChainCorrelator()
        c.onEvent(install(0, trusted = true))
        c.onEvent(perm(hour))
        assertTrue(c.onEvent(upload(2 * hour)).isEmpty())
    }

    @Test
    fun `download install accessibility chain is critical`() {
        val c = AttackChainCorrelator()
        c.onEvent(
            Event(
                id = "d1", type = EventType.DOWNLOAD_COMPLETED, timestamp = 0, packageName = pkg,
                observability = Observability.PLATFORM_DIRECT,
                attributes = mapOf("mime" to "application/vnd.android.package-archive"),
            )
        )
        c.onEvent(install(1000))
        val ev = c.onEvent(
            Event(
                id = "a1", type = EventType.SPECIAL_ACCESS_CHANGED, timestamp = 2000,
                packageName = pkg, observability = Observability.PLATFORM_DIRECT,
                attributes = mapOf("access" to "accessibility", "enabled" to "true"),
            )
        )
        assertEquals(Severity.CRITICAL, ev.single().severity)
    }

    /** A chain is only as trustworthy as its weakest observation. */
    @Test
    fun `chain observability degrades to its weakest link`() {
        val c = AttackChainCorrelator()
        c.onEvent(install(0))
        c.onEvent(perm(hour))
        val weak = upload(2 * hour).copy(observability = Observability.UNTRUSTED_CONTENT)
        val ev = c.onEvent(weak)
        assertEquals(Observability.UNTRUSTED_CONTENT, ev.single().observability)
    }

    @Test
    fun `events without a package are ignored`() {
        val c = AttackChainCorrelator()
        val anon = install(0).copy(packageName = null)
        assertTrue(c.onEvent(anon).isEmpty())
    }
}
