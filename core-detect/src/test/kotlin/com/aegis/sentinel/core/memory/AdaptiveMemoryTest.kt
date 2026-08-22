package com.aegis.sentinel.core.memory

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AdaptiveMemoryTest {

    private val day = 24L * 60 * 60 * 1000

    @Test
    fun `first observation is never trusted`() {
        val m = AdaptiveMemory()
        val e = m.observe("pkg|NET|host", now = 0, sessionId = 1)
        assertEquals(MemoryStage.OBSERVED, e.stage)
        assertEquals(0.0, e.trustWeight(), 1e-9)
    }

    @Test
    fun `promotion requires observations time and distinct sessions`() {
        val m = AdaptiveMemory()
        val key = "pkg|NET|host"

        // Many observations, but all in one session and all at t=0.
        repeat(30) { m.observe(key, now = 0, sessionId = 1) }
        assertEquals(
            "same-session burst must not reach TRUSTED",
            MemoryStage.PROVISIONAL,
            m.get(key)!!.stage,
        )

        // Spread across sessions and time.
        var t = 0L
        for (s in 2..10) {
            t += day
            m.observe(key, now = t, sessionId = s)
        }
        assertEquals(MemoryStage.TRUSTED, m.get(key)!!.stage)
    }

    /** Anti-poisoning: suspicious activity must never widen the definition of normal. */
    @Test
    fun `suspicious observations can never promote to trusted`() {
        val m = AdaptiveMemory()
        val key = "pkg|FILE|bulkwrite"
        var t = 0L
        repeat(60) {
            t += day
            m.observe(key, now = t, sessionId = it + 1, suspicious = true)
        }
        val e = m.get(key)!!
        assertNotEquals(MemoryStage.TRUSTED, e.stage)
        assertNotEquals(MemoryStage.VALIDATED, e.stage)
        assertTrue(e.trustWeight() <= 0.25)
    }

    /** Retroactive suspicion must strip previously granted trust. */
    @Test
    fun `marking suspicious demotes a trusted entry`() {
        val m = AdaptiveMemory()
        val key = "pkg|NET|host"
        var t = 0L
        for (s in 1..25) {
            t += day
            m.observe(key, now = t, sessionId = s)
        }
        assertEquals(MemoryStage.TRUSTED, m.get(key)!!.stage)

        m.markSuspicious(key)
        assertEquals(MemoryStage.PROVISIONAL, m.get(key)!!.stage)
    }

    @Test
    fun `snapshot and rollback restore prior learned state`() {
        val m = AdaptiveMemory()
        val key = "pkg|NET|host"
        var t = 0L
        for (s in 1..25) {
            t += day
            m.observe(key, now = t, sessionId = s)
        }
        val snap = m.snapshot(t)
        val versionAtSnapshot = m.version
        assertEquals(MemoryStage.TRUSTED, m.get(key)!!.stage)

        // Poison the memory afterwards.
        repeat(5) { m.observe(key, now = t, sessionId = 99, suspicious = true) }
        assertNotEquals(MemoryStage.TRUSTED, m.get(key)!!.stage)

        m.rollbackTo(snap)
        assertEquals(MemoryStage.TRUSTED, m.get(key)!!.stage)
        assertTrue("rollback must itself be versioned", m.version > versionAtSnapshot)
    }

    @Test
    fun `memory is bounded under flood`() {
        val policy = MemoryPolicy(maxEntries = 100)
        val m = AdaptiveMemory(policy)
        for (i in 0 until 5000) {
            m.observe("key-$i", now = i.toLong(), sessionId = 1)
        }
        assertTrue("memory grew unbounded: ${m.size}", m.size <= 100)
    }

    @Test
    fun `every mutation bumps the version`() {
        val m = AdaptiveMemory()
        val v0 = m.version
        m.observe("k", now = 1, sessionId = 1)
        val v1 = m.version
        m.observe("k", now = 2, sessionId = 2)
        assertTrue(v1 > v0)
        assertTrue(m.version > v1)
    }
}

class BehaviorBaselineTest {

    /** Baseline poisoning: a flagged sample must not be folded into "normal". */
    @Test
    fun `suspicious samples are refused by the baseline`() {
        val b = BehaviorBaseline()
        repeat(20) { b.update("pkg:bytes_out", 1000.0) }

        val accepted = b.update("pkg:bytes_out", 50_000_000.0, suspicious = true)
        assertTrue("suspicious sample must be rejected", !accepted)

        // The huge value never entered the baseline, so it still reads as a strong anomaly.
        val z = b.robustZ("pkg:bytes_out", 50_000_000.0)
        assertTrue("expected large anomaly score, got $z", z > 5.0)
    }

    @Test
    fun `baseline requires history before it is considered established`() {
        val b = BehaviorBaseline()
        assertTrue(!b.isEstablished("pkg:f"))
        repeat(8) { b.update("pkg:f", 1.0) }
        assertTrue(b.isEstablished("pkg:f"))
    }

    @Test
    fun `gradual poisoning still shifts a baseline only slowly`() {
        val b = BehaviorBaseline(sampleCapacity = 64)
        repeat(64) { b.update("pkg:f", 100.0) }
        // Attacker drips in slightly larger values that are not individually flagged.
        repeat(10) { b.update("pkg:f", 130.0) }
        // A large jump must still be detected as anomalous.
        assertTrue(b.robustZ("pkg:f", 10_000.0) > 5.0)
    }
}
