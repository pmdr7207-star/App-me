package com.aegis.sentinel.core.pipeline

import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Verdict
import com.aegis.sentinel.core.stats.BoundedSample
import com.aegis.sentinel.core.stats.Entropy
import com.aegis.sentinel.core.stats.Ewma
import com.aegis.sentinel.core.stats.PageHinkley
import com.aegis.sentinel.core.stats.TokenBucket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * End-to-end pipeline behaviour. All fixtures are synthetic metadata describing benign or
 * simulated-hostile *patterns*; no malicious code is present or produced.
 */
class DetectionPipelineTest {

    private val pkg = "com.example.suspect"
    private val hour = 3_600_000L

    @Test
    fun `a quiet device produces no alarming verdict`() {
        val p = DetectionPipeline()
        var ts = 0L
        repeat(20) {
            ts += 300_000
            p.ingest(
                Event(
                    id = "e$it", type = EventType.APP_FOREGROUND, timestamp = ts,
                    packageName = "com.example.benign",
                    observability = Observability.PLATFORM_DIRECT,
                )
            )
        }
        val a = p.assess("com.example.benign", ts)
        assertNotEquals(Verdict.LIKELY_MALICIOUS, a.verdict)
    }

    /** Full simulated ransomware-like scenario: multiple independent detectors must agree. */
    @Test
    fun `multi signal ransomware like scenario reaches a malicious verdict`() {
        val p = DetectionPipeline()
        var ts = 0L

        // Stage 1: sideloaded install.
        p.ingest(
            Event(
                id = "i1", type = EventType.APP_INSTALLED, timestamp = ts, packageName = pkg,
                observability = Observability.PLATFORM_DIRECT,
                attributes = mapOf("installer_trusted" to "false"),
            )
        )
        // Stage 2: dangerous permission.
        ts += hour
        p.ingest(
            Event(
                id = "p1", type = EventType.PERMISSION_GRANTED, timestamp = ts, packageName = pkg,
                observability = Observability.PLATFORM_DIRECT,
                attributes = mapOf("dangerous" to "true", "permission" to "MANAGE_EXTERNAL_STORAGE"),
            )
        )
        // Stage 3: mass rewrite with uniform extension + ciphertext entropy.
        for (i in 1..45) {
            ts += 500
            p.ingest(
                Event(
                    id = "f$i", type = EventType.FILE_WRITE, timestamp = ts, packageName = pkg,
                    observability = Observability.PLATFORM_DIRECT,
                    attributes = mapOf(
                        "path" to "/storage/emulated/0/DCIM/img$i.locked",
                        "extension_changed" to "true",
                    ),
                    numeric = mapOf("entropy" to 7.93),
                )
            )
        }
        // Stage 4: regular outbound beaconing.
        for (i in 0..12) {
            ts += 60_000
            p.ingest(
                Event(
                    id = "n$i", type = EventType.NETWORK_FLOW, timestamp = ts, packageName = pkg,
                    observability = Observability.PLATFORM_DIRECT,
                    attributes = mapOf("endpoint" to "203.0.113.9:443"),
                    numeric = mapOf("bytes_out" to 2_000_000.0),
                )
            )
        }

        val a = p.assess(pkg, ts)
        assertEquals(
            "expected malicious; score=${a.score} rationale=${a.rationale}",
            Verdict.LIKELY_MALICIOUS,
            a.verdict,
        )
        assertTrue("verdict must be traceable", a.supporting.isNotEmpty())
        assertTrue(a.supporting.map { it.detector }.distinct().size >= 3)
    }

    /** Anti-poisoning at pipeline level: hostile activity must not be learned as normal. */
    @Test
    fun `suspicious activity does not become the baseline`() {
        val p = DetectionPipeline()
        var ts = 0L
        for (i in 1..45) {
            ts += 500
            p.ingest(
                Event(
                    id = "f$i", type = EventType.FILE_WRITE, timestamp = ts, packageName = pkg,
                    observability = Observability.PLATFORM_DIRECT,
                    attributes = mapOf(
                        "path" to "/storage/emulated/0/Docs/f$i.locked",
                        "extension_changed" to "true",
                    ),
                    numeric = mapOf("entropy" to 7.9),
                )
            )
        }
        val mem = p.adaptiveMemory()
        val trusted = mem.all().values.count {
            it.stage == com.aegis.sentinel.core.memory.MemoryStage.TRUSTED
        }
        assertEquals("no hostile behaviour may be trusted", 0, trusted)
    }

    /** Backpressure must drop transparently rather than grow without bound. */
    @Test
    fun `event flood is bounded and drops are counted`() {
        val p = DetectionPipeline(config = DetectionPipeline.Config(
            maxEventsPerSecond = 10.0, burstCapacity = 20.0,
        ))
        for (i in 0 until 5000) {
            p.ingest(
                Event(
                    id = "e$i", type = EventType.APP_FOREGROUND, timestamp = 1000L,
                    packageName = pkg, observability = Observability.PLATFORM_DIRECT,
                )
            )
        }
        assertTrue("expected drops under flood", p.droppedEvents > 0)
        assertEquals(5000L, p.processedEvents + p.droppedEvents)
    }

    @Test
    fun `malformed events never crash the pipeline`() {
        val p = DetectionPipeline()
        val malformed = listOf(
            Event("m1", EventType.FILE_WRITE, 1L, null, Observability.PLATFORM_DIRECT),
            Event("m2", EventType.NETWORK_FLOW, 2L, pkg, Observability.PLATFORM_DIRECT,
                attributes = mapOf("endpoint" to "")),
            Event("m3", EventType.DNS_QUERY, 3L, pkg, Observability.UNTRUSTED_CONTENT,
                attributes = mapOf("hostname" to "\u202Eevil")),
            Event("m4", EventType.FILE_WRITE, 4L, pkg, Observability.PLATFORM_DIRECT,
                attributes = mapOf("path" to "no-slash-file"),
                numeric = mapOf("entropy" to Double.NaN)),
        )
        malformed.forEach { p.ingest(it) }
        // Reaching here without an exception is the assertion.
        assertTrue(p.processedEvents >= 4)
    }

    @Test
    fun `threat graph records relationships for the incident timeline`() {
        val p = DetectionPipeline()
        var ts = 0L
        for (i in 0..12) {
            ts += 60_000
            p.ingest(
                Event(
                    id = "n$i", type = EventType.NETWORK_FLOW, timestamp = ts, packageName = pkg,
                    observability = Observability.PLATFORM_DIRECT,
                    attributes = mapOf("endpoint" to "198.51.100.4:443"),
                )
            )
        }
        val g = p.threatGraph()
        assertTrue("graph should have nodes", g.nodeCount > 0)
        assertTrue("package node expected", g.node("package:$pkg") != null)
    }
}

class StatisticsTest {

    @Test
    fun `ewma tracks a shifting mean`() {
        val e = Ewma(0.3)
        repeat(50) { e.update(10.0) }
        assertEquals(10.0, e.mean, 0.5)
        repeat(50) { e.update(20.0) }
        assertTrue(e.mean > 15.0)
    }

    @Test
    fun `robust statistics resist a single extreme outlier`() {
        val s = BoundedSample(64)
        repeat(50) { s.add(10.0) }
        s.add(1_000_000.0)
        assertEquals("median must ignore the outlier", 10.0, s.median(), 1e-9)
    }

    @Test
    fun `bounded sample never exceeds capacity`() {
        val s = BoundedSample(10)
        repeat(1000) { s.add(it.toDouble()) }
        assertEquals(10, s.size)
    }

    @Test
    fun `coefficient of variation identifies regular versus irregular series`() {
        val regular = BoundedSample(32)
        repeat(20) { regular.add(60_000.0) }
        assertTrue(regular.coefficientOfVariation() < 0.05)

        val irregular = BoundedSample(32)
        listOf(1_000.0, 90_000.0, 5_000.0, 250_000.0, 12_000.0, 700_000.0)
            .forEach { irregular.add(it) }
        assertTrue(irregular.coefficientOfVariation() > 0.5)
    }

    @Test
    fun `page hinkley detects a sustained shift but tolerates noise`() {
        val ph = PageHinkley(delta = 0.005, lambda = 8.0)
        var detected = false
        repeat(200) { ph.update(1.0 + (it % 3) * 0.01) }
        repeat(200) { if (ph.update(25.0)) detected = true }
        assertTrue("expected drift detection", detected)
    }

    @Test
    fun `entropy of uniform data is maximal and of constant data is zero`() {
        assertEquals(0.0, Entropy.ofBytes(ByteArray(1024)), 1e-9)
        val all = ByteArray(256) { it.toByte() }
        assertEquals(8.0, Entropy.ofBytes(all), 1e-9)
        assertEquals(0.0, Entropy.ofBytes(ByteArray(0)), 1e-9)
    }

    @Test
    fun `token bucket enforces a rate and refills over time`() {
        val b = TokenBucket(capacity = 5.0, refillPerSecond = 1.0, nowMs = 0)
        repeat(5) { assertTrue(b.tryConsume(0)) }
        assertTrue("bucket must be empty", !b.tryConsume(0))
        assertTrue("should refill after 2s", b.tryConsume(2000))
    }
}
