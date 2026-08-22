package com.aegis.sentinel.core.detect

import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * All fixtures are synthetic and benign: they describe *metadata* of file activity
 * (paths, entropy values, flags). No malicious payload or encryption routine exists here.
 */
class FileDefenseDetectorTest {

    private fun write(
        i: Int,
        ts: Long,
        dir: String = "/storage/emulated/0/Documents",
        ext: String = "jpg",
        extChanged: Boolean = false,
        entropy: Double? = null,
        mismatch: Boolean = false,
        pkg: String = "com.example.suspect",
    ) = Event(
        id = "evt-$i",
        type = EventType.FILE_WRITE,
        timestamp = ts,
        packageName = pkg,
        observability = Observability.PLATFORM_DIRECT,
        attributes = buildMap {
            put("path", "$dir/file$i.$ext")
            put("extension_changed", extChanged.toString())
            put("type_mismatch", mismatch.toString())
        },
        numeric = buildMap { entropy?.let { put("entropy", it) } },
    )

    @Test
    fun `normal light file activity produces no evidence`() {
        val d = FileDefenseDetector()
        var found = 0
        for (i in 1..10) {
            found += d.onEvent(write(i, ts = i * 1000L)).size
        }
        assertEquals(0, found)
    }

    @Test
    fun `mass rewrite with uniform new extension and high entropy is detected`() {
        val d = FileDefenseDetector()
        var evidence = emptyList<com.aegis.sentinel.core.model.Evidence>()
        for (i in 1..40) {
            evidence = d.onEvent(
                write(i, ts = i * 100L, ext = "locked", extChanged = true, entropy = 7.9)
            )
        }
        val ids = evidence.map { it.id.substringAfter("file.transformation:").substringBefore(":") }
        assertTrue("expected burst evidence, got $ids", ids.contains("burst"))
        assertTrue("expected extension churn evidence, got $ids", ids.contains("extchurn"))
        assertTrue("expected entropy evidence, got $ids", ids.contains("entropy"))
        assertTrue("expected concentration evidence, got $ids", ids.contains("concentration"))

        val ext = evidence.first { it.id.contains(":extchurn:") }
        assertEquals(Severity.HIGH, ext.severity)
        assertTrue(ext.summary.contains(".locked"))
    }

    /** False-positive guard: a legitimate bulk operation without the other markers stays mild. */
    @Test
    fun `bulk copy without extension change or entropy rise stays low severity`() {
        val d = FileDefenseDetector()
        var evidence = emptyList<com.aegis.sentinel.core.model.Evidence>()
        for (i in 1..30) {
            evidence = d.onEvent(write(i, ts = i * 100L, entropy = 4.0))
        }
        assertTrue(evidence.none { it.id.contains(":entropy:") })
        assertTrue(evidence.none { it.id.contains(":extchurn:") })
        assertTrue(evidence.any { it.id.contains(":burst:") })
        assertEquals(Severity.MEDIUM, evidence.first { it.id.contains(":burst:") }.severity)
    }

    @Test
    fun `activity spread across directories does not trigger concentration`() {
        val d = FileDefenseDetector()
        var evidence = emptyList<com.aegis.sentinel.core.model.Evidence>()
        for (i in 1..30) {
            evidence = d.onEvent(write(i, ts = i * 100L, dir = "/storage/emulated/0/dir${i % 10}"))
        }
        assertTrue(evidence.none { it.id.contains(":concentration:") })
    }

    @Test
    fun `events outside the window are evicted so the detector does not accumulate`() {
        val d = FileDefenseDetector()
        for (i in 1..30) d.onEvent(write(i, ts = i * 100L))
        val before = d.trackedCount()
        assertTrue(before > 0)
        // Jump far beyond the window with a single event.
        d.onEvent(write(999, ts = 10_000_000L), now = 10_000_000L)
        assertEquals(1, d.trackedCount())
    }

    @Test
    fun `tracked events are bounded under a flood`() {
        val d = FileDefenseDetector(FileDefenseDetector.Config(maxTrackedEvents = 100))
        for (i in 1..5000) d.onEvent(write(i, ts = i.toLong()))
        assertTrue("tracking grew unbounded: ${d.trackedCount()}", d.trackedCount() <= 100)
    }

    @Test
    fun `non file events are ignored`() {
        val d = FileDefenseDetector()
        val e = Event(
            id = "n1",
            type = EventType.NETWORK_FLOW,
            timestamp = 1L,
            packageName = "com.example.suspect",
            observability = Observability.PLATFORM_DIRECT,
        )
        assertEquals(0, d.onEvent(e).size)
    }

    @Test
    fun `malformed event without a path is ignored safely`() {
        val d = FileDefenseDetector()
        val e = Event(
            id = "bad",
            type = EventType.FILE_WRITE,
            timestamp = 1L,
            packageName = "com.example.suspect",
            observability = Observability.PLATFORM_DIRECT,
            attributes = mapOf("not_a_path" to "x"),
        )
        assertEquals(0, d.onEvent(e).size)
    }
}
