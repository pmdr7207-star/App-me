package com.aegis.sentinel

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.aegis.sentinel.core.model.Confidence
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.core.model.Reliability
import com.aegis.sentinel.core.model.Severity
import com.aegis.sentinel.platform.evidence.EvidenceStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Verifies the Keystore-backed encryption and the tamper-evident MAC chain on a real device.
 */
@RunWith(AndroidJUnit4::class)
class EvidenceStoreInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var store: EvidenceStore

    private fun evidence(id: String) = Evidence(
        id = id,
        detector = "test.detector",
        packageName = "com.example.subject",
        timestamp = 1_700_000_000_000,
        severity = Severity.HIGH,
        confidence = Confidence(0.8),
        reliability = Reliability(0.9),
        observability = Observability.PLATFORM_DIRECT,
        summary = "synthetic finding $id",
    )

    @Before
    fun setUp() {
        store = EvidenceStore(context)
        store.clear()
    }

    @After
    fun tearDown() {
        store.clear()
    }

    @Test
    fun recordsRoundTripThroughKeystoreEncryption() {
        assertTrue(store.append("com.example.subject", listOf(evidence("e1")), 1L))
        val all = store.readAll()
        assertEquals(1, all.size)
        assertEquals("com.example.subject", all.first().getString("subject"))
    }

    @Test
    fun plaintextIsNotPresentOnDisk() {
        store.append("com.example.subject", listOf(evidence("secret-marker-xyz")), 1L)
        val file = File(context.filesDir, "evidence/chain.log")
        val raw = file.readText()
        assertTrue(
            "evidence summary must not be stored in plaintext",
            !raw.contains("secret-marker-xyz"),
        )
    }

    @Test
    fun chainVerifiesAcrossMultipleRecords() {
        repeat(5) { store.append("pkg", listOf(evidence("e$it")), it.toLong()) }
        assertEquals(5, store.verifyChain())
    }

    /** Tamper evidence: modifying any record must break verification. */
    @Test
    fun modifiedRecordIsDetected() {
        repeat(3) { store.append("pkg", listOf(evidence("e$it")), it.toLong()) }
        val file = File(context.filesDir, "evidence/chain.log")
        val lines = file.readLines().toMutableList()
        lines[1] = lines[1].replace("\"ts\":1", "\"ts\":9999")
        file.writeText(lines.joinToString("\n") + "\n")

        assertEquals("tampering must be detected", -1, store.verifyChain())
        assertTrue(store.readAll().isEmpty())
    }

    /** Deleting a record from the middle must also be detected, thanks to MAC chaining. */
    @Test
    fun deletedRecordIsDetected() {
        repeat(4) { store.append("pkg", listOf(evidence("e$it")), it.toLong()) }
        val file = File(context.filesDir, "evidence/chain.log")
        val lines = file.readLines().filter { it.isNotBlank() }.toMutableList()
        lines.removeAt(1)
        file.writeText(lines.joinToString("\n") + "\n")

        assertEquals("record deletion must be detected", -1, store.verifyChain())
    }

    @Test
    fun emptyStoreVerifiesCleanly() {
        assertEquals(0, store.verifyChain())
        assertTrue(store.readAll().isEmpty())
    }
}
