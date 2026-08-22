package com.aegis.sentinel.platform.evidence

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.aegis.sentinel.core.model.Evidence
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Integrity-protected, encrypted evidence storage.
 *
 * Design:
 *  - Records are stored in app-private storage, which other apps cannot read on a non-rooted
 *    device (this is the honest limit: root defeats it, and we say so in the docs).
 *  - Confidentiality: AES-256-GCM with a key held in the Android Keystore, so the key material is
 *    never exposed to the app process and cannot be extracted by copying files.
 *  - Integrity/tamper evidence: every record carries an HMAC chained to the previous record's MAC,
 *    so deleting or reordering records is detectable, not just modifying one.
 *
 * GCM already authenticates each record; the chained HMAC additionally protects the *sequence*.
 */
class EvidenceStore(context: Context) {

    private val dir = File(context.filesDir, "evidence").apply { mkdirs() }
    private val chainFile = File(dir, "chain.log")

    /** Encrypt and append an incident record, chaining its MAC to the previous entry. */
    fun append(subject: String, evidence: List<Evidence>, timestamp: Long): Boolean = runCatching {
        val payload = toJson(subject, evidence, timestamp).toString().toByteArray()

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(payload)

        val previousMac = lastMac()
        val mac = chainMac(previousMac, iv, ciphertext)

        val record = JSONObject().apply {
            put("ts", timestamp)
            put("iv", android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
            put("ct", android.util.Base64.encodeToString(ciphertext, android.util.Base64.NO_WRAP))
            put("mac", android.util.Base64.encodeToString(mac, android.util.Base64.NO_WRAP))
        }
        chainFile.appendText(record.toString() + "\n")
        true
    }.getOrDefault(false)

    /**
     * Verify the whole chain.
     * @return the number of valid records, or -1 when tampering is detected.
     */
    fun verifyChain(): Int {
        if (!chainFile.exists()) return 0
        var previousMac = ByteArray(0)
        var count = 0
        chainFile.forEachLine { line ->
            if (line.isBlank()) return@forEachLine
            val o = runCatching { JSONObject(line) }.getOrNull() ?: return -1
            val iv = decode(o.optString("iv"))
            val ct = decode(o.optString("ct"))
            val mac = decode(o.optString("mac"))
            val expected = runCatching { chainMac(previousMac, iv, ct) }.getOrNull() ?: return -1
            if (!expected.contentEquals(mac)) return -1
            previousMac = mac
            count++
        }
        return count
    }

    /** Decrypt all stored records. Returns an empty list when the chain fails verification. */
    fun readAll(): List<JSONObject> {
        if (verifyChain() < 0) return emptyList()
        if (!chainFile.exists()) return emptyList()
        val out = mutableListOf<JSONObject>()
        chainFile.forEachLine { line ->
            if (line.isBlank()) return@forEachLine
            runCatching {
                val o = JSONObject(line)
                val iv = decode(o.getString("iv"))
                val ct = decode(o.getString("ct"))
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, encryptionKey(), GCMParameterSpec(TAG_BITS, iv))
                out += JSONObject(String(cipher.doFinal(ct)))
            }
        }
        return out
    }

    fun recordCount(): Int = if (chainFile.exists()) {
        chainFile.readLines().count { it.isNotBlank() }
    } else {
        0
    }

    fun clear() {
        chainFile.delete()
    }

    private fun lastMac(): ByteArray {
        if (!chainFile.exists()) return ByteArray(0)
        val last = chainFile.readLines().lastOrNull { it.isNotBlank() } ?: return ByteArray(0)
        return runCatching { decode(JSONObject(last).getString("mac")) }.getOrDefault(ByteArray(0))
    }

    private fun chainMac(previousMac: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val mac = Mac.getInstance(MAC_ALGORITHM)
        mac.init(macKey())
        mac.update(previousMac)
        mac.update(iv)
        mac.update(ciphertext)
        return mac.doFinal()
    }

    private fun decode(s: String): ByteArray =
        android.util.Base64.decode(s, android.util.Base64.NO_WRAP)

    private fun toJson(subject: String, evidence: List<Evidence>, timestamp: Long): JSONObject {
        val arr = JSONArray()
        evidence.forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("id", e.id)
                    put("detector", e.detector)
                    put("package", e.packageName ?: JSONObject.NULL)
                    put("timestamp", e.timestamp)
                    put("severity", e.severity.name)
                    put("confidence", e.confidence.value)
                    put("reliability", e.reliability.value)
                    put("observability", e.observability.name)
                    put("supports_malicious", e.supportsMalicious)
                    put("summary", e.summary)
                    put("source_events", JSONArray(e.sourceEventIds))
                }
            )
        }
        return JSONObject().apply {
            put("subject", subject)
            put("captured_at", timestamp)
            put("evidence", arr)
        }
    }

    private fun encryptionKey(): SecretKey = getOrCreateKey(KEY_ALIAS_ENC) { spec ->
        spec.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
    }

    private fun macKey(): SecretKey = getOrCreateKey(KEY_ALIAS_MAC, KeyProperties.KEY_ALGORITHM_HMAC_SHA256) { it }

    private fun getOrCreateKey(
        alias: String,
        algorithm: String = KeyProperties.KEY_ALGORITHM_AES,
        configure: (KeyGenParameterSpec.Builder) -> KeyGenParameterSpec.Builder,
    ): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val purposes = if (algorithm == KeyProperties.KEY_ALGORITHM_AES) {
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        } else {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        }
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
        val spec = configure(builder).build()

        val generator = KeyGenerator.getInstance(algorithm, ANDROID_KEYSTORE)
        generator.init(spec)
        return generator.generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS_ENC = "aegis.evidence.enc.v1"
        const val KEY_ALIAS_MAC = "aegis.evidence.mac.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val MAC_ALGORITHM = "HmacSHA256"
        const val TAG_BITS = 128
    }
}
