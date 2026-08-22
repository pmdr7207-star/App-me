package com.aegis.sentinel.platform.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.aegis.sentinel.core.model.Event
import com.aegis.sentinel.core.model.EventType
import com.aegis.sentinel.core.model.Observability
import com.aegis.sentinel.platform.AegisRuntime
import com.aegis.sentinel.platform.net.PacketMetadataParser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicLong

/**
 * Local-sink VpnService used purely for on-device flow observation.
 *
 * WHAT THIS DOES: establishes a TUN interface, reads outbound IP packets, and extracts *metadata*
 * only — protocol, destination address/port, packet size and timing — which feed the network
 * behaviour detector.
 *
 * WHAT THIS EXPLICITLY DOES NOT DO, because it is not possible for a non-root app and we will not
 * pretend otherwise:
 *   - decrypt TLS, or inspect any HTTPS payload
 *   - bypass certificate pinning
 *   - read the contents of QUIC or DNS-over-HTTPS/TLS traffic
 *   - observe traffic of other VPN apps, or inbound connections
 *   - forward traffic anywhere: packets are read and dropped locally, nothing leaves the device
 *
 * Because packets are not forwarded, enabling this interface interrupts connectivity for the
 * captured scope. The service therefore runs only while the user explicitly enables observation,
 * and it defaults to a narrow allow-list rather than the whole device.
 */
class AegisVpnService : VpnService() {

    private var tunnel: ParcelFileDescriptor? = null
    private var observedPackage: String? = null
    private var scope: CoroutineScope? = null
    private val packetsObserved = AtomicLong(0)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> establish(intent?.getStringArrayExtra(EXTRA_PACKAGES)?.toList().orEmpty())
        }
        return START_STICKY
    }

    private fun establish(observedPackages: List<String>) {
        if (tunnel != null) return

        val builder = Builder()
            .setSession(SESSION_NAME)
            .addAddress(LOCAL_ADDRESS, LOCAL_PREFIX)
            .addRoute(ROUTE_ADDRESS, ROUTE_PREFIX)
            .setBlocking(true)
            .setMtu(MTU)

        // Narrow scope by default. An empty list means the user has not chosen any app, in which
        // case we do not capture at all rather than silently capturing everything.
        if (observedPackages.isEmpty()) {
            stopSelf()
            return
        }
        val allowed = observedPackages.filter { pkg ->
            runCatching { builder.addAllowedApplication(pkg); true }.getOrDefault(false)
        }
        if (allowed.isEmpty()) {
            // Every requested package was rejected by the system; do not pretend to observe.
            stopSelf()
            return
        }
        // Attribution is only sound when exactly one app is in scope. With several allowed apps
        // the tunnel cannot tell them apart, so we record the flow without a package rather than
        // guessing.
        observedPackage = allowed.singleOrNull()

        // Never route our own traffic through the tunnel.
        runCatching { builder.addDisallowedApplication(packageName) }

        val fd = runCatching { builder.establish() }.getOrNull()
        if (fd == null) {
            // Consent missing or the system refused: stop honestly instead of appearing active.
            stopSelf()
            return
        }
        tunnel = fd

        val job = SupervisorJob()
        val newScope = CoroutineScope(Dispatchers.IO + job)
        scope = newScope
        newScope.launch { readLoop(fd, job) }
    }

    private suspend fun readLoop(fd: ParcelFileDescriptor, job: Job) {
        val runtime = AegisRuntime.get()
        val buffer = ByteArray(MTU)
        FileInputStream(fd.fileDescriptor).use { input ->
            while (job.isActive) {
                val length = runCatching { input.read(buffer) }.getOrDefault(-1)
                if (length <= 0) break

                val meta = PacketMetadataParser.parse(buffer, length) ?: continue
                packetsObserved.incrementAndGet()

                runtime?.pipeline?.ingest(
                    Event(
                        id = "vpn-${packetsObserved.get()}",
                        type = EventType.NETWORK_FLOW,
                        timestamp = System.currentTimeMillis(),
                        // Per-app attribution is only reliable because we restricted the tunnel to
                        // an explicit allow-list above.
                        packageName = observedPackage,
                        observability = Observability.PLATFORM_DIRECT,
                        attributes = mapOf(
                            "endpoint" to "${meta.destinationAddress}:${meta.destinationPort}",
                            "protocol" to meta.protocolName,
                        ),
                        numeric = mapOf("bytes_out" to length.toDouble()),
                    )
                )
            }
        }
    }

    override fun onRevoke() {
        teardown()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }

    private fun teardown() {
        scope?.cancel()
        scope = null
        runCatching { tunnel?.close() }
        tunnel = null
    }

    companion object {
        private const val SESSION_NAME = "Aegis Flow Observation"
        private const val LOCAL_ADDRESS = "10.111.222.1"
        private const val LOCAL_PREFIX = 32
        private const val ROUTE_ADDRESS = "0.0.0.0"
        private const val ROUTE_PREFIX = 0
        private const val MTU = 1500

        const val ACTION_STOP = "com.aegis.sentinel.VPN_STOP"
        const val EXTRA_PACKAGES = "packages"

        /**
         * Returns the consent intent that must be shown to the user, or null when consent already
         * exists. Callers must never start the service without handling this.
         */
        fun consentIntent(context: Context): Intent? = prepare(context)

        fun start(context: Context, packages: List<String>) {
            val intent = Intent(context, AegisVpnService::class.java)
                .putExtra(EXTRA_PACKAGES, packages.toTypedArray())
            context.startService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, AegisVpnService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}
