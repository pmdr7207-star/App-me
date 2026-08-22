package com.aegis.sentinel.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.model.Assessment
import com.aegis.sentinel.core.model.Capability
import com.aegis.sentinel.platform.AegisRuntime
import com.aegis.sentinel.platform.capability.CapabilityDiscovery
import com.aegis.sentinel.platform.prefs.AegisPreferences
import com.aegis.sentinel.platform.service.AegisMonitorService
import com.aegis.sentinel.platform.telemetry.AppInventory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class DashboardState(
    val scanning: Boolean = false,
    val monitoringEnabled: Boolean = false,
    val appsVisible: Int = 0,
    val assessments: List<Assessment> = emptyList(),
    val capabilities: List<Capability> = emptyList(),
    val deviceSummary: String = "",
    val lastScanAt: Long? = null,
    val evidenceIntegrityOk: Boolean = true,
)

class DashboardViewModel(app: Application) : AndroidViewModel(app) {

    private val runtime: AegisRuntime = AegisRuntime.create(app)
    private val prefs = AegisPreferences(app)

    private val _state = MutableStateFlow(
        DashboardState(
            monitoringEnabled = prefs.monitoringEnabled,
            capabilities = runtime.capabilities.all,
            deviceSummary = runtime.deviceProfile.let {
                "${it.manufacturer} ${it.model} · Android API ${it.sdkInt} · " +
                    "${it.cpuCores} cores · ${it.totalRamMb} MB RAM"
            },
        )
    )
    val state: StateFlow<DashboardState> = _state.asStateFlow()

    init {
        scan()
    }

    fun scan() {
        if (_state.value.scanning) return
        _state.value = _state.value.copy(scanning = true)

        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                val now = System.currentTimeMillis()
                val inventory = AppInventory(getApplication())
                val records = inventory.enumerate()

                records.forEach { record ->
                    inventory.analyze(record, now).forEach { evidence ->
                        runtime.pipeline.threatGraph().ingestEvidence(evidence)
                        runtime.evidenceStore.append(record.packageName, listOf(evidence), now)
                    }
                }

                // Assess every package we produced evidence for, plus fuse pipeline evidence.
                val assessments = records.mapNotNull { record ->
                    val evidence = inventory.analyze(record, now) +
                        runtime.pipeline.evidenceFor(record.packageName)
                    if (evidence.isEmpty()) {
                        null
                    } else {
                        runtime.pipeline.assess(record.packageName, now)
                            .takeIf { it.supporting.isNotEmpty() || it.contradictions.isNotEmpty() }
                            ?: fuseDirect(record.packageName, evidence, now)
                    }
                }.sortedByDescending { it.score }

                Triple(records.size, assessments, runtime.evidenceStore.verifyChain() >= 0)
            }

            _state.value = _state.value.copy(
                scanning = false,
                appsVisible = result.first,
                assessments = result.second,
                lastScanAt = System.currentTimeMillis(),
                evidenceIntegrityOk = result.third,
                capabilities = runtime.capabilities.all,
            )
        }
    }

    private fun fuseDirect(
        subject: String,
        evidence: List<com.aegis.sentinel.core.model.Evidence>,
        now: Long,
    ): Assessment = com.aegis.sentinel.core.fusion.EvidenceFusion().assess(subject, evidence, now)

    fun setMonitoring(enabled: Boolean) {
        prefs.monitoringEnabled = enabled
        val app = getApplication<Application>()
        if (enabled) AegisMonitorService.start(app) else AegisMonitorService.stop(app)
        _state.value = _state.value.copy(monitoringEnabled = enabled)
    }

    /** Capabilities the user could still unlock, for the honest "what I cannot see" panel. */
    fun unavailableCapabilities(): List<Capability> =
        runtime.capabilities.all.filter { !it.productionEnabled }

    fun usageAccessGranted(): Boolean =
        CapabilityDiscovery.hasUsageStatsAccess(getApplication())

    fun blockedByPrivilege(): List<Capability> =
        runtime.capabilities.all.filter {
            !it.productionEnabled &&
                (it.accessClass == AccessClass.DEVICE_OWNER ||
                    it.accessClass == AccessClass.SYSTEM_OEM ||
                    it.accessClass == AccessClass.ROOT_ONLY)
        }
}
