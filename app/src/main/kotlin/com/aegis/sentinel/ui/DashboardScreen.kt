package com.aegis.sentinel.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aegis.sentinel.core.model.AccessClass
import com.aegis.sentinel.core.model.Assessment
import com.aegis.sentinel.core.model.Capability
import com.aegis.sentinel.core.model.Verdict

/**
 * Diagnostics-first dashboard.
 *
 * The UI is deliberately explicit about the limits of what the app can see. A security tool that
 * overstates its coverage is itself a risk, so unavailable capabilities are shown, not hidden.
 */
@Composable
fun DashboardScreen(viewModel: DashboardViewModel, modifier: Modifier = Modifier) {
    val state by viewModel.state.collectAsStateWithLifecycle()

    LazyColumn(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { Spacer(Modifier.height(24.dp)) }

        item {
            Text(
                text = "Aegis Sentinel X",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = state.deviceSummary,
                style = MaterialTheme.typography.bodySmall,
            )
        }

        item {
            Card(Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Background monitoring", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Adaptive foreground service; backs off on low battery or memory.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Switch(
                        checked = state.monitoringEnabled,
                        onCheckedChange = { viewModel.setMonitoring(it) },
                    )
                }
            }
        }

        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Row(
                        Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Visible apps analysed: ${state.appsVisible}")
                        if (state.scanning) {
                            CircularProgressIndicator(Modifier.height(20.dp))
                        } else {
                            ElevatedButton(onClick = { viewModel.scan() }) { Text("Rescan") }
                        }
                    }
                    Text(
                        "Only apps with a launcher entry are visible. This app does not request " +
                            "QUERY_ALL_PACKAGES, so some packages are not analysable.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (!state.evidenceIntegrityOk) {
                        Text(
                            "Evidence integrity check FAILED — the evidence log was modified.",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                        )
                    }
                }
            }
        }

        item {
            Text("Findings", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        }

        val notable = state.assessments.filter { it.verdict != Verdict.UNKNOWN || it.score > 0.0 }
        if (notable.isEmpty()) {
            item {
                Text(
                    "No notable findings. Absence of findings is not proof of safety — see the " +
                        "capability panel below for what this device allows us to observe.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        } else {
            items(notable, key = { it.subject }) { AssessmentCard(it) }
        }

        item {
            HorizontalDivider()
            Text(
                "Capability transparency",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "What this build can and cannot observe on this specific device.",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        items(state.capabilities, key = { it.id }) { CapabilityRow(it) }

        item { Spacer(Modifier.height(48.dp)) }
    }
}

@Composable
private fun AssessmentCard(a: Assessment) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(a.subject, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace)
            Text(
                "${a.verdict}  ·  score ${"%.2f".format(a.score)}  ·  confidence ${"%.2f".format(a.confidence)}",
                style = MaterialTheme.typography.bodyMedium,
                color = when (a.verdict) {
                    Verdict.LIKELY_MALICIOUS -> MaterialTheme.colorScheme.error
                    Verdict.SUSPICIOUS -> MaterialTheme.colorScheme.tertiary
                    else -> MaterialTheme.colorScheme.onSurface
                },
            )
            Spacer(Modifier.height(6.dp))
            a.supporting.take(4).forEach {
                Text("• ${it.summary}", style = MaterialTheme.typography.bodySmall)
            }
            if (a.contradictions.isNotEmpty()) {
                Spacer(Modifier.height(6.dp))
                Text("Evidence against:", style = MaterialTheme.typography.labelSmall)
                a.contradictions.take(3).forEach {
                    Text("• ${it.summary}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun CapabilityRow(c: Capability) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    c.description,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    if (c.productionEnabled) "ACTIVE" else "OFF",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (c.productionEnabled) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.outline
                    },
                )
            }
            Text(
                accessLabel(c.accessClass),
                style = MaterialTheme.typography.labelSmall,
            )
            if (c.notes.isNotBlank()) {
                Text(c.notes, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private fun accessLabel(a: AccessClass): String = when (a) {
    AccessClass.NORMAL_APP -> "Standard app capability"
    AccessClass.USER_PERMISSION -> "Requires a runtime permission"
    AccessClass.SPECIAL_ACCESS -> "Requires special access in Settings"
    AccessClass.DEVICE_OWNER -> "Requires device owner — not available to this app"
    AccessClass.SYSTEM_OEM -> "Requires system/OEM privilege — not available"
    AccessClass.ROOT_ONLY -> "Requires root — out of scope"
    AccessClass.UNAVAILABLE -> "Not possible on this Android version"
    AccessClass.UNKNOWN -> "Unverified — disabled in production"
}
