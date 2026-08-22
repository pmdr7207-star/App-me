package com.aegis.sentinel.core.graph

import com.aegis.sentinel.core.model.EpochMillis
import com.aegis.sentinel.core.model.Evidence
import com.aegis.sentinel.core.model.Severity

/**
 * Bounded threat graph relating the entities an incident is made of.
 *
 * The graph exists to answer the incident-timeline questions: what happened, when, which app was
 * responsible, on what evidence, and what argues against the conclusion.
 */
class ThreatGraph(private val maxNodes: Int = 5000, private val maxEdges: Int = 20000) {

    enum class NodeType { APP, PACKAGE, PERMISSION, COMPONENT, DOMAIN, IP, FILE, EVENT, INCIDENT }

    data class Node(
        val id: String,
        val type: NodeType,
        val label: String,
        val firstSeen: EpochMillis,
        var lastSeen: EpochMillis,
        val attributes: MutableMap<String, String> = mutableMapOf(),
    )

    data class Edge(
        val from: String,
        val to: String,
        val relation: String,
        val timestamp: EpochMillis,
        val evidenceId: String? = null,
    )

    private val nodes = LinkedHashMap<String, Node>()
    private val edges = ArrayList<Edge>()
    private val adjacency = HashMap<String, MutableList<Int>>()

    val nodeCount: Int get() = nodes.size
    val edgeCount: Int get() = edges.size

    fun upsertNode(
        id: String,
        type: NodeType,
        label: String,
        now: EpochMillis,
        attributes: Map<String, String> = emptyMap(),
    ): Node {
        val existing = nodes[id]
        if (existing != null) {
            existing.lastSeen = now
            existing.attributes.putAll(attributes)
            return existing
        }
        evictNodesIfNeeded()
        val n = Node(id, type, label, now, now, attributes.toMutableMap())
        nodes[id] = n
        return n
    }

    fun addEdge(
        from: String,
        to: String,
        relation: String,
        now: EpochMillis,
        evidenceId: String? = null,
    ) {
        if (!nodes.containsKey(from) || !nodes.containsKey(to)) return
        if (edges.size >= maxEdges) {
            // Drop the oldest edge and rebuild adjacency lazily.
            edges.removeAt(0)
            rebuildAdjacency()
        }
        edges.add(Edge(from, to, relation, now, evidenceId))
        adjacency.getOrPut(from) { mutableListOf() }.add(edges.size - 1)
        adjacency.getOrPut(to) { mutableListOf() }.add(edges.size - 1)
    }

    fun node(id: String): Node? = nodes[id]

    fun nodes(): List<Node> = nodes.values.toList()

    fun edges(): List<Edge> = edges.toList()

    fun neighbors(id: String): List<Node> =
        adjacency[id].orEmpty()
            .mapNotNull { edges.getOrNull(it) }
            .flatMap { listOf(it.from, it.to) }
            .filter { it != id }
            .distinct()
            .mapNotNull { nodes[it] }

    /** Index an evidence item into the graph, wiring the entities it mentions. */
    fun ingestEvidence(e: Evidence) {
        val evidenceNodeId = "evidence:${e.id}"
        upsertNode(evidenceNodeId, NodeType.EVENT, e.summary, e.timestamp, mapOf(
            "detector" to e.detector,
            "severity" to e.severity.name,
        ))
        e.packageName?.let { pkg ->
            val pkgId = "package:$pkg"
            upsertNode(pkgId, NodeType.PACKAGE, pkg, e.timestamp)
            addEdge(pkgId, evidenceNodeId, "produced", e.timestamp, e.id)
        }
        e.attributes["endpoint"]?.let { ep ->
            val id = "endpoint:$ep"
            upsertNode(id, NodeType.IP, ep, e.timestamp)
            addEdge(evidenceNodeId, id, "contacted", e.timestamp, e.id)
        }
        e.attributes["hostname"]?.let { h ->
            val id = "domain:$h"
            upsertNode(id, NodeType.DOMAIN, h, e.timestamp)
            addEdge(evidenceNodeId, id, "resolved", e.timestamp, e.id)
        }
    }

    private fun evictNodesIfNeeded() {
        if (nodes.size < maxNodes) return
        val victims = nodes.values.sortedBy { it.lastSeen }.take(nodes.size - maxNodes + 1)
        for (v in victims) {
            nodes.remove(v.id)
            adjacency.remove(v.id)
        }
        edges.removeAll { it.from !in nodes || it.to !in nodes }
        rebuildAdjacency()
    }

    private fun rebuildAdjacency() {
        adjacency.clear()
        edges.forEachIndexed { i, e ->
            adjacency.getOrPut(e.from) { mutableListOf() }.add(i)
            adjacency.getOrPut(e.to) { mutableListOf() }.add(i)
        }
    }
}

/** An incident: a correlated, time-ordered story with its supporting and opposing evidence. */
data class Incident(
    val id: String,
    val subject: String,
    val title: String,
    val openedAt: EpochMillis,
    val lastUpdatedAt: EpochMillis,
    val severity: Severity,
    val timeline: List<TimelineEntry>,
    val supporting: List<Evidence>,
    val contradictions: List<Evidence>,
    val status: IncidentStatus = IncidentStatus.OPEN,
)

enum class IncidentStatus { OPEN, CONTAINED, RESOLVED, DISMISSED }

data class TimelineEntry(
    val timestamp: EpochMillis,
    val actor: String?,
    val what: String,
    val evidenceIds: List<String>,
)

/** Builds incidents from evidence, preserving ordering and contradictions. */
object IncidentBuilder {
    fun build(
        id: String,
        subject: String,
        title: String,
        evidence: List<Evidence>,
        now: EpochMillis,
    ): Incident {
        val supporting = evidence.filter { it.supportsMalicious }
        val contradicting = evidence.filterNot { it.supportsMalicious }
        val timeline = evidence.sortedBy { it.timestamp }.map {
            TimelineEntry(
                timestamp = it.timestamp,
                actor = it.packageName,
                what = it.summary,
                evidenceIds = listOf(it.id),
            )
        }
        val severity = supporting.maxOfOrNull { it.severity } ?: Severity.INFO
        return Incident(
            id = id,
            subject = subject,
            title = title,
            openedAt = evidence.minOfOrNull { it.timestamp } ?: now,
            lastUpdatedAt = now,
            severity = severity,
            timeline = timeline,
            supporting = supporting,
            contradictions = contradicting,
        )
    }
}
