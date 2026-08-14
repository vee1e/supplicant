"""Security graph: build a plain-dict graph and serialize to DOT / JSON.

Stdlib only. Depends on models (Artifact, Signal, severity_rank).
"""

from __future__ import annotations

import json

from .models import Artifact, Signal, severity_rank

SEVERITY_COLORS = {
    "ok": "green",
    "low": "yellow",
    "medium": "orange",
    "high": "red",
    "critical": "darkred",
}


def serialize_signal(signal: Signal) -> dict:
    """Flatten a Signal into a JSON-safe dict."""
    return {
        "id": signal.id,
        "kind": signal.kind,
        "artifact": signal.artifact.key if signal.artifact else None,
        "severity": signal.severity,
        "confidence": signal.confidence,
        "evidence": dict(signal.evidence),
        "reported_by": signal.reported_by,
        "explanation": signal.explanation,
    }


def build_graph(artifacts: list[Artifact], edges: list[tuple], signals: list[Signal]) -> dict:
    """Build a plain-dict security graph from artifacts, edges and signals.

    Node severity is the highest severity among signals attached to that
    artifact, or "ok" when the artifact has no signals.
    """
    by_artifact: dict[str, list[Signal]] = {}
    for s in signals:
        if s.artifact is not None:
            by_artifact.setdefault(s.artifact.key, []).append(s)

    nodes = []
    for a in artifacts:
        matched = by_artifact.get(a.key, [])
        severity = "ok"
        if matched:
            severity = max(matched, key=lambda s: severity_rank(s.severity)).severity
        nodes.append(
            {
                "key": a.key,
                "ecosystem": a.ecosystem,
                "name": a.name,
                "version": a.version,
                "severity": severity,
                "signals": len(matched),
            }
        )

    return {
        "nodes": nodes,
        "edges": [{"from": f.key, "to": t.key} for f, t in edges],
        "signals": [serialize_signal(s) for s in signals],
    }


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _dot_id(key: str) -> str:
    return f'"{_dot_escape(key)}"'


def to_dot(graph: dict) -> str:
    """Serialize a build_graph() dict to graphviz DOT."""
    lines = ["digraph supplicant {"]
    lines.append("  // security graph: nodes are versioned artifacts, edges are dependencies")
    lines.append("  // legend: ok=green  low=yellow  medium=orange  high=red  critical=darkred")
    for node in graph["nodes"]:
        color = SEVERITY_COLORS.get(node["severity"], "grey")
        label = f'{node["name"]}@{node["version"]}'
        lines.append(
            f'  {_dot_id(node["key"])} [label="{_dot_escape(label)}", '
            f'color="{color}", fontcolor="{color}", fillcolor="{color}", style="filled"];'
        )
    for edge in graph["edges"]:
        lines.append(f'  {_dot_id(edge["from"])} -> {_dot_id(edge["to"])};')
    lines.append("}")
    return "\n".join(lines)


def to_json(graph: dict) -> str:
    """Serialize a build_graph() dict to indented JSON."""
    return json.dumps(graph, indent=2)
