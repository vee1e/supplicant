"""Renderers: human text, JSON, and focused version-diff output.

Stdlib only. Depends on models and graph. diff/engine is intentionally NOT
imported at module load (it may not exist yet); nothing here needs it.
"""

from __future__ import annotations

import json
from typing import Any

from ..graph import serialize_signal
from ..models import DiffOutcome, ScanReport, severity_rank
from .. import __version__ as _supplicant_version

RESET = "\033[0m"

ANSI = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[0m",
    "ok": "\033[32m",
}

VERDICT_TEXT = {
    "ok": "take the bump",
    "review": "review before merging",
    "block": "DO NOT TAKE THIS BUMP",
}

_VERDICT_COLOR = {"ok": "ok", "review": "medium", "block": "critical"}

_DIFF_EVIDENCE_PAD = "│" + " " * 12


def colorize(text: str, severity: str, enabled: bool = True) -> str:
    """Wrap text in an ANSI color code for the given severity."""
    if not enabled:
        return text
    code = ANSI.get(severity, ANSI["info"])
    return f"{code}{text}{RESET}"


def _verdict_color(verdict: str) -> str:
    return _VERDICT_COLOR.get(verdict, "info")


def _signal_lines_at_or_above(signals: list, min_severity: str) -> list:
    floor = severity_rank(min_severity)
    return [s for s in signals if severity_rank(s.severity) >= floor]


def _render_dependency_tree(report: ScanReport) -> list[str]:
    key_to_artifact = {a.key: a for a in report.artifacts}
    children: dict[str, list[str]] = {}
    child_keys: set[str] = set()
    for parent, child in report.edges:
        children.setdefault(parent.key, []).append(child.key)
        child_keys.add(child.key)

    def label(key: str) -> str:
        a = key_to_artifact.get(key)
        return str(a) if a is not None else key

    if not report.edges:
        return [f"  {str(a)}" for a in report.artifacts] or ["  (none)"]

    roots = [a.key for a in report.artifacts if a.key not in child_keys]
    if not roots:
        roots = [a.key for a in report.artifacts]

    lines: list[str] = []
    seen: set[str] = set()

    def draw(node: str, prefix: str, is_root: bool) -> None:
        if node in seen:
            return
        seen.add(node)
        if is_root:
            lines.append(label(node))
        kids = children.get(node, [])
        for i, kid in enumerate(kids):
            last = i == len(kids) - 1
            branch = "└─ " if last else "├─ "
            lines.append(f"{prefix}{branch}{label(kid)}")
            draw(kid, prefix + ("   " if last else "│  "), is_root=False)

    for root in roots:
        draw(root, "", True)

    return lines or ["  (none)"]


def _render_signal_lines(signals: list, min_severity: str, color: bool) -> list[str]:
    filtered = _signal_lines_at_or_above(signals, min_severity)
    if not filtered:
        return [f"  (none at or above {min_severity})"]

    by_artifact: dict[str, list] = {}
    for s in filtered:
        by_artifact.setdefault(s.artifact.key if s.artifact else "", []).append(s)

    lines: list[str] = []
    for key in sorted(by_artifact):
        group = sorted(by_artifact[key], key=lambda s: -severity_rank(s.severity))
        for s in group:
            sev_label = f"[{colorize(s.severity.upper(), s.severity, color)}]"
            line = f"  {sev_label} {s.kind}"
            if s.artifact is not None:
                line += f"  {str(s.artifact)}"
            line += f"  - {s.explanation}"
            lines.append(line)
            file = s.evidence.get("file")
            if file:
                loc = f"{file}:{s.evidence['line']}" if s.evidence.get("line") is not None else str(file)
                lines.append(f"    evidence: {loc}")
        lines.append("")
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def _size_note(change: Any) -> str:
    before = change.size_before if change.size_before is not None else 0
    after = change.size_after if change.size_after is not None else 0
    if change.status == "added":
        return f"(+{after} B)" if after else ""
    if change.status == "removed":
        return f"(-{before} B)" if before else ""
    delta = after - before
    if delta == 0:
        return ""
    sign = "+" if delta > 0 else "-"
    return f"({sign}{abs(delta)} B)"


def _render_diff_block(outcome: DiffOutcome, min_severity: str, color: bool) -> list[str]:
    lines = [f"diff {outcome.artifact.name} {outcome.from_version} -> {outcome.to_version}"]
    if outcome.diff:
        for change in outcome.diff.changes:
            line = f"  {change.status}: {change.path}"
            note = _size_note(change)
            if note:
                line += f" {note}"
            lines.append(line)
    lines.extend(_render_signal_lines(outcome.signals, min_severity, color))
    verdict = outcome.verdict.upper()
    lines.append(f"  {colorize('verdict: ' + verdict, _verdict_color(outcome.verdict), color)}")
    return lines


def render_text(report: ScanReport, min_severity: str = "info", color: bool = True) -> str:
    """Full human-readable scan report (header, tree, signals, diffs, fingerprints, errors)."""
    shown = _signal_lines_at_or_above(report.signals, min_severity)
    n_high = sum(1 for s in shown if s.severity == "high")
    n_crit = sum(1 for s in shown if s.severity == "critical")
    parts = [
        f"supplicant scan - {len(report.artifacts)} artifacts, "
        f"{len(shown)} signals at/above {min_severity} ({n_high} high, {n_crit} critical)",
        "",
        "Dependency tree",
        "──────────────",
    ]
    parts.extend(_render_dependency_tree(report))

    parts.extend(["", "Signals", "───────"])
    parts.extend(_render_signal_lines(report.signals, min_severity, color))

    if report.diffs:
        parts.extend(["", "Diffs", "─────"])
        for d in report.diffs:
            parts.extend(_render_diff_block(d, min_severity, color))
            parts.append("")

    shared = {fp: keys for fp, keys in report.fingerprints.items() if len(keys) >= 2}
    if shared:
        parts.extend(["", "Fingerprints", "────────────"])
        for fp_id in sorted(shared):
            keys = shared[fp_id]
            parts.append(f"  {fp_id}: {len(keys)} packages ({', '.join(keys)})")

    if report.errors:
        parts.extend(["", "Errors", "──────"])
        for err in report.errors:
            parts.append(f"  - {err}")

    return "\n".join(parts)


def _group_signals_by_severity(signals: list, min_severity: str = "info") -> list[dict]:
    floor = severity_rank(min_severity)
    groups = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        if severity_rank(sev) < floor:
            continue
        picked = [s for s in signals if s.severity == sev]
        if picked:
            groups.append({"severity": sev, "signals": picked})
    return groups


def _diff_evidence(signal: Any) -> str:
    file = signal.evidence.get("file")
    if not file:
        return ""
    loc = f"{file}:{signal.evidence['line']}" if signal.evidence.get("line") is not None else str(file)
    return f"evidence: file={loc}"


def _verdict_from(signals: list) -> str:
    """Verdict computed from a signal set (mirrors pipeline._verdict)."""
    has = {s.severity for s in signals}
    if "critical" in has:
        return "block"
    if any(sev in has for sev in ("medium", "high")):
        return "review"
    return "ok"


def render_diff_text(outcome: DiffOutcome, min_severity: str = "info", color: bool = True) -> str:
    """Focused version-diff output for the `diff` command (SPEC §5.1 style)."""
    lines = [f" {outcome.artifact.name} {outcome.from_version} → {outcome.to_version}"]

    added = outcome.diff.added if outcome.diff else []
    modified = outcome.diff.modified if outcome.diff else []
    removed = outcome.diff.removed if outcome.diff else []
    counts = [len(added), len(modified), len(removed)]
    width = len(str(max(counts))) if counts else 1

    for status, items in (("added", added), ("modified", modified), ("removed", removed)):
        line = f"├─ files {status}: {len(items):>{width + 2}}"
        if items:
            line += f"   ({', '.join(c.path for c in items)})"
        lines.append(line)

    if outcome.diff and outcome.diff.delta_fingerprint:
        lines.extend(["│", f"├─ fingerprint: {outcome.diff.delta_fingerprint}"])

    floor = severity_rank(min_severity)
    shown_signals = [s for s in outcome.signals if severity_rank(s.severity) >= floor]
    groups = _group_signals_by_severity(outcome.signals, min_severity)
    if groups:
        lines.append("│")
    for group in groups:
        sev = group["severity"]
        signals = group["signals"]
        for s in signals[:15]:
            sev_label = colorize(sev.upper(), sev, color)
            lines.append(f"├─ {sev_label}  {s.kind}  - {s.explanation}")
            ev = _diff_evidence(s)
            if ev:
                lines.append(f"{_DIFF_EVIDENCE_PAD}{ev}")
        if len(signals) > 15:
            lines.append(f"├─ ... {len(signals) - 15} more {sev} signals")
        lines.append("│")

    verdict = _verdict_from(shown_signals)
    text = VERDICT_TEXT.get(verdict, verdict)
    lines.append(f"└─ verdict: {colorize(text, _verdict_color(verdict), color)} ({verdict})")

    return "\n".join(lines)


def _diff_payload(outcome: DiffOutcome) -> dict:
    diff = outcome.diff
    return {
        "artifact": outcome.artifact.name,
        "from": outcome.from_version,
        "to": outcome.to_version,
        "added": [c.path for c in diff.added] if diff else [],
        "removed": [c.path for c in diff.removed] if diff else [],
        "modified": [c.path for c in diff.modified] if diff else [],
        "delta_fingerprint": diff.delta_fingerprint if diff else None,
        "signals": [serialize_signal(s) for s in outcome.signals],
        "verdict": outcome.verdict,
    }


def render_json(report: ScanReport) -> str:
    """Full report as indented JSON."""
    payload = {
        "artifacts": [a.key for a in report.artifacts],
        "edges": [[parent.key, child.key] for parent, child in report.edges],
        "signals": [serialize_signal(s) for s in report.signals],
        "diffs": [_diff_payload(d) for d in report.diffs],
        "fingerprints": dict(report.fingerprints),
        "errors": list(report.errors),
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_RULE_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "supplicant"
TOOL_INFORMATION_URI = "https://github.com/vee1e/supplicant"


def _sarif_rule(kind: str) -> dict:
    """One reportingDescriptor per detector kind. SARIF dedupes results by ruleId."""
    return {
        "id": kind,
        "name": kind,
        "shortDescription": {"text": kind.replace("_", " ")},
        "defaultConfiguration": {"level": "warning"},
    }


def _sarif_result(signal) -> dict:
    """Map a Signal to a SARIF result. One result per signal."""
    rule = {"id": signal.kind}
    props = {
        "severity": signal.severity,
        "confidence": signal.confidence,
        "reportedBy": signal.reported_by,
        "signalId": signal.id,
    }
    if signal.artifact is not None:
        props["artifact"] = signal.artifact.key

    result = {
        "ruleId": signal.kind,
        "rule": rule,
        "level": _SARIF_LEVEL.get(signal.severity, "warning"),
        "message": {"text": signal.explanation or signal.kind},
        "properties": props,
    }

    file = signal.evidence.get("file") if signal.evidence else None
    if file:
        location = {
            "physicalLocation": {
                "artifactLocation": {"uri": file, "uriBaseId": "%SRCROOT%"},
            }
        }
        line = signal.evidence.get("line") if signal.evidence else None
        if isinstance(line, int) and line > 0:
            location["physicalLocation"]["region"] = {"startLine": line}
        result["locations"] = [location]

    return result


def render_sarif(report: ScanReport) -> str:
    """SARIF 2.1.0 report. One result per Signal, rules deduped by detector kind."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for signal in report.signals:
        rules.setdefault(signal.kind, _sarif_rule(signal.kind))
        results.append(_sarif_result(signal))

    for outcome in report.diffs:
        for signal in outcome.signals:
            rules.setdefault(signal.kind, _sarif_rule(signal.kind))
            results.append(_sarif_result(signal))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": _supplicant_version,
                        "rules": sorted(rules.values(), key=lambda r: r["id"]),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)
