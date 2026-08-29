"""Tests for the SARIF 2.1.0 renderer."""

from __future__ import annotations

import json

from supplicant.models import Artifact, DiffOutcome, ScanReport, Signal
from supplicant.report.render import render_sarif


def _signal(kind, severity, artifact=None, file=None, line=None, explanation="x"):
    evidence = {}
    if file is not None:
        evidence["file"] = file
    if line is not None:
        evidence["line"] = line
    return Signal(
        kind=kind,
        artifact=artifact,
        severity=severity,
        confidence=0.9,
        evidence=evidence,
        explanation=explanation,
    )


def test_sarif_envelope():
    report = ScanReport(artifacts=[Artifact("npm", "x", "1.0.0")])
    out = json.loads(render_sarif(report))
    assert out["version"] == "2.1.0"
    assert out["$schema"].endswith("sarif-2.1.0.json")
    run = out["runs"][0]
    assert run["tool"]["driver"]["name"] == "supplicant"
    assert run["tool"]["driver"]["informationUri"].startswith("https://")
    assert run["results"] == []


def test_sarif_maps_signal_to_result_with_rule_and_location():
    art = Artifact("npm", "keyv", "6.0.0")
    sig = _signal(
        "install_script_network",
        "high",
        artifact=art,
        file="setup.mjs",
        line=3,
        explanation="curl | sh in install hook",
    )
    report = ScanReport(artifacts=[art], signals=[sig])
    out = json.loads(render_sarif(report))
    result = out["runs"][0]["results"][0]
    assert result["ruleId"] == "install_script_network"
    assert result["level"] == "error"
    assert result["message"]["text"] == "curl | sh in install hook"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "setup.mjs"
    assert loc["region"]["startLine"] == 3
    rule = out["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "install_script_network"


def test_sarif_dedupes_rules_by_kind():
    art = Artifact("npm", "x", "1.0.0")
    sigs = [
        _signal("obfuscation", "low", artifact=art, file="a.js"),
        _signal("obfuscation", "low", artifact=art, file="b.js"),
        _signal("native_binary", "medium", artifact=art, file="lib.so"),
    ]
    report = ScanReport(artifacts=[art], signals=sigs)
    out = json.loads(render_sarif(report))
    rules = out["runs"][0]["tool"]["driver"]["rules"]
    assert {r["id"] for r in rules} == {"obfuscation", "native_binary"}
    assert len(out["runs"][0]["results"]) == 3


def test_sarif_severity_to_level_mapping():
    art = Artifact("npm", "x", "1.0.0")
    sigs = [
        _signal("k", "critical", artifact=art, explanation="c"),
        _signal("k", "high", artifact=art, explanation="h"),
        _signal("k", "medium", artifact=art, explanation="m"),
        _signal("k", "low", artifact=art, explanation="l"),
        _signal("k", "info", artifact=art, explanation="i"),
    ]
    report = ScanReport(artifacts=[art], signals=sigs)
    out = json.loads(render_sarif(report))
    levels = [r["level"] for r in out["runs"][0]["results"]]
    assert levels == ["error", "error", "warning", "note", "note"]


def test_sarif_includes_diff_signals():
    art = Artifact("npm", "keyv", "6.0.0")
    diff_sig = _signal(
        "baseline_deviation",
        "critical",
        artifact=art,
        file="setup.mjs",
        explanation="new install hook in patch bump",
    )
    diff = DiffOutcome(
        artifact=art,
        from_version="5.2.0",
        to_version="6.0.0",
        signals=[diff_sig],
    )
    report = ScanReport(artifacts=[art], diffs=[diff])
    out = json.loads(render_sarif(report))
    result = out["runs"][0]["results"][0]
    assert result["ruleId"] == "baseline_deviation"
    assert result["level"] == "error"
    assert out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "setup.mjs"


def test_sarif_handles_missing_evidence_file():
    sig = _signal("obfuscation", "medium", artifact=Artifact("npm", "x", "1.0.0"), explanation="eval found")
    report = ScanReport(artifacts=[sig.artifact], signals=[sig])
    out = json.loads(render_sarif(report))
    result = out["runs"][0]["results"][0]
    assert "locations" not in result or result.get("locations") == []


def test_sarif_output_is_valid_json():
    sig = _signal("obfuscation", "low", artifact=Artifact("npm", "x", "1.0.0"), file="a.js")
    report = ScanReport(artifacts=[sig.artifact], signals=[sig])
    out = render_sarif(report)
    parsed = json.loads(out)
    assert isinstance(parsed["runs"], list)
    assert isinstance(parsed["runs"][0]["results"], list)
