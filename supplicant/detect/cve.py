"""Known-vulnerability matching against the OSV.dev API.

Fetches advisories for (package, version) via the OSV query endpoint and
maps them into Signals. Only the OSV query here; network policy stays inside
this module (cache.http_get is GET-only, so we POST directly).
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from ..models import KIND_CVE, Signal
from .base import Detector

OSV_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}

UA = "supplicant/0.1 (+https://github.com/supplicant)"

_SEV_ORDER = {"LOW": 0, "MODERATE": 1, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _osv_post(payload: dict, timeout: int = 20, retries: int = 1) -> dict:
    """POST a query to OSV.dev. Retries once on transient failures."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                OSV_URL,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={
                    "User-Agent": UA,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
            return json.loads(body.decode("utf-8"))
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
            ValueError,
        ):
            if attempt < retries:
                time.sleep(1)
                continue
            raise
    raise RuntimeError("OSV query failed")


def query_osv(ecosystem: str, name: str, version: str) -> list[dict]:
    """Return OSV vuln dicts for one (ecosystem, name, version)."""
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    data = _osv_post(payload)
    if not isinstance(data, dict):
        return []
    vulns = data.get("vulns")
    return vulns if isinstance(vulns, list) else []


_CVSS_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS_V3_AC = {"L": 0.77, "H": 0.44}
_CVSS_V3_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_V3_UI = {"N": 0.85, "R": 0.62}
_CVSS_V3_IMP = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_v3_score(vector: str) -> float | None:
    """Approximate CVSS v3 base score from a vector string.

    Parses the fixed-order segments (AV/AC/PR/UI/S/C/I/A) — never bare
    "C:"/"I:" matches, which misread AC:H, PR:N etc.
    """
    parts = {seg.split(":", 1)[0]: seg.split(":", 1)[1] for seg in vector.split("/") if ":" in seg}
    try:
        av = _CVSS_V3_AV[parts["AV"]]
        ac = _CVSS_V3_AC[parts["AC"]]
        pr = _CVSS_V3_PR[parts["PR"]]
        ui = _CVSS_V3_UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        c = _CVSS_V3_IMP[parts["C"]]
        i = _CVSS_V3_IMP[parts["I"]]
        a = _CVSS_V3_IMP[parts["A"]]
    except KeyError:
        return None
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    exploitability = 8.22 * av * ac * pr * ui
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    score = impact + exploitability
    if scope_changed:
        score = 1.08 * score
    return round(max(0.0, min(score, 10.0)), 1)


def _parse_cvss_score(score) -> float | None:
    """Parse a CVSS score from a bare number or a CVSS 3.x vector string."""
    if score is None:
        return None
    if isinstance(score, (int, float)):
        return float(score)
    s = str(score)
    m = re.search(r"(\d+(?:\.\d+)?)\s*$", s)
    if m:
        return float(m.group(1))
    if s.startswith("CVSS:"):
        return _cvss_v3_score(s)
    return None


def _label_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _best_raw_severity(vuln: dict) -> str:
    """Best available severity label: highest of affected[].severity[] or CVSS."""
    best = ""
    best_rank = -1

    def consider(label) -> None:
        nonlocal best, best_rank
        if label is None:
            return
        l = str(label).upper()
        if l in _SEV_ORDER and _SEV_ORDER[l] > best_rank:
            best, best_rank = l, _SEV_ORDER[l]

    consider(vuln.get("severity"))
    consider((vuln.get("database_specific") or {}).get("severity"))
    for affected in vuln.get("affected") or []:
        for sev in affected.get("severity") or []:
            consider(sev.get("severity"))
            score = _parse_cvss_score(sev.get("score"))
            if score is not None:
                consider(_label_from_score(score))
    return best


def _vuln_severity(vuln: dict) -> str:
    raw = _best_raw_severity(vuln)
    summary = " ".join(str(vuln.get(k) or "") for k in ("summary", "details"))
    vid = str(vuln.get("id") or "")
    aliases = vuln.get("aliases") or []
    if vid.startswith("MAL-") or any(str(a).startswith("MAL-") for a in aliases):
        return "critical"
    if re.search(r"arbitrary code|remote code|\brce\b", summary, re.IGNORECASE) or raw == "CRITICAL":
        return "critical"
    if raw == "HIGH":
        return "high"
    if raw in ("MODERATE", "MEDIUM"):
        return "medium"
    if raw == "LOW":
        return "low"
    # No severity data available: report the advisory but don't inflate it.
    return "medium"


class CveDetector(Detector):
    name = "cve"

    def scan_version(self, artifact, extract_dir, ctx) -> list[Signal]:
        if not ctx.config.get("osv", True):
            return []
        if artifact.version in (None, "latest"):
            return []
        osv_eco = OSV_ECOSYSTEMS.get(artifact.ecosystem)
        if osv_eco is None:
            return []
        done = ctx.config.setdefault("_osv_done", set())
        if artifact.key in done:
            return []
        done.add(artifact.key)
        try:
            vulns = query_osv(osv_eco, artifact.name, artifact.version)
        except Exception as exc:
            ctx.config.setdefault("_errors", []).append(
                f"osv {artifact.key}: {type(exc).__name__}: {exc}"
            )
            return []
        signals: list[Signal] = []
        for vuln in vulns:
            vid = vuln.get("id", "")
            summary = vuln.get("summary") or (vuln.get("details") or "")[:200]
            aliases = vuln.get("aliases") or []
            signals.append(
                Signal(
                    kind=KIND_CVE,
                    artifact=artifact,
                    severity=_vuln_severity(vuln),
                    confidence=1.0,
                    evidence={"id": vid, "summary": summary, "aliases": aliases},
                    reported_by=self.name,
                    explanation=f"known vulnerability {vid}: {summary}",
                )
            )
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:
        return self.scan_version(version_diff.artifact, None, ctx)
