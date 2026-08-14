"""Delta-fingerprint worm detector.

Identical diffs across many unrelated packages are the signature of a
coordinated supply-chain worm. The canonical signature is computed by the diff
engine (diff/engine.compute_delta_fingerprint); this detector consumes it and
tracks how many packages share it within one scan context.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..detect.base import Detector
from ..diff.engine import compute_delta_fingerprint
from ..models import KIND_FINGERPRINT, Signal

if TYPE_CHECKING:
    from ..context import ScanContext


def delta_signature(version_diff) -> str:
    """Canonical signature of one version bump (single source of truth)."""
    return compute_delta_fingerprint(version_diff)


def _delta_bytes(version_diff) -> int:
    total = 0
    for c in version_diff.changes:
        if c.status == "added":
            total += c.size_after or 0
        elif c.status == "removed":
            total -= c.size_before or 0
        else:
            total += (c.size_after or 0) - (c.size_before or 0)
    return total


def _parse_suspicious(sig: str) -> tuple[int, int, int]:
    m = re.search(r"hooks:\+(\d+)/-?(\d+)", sig)
    hooks = int(m.group(1)) if m else 0
    m = re.search(r"bins:\+(\d+)", sig)
    bins = int(m.group(1)) if m else 0
    m = re.search(r"obf:(\d+)", sig)
    obf = int(m.group(1)) if m else 0
    return hooks, bins, obf


class FingerprintDetector(Detector):
    name = "fingerprint"

    def scan_diff(self, version_diff, ctx: "ScanContext") -> list[Signal]:
        sig = compute_delta_fingerprint(version_diff)
        if sig == "noop":
            return []

        version_diff.delta_fingerprint = sig
        seen = ctx.fingerprints.setdefault(sig, [])
        key = version_diff.artifact.key
        if key not in seen:
            seen.append(key)

        hooks, bins, obf = _parse_suspicious(sig)
        suspicious = hooks >= 1 or bins >= 1 or obf >= 1
        n = len(seen)
        delta = _delta_bytes(version_diff)

        if n >= 3 and suspicious:
            return [
                Signal(
                    kind=KIND_FINGERPRINT,
                    artifact=version_diff.artifact,
                    severity="critical",
                    confidence=0.9,
                    evidence={"signature": sig, "seen_on": list(seen)},
                    reported_by=self.name,
                    explanation=f"delta fingerprint matches {n - 1} other packages (worm signature)",
                )
            ]
        if n == 2 and suspicious:
            return [
                Signal(
                    kind=KIND_FINGERPRINT,
                    artifact=version_diff.artifact,
                    severity="high",
                    confidence=0.8,
                    evidence={"signature": sig, "seen_on": list(seen)},
                    reported_by=self.name,
                    explanation="delta fingerprint matches 1 other package (suspicious structure)",
                )
            ]
        if n >= 3 and (suspicious or abs(delta) > 1024 * 1024):
            return [
                Signal(
                    kind=KIND_FINGERPRINT,
                    artifact=version_diff.artifact,
                    severity="medium",
                    confidence=0.6,
                    evidence={"signature": sig, "seen_on": list(seen)},
                    reported_by=self.name,
                    explanation=f"identical delta fingerprint across {n} packages (possible coordinated release)",
                )
            ]
        return []
