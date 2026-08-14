"""Obfuscation detection, scored relative to a package's own history.

A standalone obfuscated file is common in minified bundles (low); a *new*
obfuscated file appearing in a version bump is more meaningful (medium), and
escalates to high when that file is also an install hook.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import KIND_OBFUSCATE, Signal
from ..utils import compute_entropy, looks_binary
from ._archive import archive_read
from .base import Detector
from .install import HOOK_NAMES

SAMPLE_BYTES = 8192
DIFF_CAP = 10
# A padded base64 run of >= 80 chars is far more likely a payload than a hash.
RE_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{80,}={1,2}")


class ObfuscationDetector(Detector):
    name = "obfuscate"

    @staticmethod
    def text_entropy(data: bytes) -> float:
        return compute_entropy(data[:SAMPLE_BYTES])

    def _looks_obfuscated(self, data: bytes) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        if b"eval(" in data:
            reasons.append("eval(")
        if b"b64decode" in data or b"atob(" in data:
            reasons.append("base64_decode")
        if RE_B64_BLOB.search(data):
            reasons.append("long_b64_blob")
        entropy = self.text_entropy(data)
        if entropy > 7.0:
            reasons.append(f"high_entropy:{entropy:.2f}")
        if b"\x00" in data:
            reasons.append("nul_bytes")
        return (bool(reasons), reasons)

    def scan_version(self, artifact, extract_dir: Path, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for p in sorted(extract_dir.rglob("*")):
            if not p.is_file():
                continue
            if str(p).endswith(".map"):
                continue  # source maps routinely embed base64 blobs
            with open(p, "rb") as f:
                data = f.read(SAMPLE_BYTES)
            if looks_binary(data):
                continue
            obfuscated, reasons = self._looks_obfuscated(data)
            if not obfuscated:
                continue
            signals.append(
                Signal(
                    kind=KIND_OBFUSCATE,
                    artifact=artifact,
                    severity="low",
                    confidence=0.5,
                    evidence={"file": str(p.relative_to(extract_dir)), "reasons": reasons},
                    reported_by=self.name,
                    explanation="obfuscated code",
                )
            )
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        hook_names = {h.lower() for h in HOOK_NAMES}
        changes = list(version_diff.added) + list(version_diff.modified)
        for change in changes:
            if len(signals) >= DIFF_CAP:
                break
            data = archive_read(ctx, version_diff, change.path, SAMPLE_BYTES)
            if data is None or looks_binary(data):
                continue
            obfuscated, reasons = self._looks_obfuscated(data)
            if not obfuscated:
                continue
            is_added_hook = change.status == "added" and Path(change.path).name.lower() in hook_names
            signals.append(
                Signal(
                    kind=KIND_OBFUSCATE,
                    artifact=version_diff.artifact,
                    severity="high" if is_added_hook else "medium",
                    confidence=0.85 if is_added_hook else 0.7,
                    evidence={"file": change.path, "reasons": reasons},
                    reported_by=self.name,
                    explanation="newly obfuscated code in this version",
                )
            )
        return signals
