"""Newly introduced native binary detection.

Binaries are common in packages (low on their own), but a *new* binary in a
version bump is suspicious — especially large ones, or PE (.exe/.dll) files
shipped in an npm/pypi package where they don't belong.
"""

from __future__ import annotations

from pathlib import Path

from ..models import KIND_NATIVE, Signal
from .. import utils
from ._archive import archive_read
from .base import Detector

BINARY_SUFFIXES = {".so", ".dll", ".exe", ".dylib", ".bin", ".node", ".wasm", ".o", ".a"}
LARGE_FILE = 2 * 1024 * 1024
DIFF_LARGE = 1024 * 1024
VERSION_CAP = 20
PE_SUFFIXES = {".exe", ".dll"}


class NativeBinaryDetector(Detector):
    name = "native"

    def scan_version(self, artifact, extract_dir: Path, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for p in sorted(extract_dir.rglob("*")):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            suffix = Path(p.name).suffix.lower()
            fmt = utils.file_magic(p)
            if not fmt and suffix not in BINARY_SUFFIXES:
                large_and_binary = False
                if size > LARGE_FILE:
                    try:
                        with open(p, "rb") as fh:
                            large_and_binary = utils.looks_binary(fh.read(8192))
                    except OSError:
                        large_and_binary = False
                if not large_and_binary:
                    continue
                fmt = "large_file"
            signals.append(
                Signal(
                    kind=KIND_NATIVE,
                    artifact=artifact,
                    severity="low",
                    confidence=0.5,
                    evidence={
                        "file": str(p.relative_to(extract_dir)),
                        "format": fmt or suffix or "large_file",
                        "size": size,
                    },
                    reported_by=self.name,
                    explanation=f"native binary {fmt or 'file'} ({size} bytes)",
                )
            )
            if len(signals) >= VERSION_CAP:
                break
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for change in version_diff.added:
            size = change.size_after or 0
            suffix = Path(change.path).suffix.lower()
            binary_suffix = suffix in BINARY_SUFFIXES
            has_magic = False
            if not binary_suffix:
                head = archive_read(ctx, version_diff, change.path, 8)
                has_magic = bool(head) and any(head.startswith(m) for m in utils.MAGIC)
            # A size alone (e.g. a 3MB .json) is not a native binary.
            if not binary_suffix and not has_magic:
                continue
            if size > DIFF_LARGE or suffix in PE_SUFFIXES or has_magic:
                severity, confidence = "high", 0.85
            else:
                severity, confidence = "medium", 0.7
            signals.append(
                Signal(
                    kind=KIND_NATIVE,
                    artifact=version_diff.artifact,
                    severity=severity,
                    confidence=confidence,
                    evidence={"file": change.path, "size": size},
                    reported_by=self.name,
                    explanation="newly introduced native binary in this version",
                )
            )
        return signals
