"""Detector interface.

A Detector inspects either (a) a single downloaded+extracted version, or
(b) a VersionDiff of two versions, and returns zero or more Signals.

Contract: detectors NEVER execute package code, only parse it. They are pure
functions over files + the shared ScanContext. No network from detectors.
"""

from __future__ import annotations

from abc import ABC
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Signal, VersionDiff

if TYPE_CHECKING:
    from ..context import ScanContext


class Detector(ABC):
    name: str = "base"

    def scan_version(self, artifact, extract_dir: Path, ctx: "ScanContext") -> list[Signal]:  # noqa: ANN001
        return []

    def scan_diff(self, version_diff: VersionDiff, ctx: "ScanContext") -> list[Signal]:  # noqa: ANN001
        return []
