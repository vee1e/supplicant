"""Shared scan context threaded through every detector.

Owns the cache, archive, live registries, baseline profiles built so far, and
collected signals. Detectors read from it; the pipeline mutates it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .models import BaselineProfile, Signal

if TYPE_CHECKING:
    from .cache import Cache
    from .registries import Registry
    from .registries.archive import Archive


@dataclass
class ScanContext:
    cache: "Cache"
    archive: "Archive"
    registries: dict[str, "Registry"] = field(default_factory=dict)
    config: dict = field(default_factory=dict)
    baselines: dict[str, BaselineProfile] = field(default_factory=dict)
    signals: list[Signal] = field(default_factory=list)
    fingerprints: dict[str, list[str]] = field(default_factory=dict)  # fp_id -> artifact keys
    depth: int = 0

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)

    def registry(self, ecosystem: str) -> "Registry":
        return self.registries[ecosystem]

    def baseline(self, ecosystem: str, name: str) -> BaselineProfile:
        key = f"{ecosystem}:{name}"
        if key not in self.baselines:
            self.baselines[key] = BaselineProfile(ecosystem=ecosystem, name=name)
        return self.baselines[key]
