"""Shared test fixtures: build package-like dir trees and fake contexts."""

from __future__ import annotations

import os
from pathlib import Path

from supplicant.cache import Cache
from supplicant.context import ScanContext
from supplicant.registries.archive import Archive


def make_tree(root: Path, files: dict[str, str | bytes], modes: dict[str, int] | None = None) -> Path:
    """Write a flat {relative_path: content} map under root. bytes = binary."""
    modes = modes or {}
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
        if rel in modes:
            os.chmod(p, modes[rel])
    return root


def make_context(tmp_path: Path, config: dict | None = None) -> ScanContext:
    cache = Cache(tmp_path / "cache")
    archive = Archive(tmp_path / "archive")
    return ScanContext(cache=cache, archive=archive, registries={}, config=dict(config or {}))


def make_installed_context(tmp_path: Path, config: dict | None = None) -> ScanContext:
    """Context with the archive populated for a fake npm package@version."""
    ctx = make_context(tmp_path, config)
    return ctx
