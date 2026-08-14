"""Immutable local archive of every artifact we've ever seen.

Purpose: a malicious version gets unpublished from the live registry; the
defender still needs the exact tarball. Once we fetch a version we store it
here forever (content-addressed), so `forensics` and `diff` keep working after
a yank.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

from ..models import Artifact


def _safe_component(value: str, label: str) -> str:
    """Reject path components that could escape the archive root."""
    if not value or value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe {label} in archive path: {value!r}")
    return value


def _safe_name(value: str) -> str:
    """Encode a package name (which may be scoped: '@scope/pkg') to one safe
    path component, then validate it. Validation runs on the RAW name so
    traversal like '../evil' can't hide inside the '/'->'__' encoding."""
    raw = str(value)
    if not raw or raw in (".", "..") or "\\" in raw or "\x00" in raw or raw.startswith("/"):
        raise ValueError(f"unsafe package name in archive path: {raw!r}")
    if "/" in raw and not raw.startswith("@"):
        raise ValueError(f"unscoped package name cannot contain '/': {raw!r}")
    for part in raw.split("/"):
        if part in ("", ".", ".."):
            raise ValueError(f"unsafe package name in archive path: {raw!r}")
    return raw.replace("/", "__")


class Archive:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.tarballs = self.root / "tarballs"
        self.extracted = self.root / "extracted"
        self.tarballs.mkdir(parents=True, exist_ok=True)
        self.extracted.mkdir(parents=True, exist_ok=True)

    def _artifact_rel(self, artifact: Artifact) -> Path:
        eco = _safe_component(artifact.ecosystem, "ecosystem")
        name = _safe_name(artifact.name)
        version = _safe_component(artifact.version, "version")
        return Path(eco) / name / version

    def store_tarball(self, artifact: Artifact, src: Path) -> Path:
        dest = self.tarballs / self._artifact_rel(artifact)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return dest

    def get_tarball(self, artifact: Artifact) -> Optional[Path]:
        p = self.tarballs / self._artifact_rel(artifact)
        return p if p.exists() else None

    def store_extracted(self, artifact: Artifact, src: Path) -> Path:
        dest = self.extracted / self._artifact_rel(artifact)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
        return dest

    def get_extracted(self, artifact: Artifact) -> Optional[Path]:
        p = self.extracted / self._artifact_rel(artifact)
        return p if p.exists() else None

    def record(self, artifact: Artifact, release: dict) -> None:
        """Persist release metadata so forensics works even after registry yank."""
        eco = _safe_component(artifact.ecosystem, "ecosystem")
        name = _safe_name(artifact.name)
        version = _safe_component(artifact.version, "version")
        meta_path = self.root / "index" / f"{eco}_{name}_{version}.json"
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(release, sort_keys=True, indent=2))

    def releases(self, ecosystem: str, name: str) -> list[str]:
        """All versions archived for a package."""
        base = self.extracted / _safe_component(ecosystem, "ecosystem") / _safe_name(name)
        if not base.exists():
            return []
        return sorted(p.name for p in base.iterdir() if p.is_dir())

    def has(self, artifact: Artifact) -> bool:
        return self.get_tarball(artifact) is not None and self.get_extracted(artifact) is not None
