"""Shared helper: read bytes/mode of an added/modified file from the local
archive for diff detectors. Keeps obfuscate/native/perms from each
re-implementing the same archive walk.
"""

from __future__ import annotations

from ..models import Artifact
from ..utils import original_mode


def archive_read(ctx, version_diff, relpath: str, n: int = 8192):
    """Read up to n bytes of relpath from the to/from extracted versions."""
    for version in (version_diff.to_version, version_diff.from_version):
        art = Artifact(
            ecosystem=version_diff.artifact.ecosystem,
            name=version_diff.artifact.name,
            version=version,
        )
        base = ctx.archive.get_extracted(art)
        if base is None:
            continue
        p = base / relpath
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    return f.read(n)
            except OSError:
                return None
    return None


def archive_mode(ctx, version_diff, relpath: str):
    """Return the file mode of relpath from the to/from extracted versions."""
    for version in (version_diff.to_version, version_diff.from_version):
        art = Artifact(
            ecosystem=version_diff.artifact.ecosystem,
            name=version_diff.artifact.name,
            version=version,
        )
        base = ctx.archive.get_extracted(art)
        if base is None:
            continue
        p = base / relpath
        if p.is_file():
            try:
                return original_mode(base, relpath, p.stat().st_mode)
            except OSError:
                return None
    return None
