"""Shared low-level helpers: safe extraction, hashing, entropy, text metrics.

Stdlib only. No network here — that lives in cache.py / registries.
"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

MAX_EXTRACT_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB safety cap per archive

MAGIC = {
    b"\x7fELF": "ELF",
    b"MZ": "PE",
    b"\xfe\xed\xfa\xce": "Mach-O",
    b"\xfe\xed\xfa\xcf": "Mach-O",
    b"\xca\xfe\xba\xbe": "Mach-O",
    b"\xcf\xfa\xed\xfe": "Mach-O",
    b"\xce\xfa\xed\xfe": "Mach-O",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0..8) of the given buffer."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _safe_tar_extract(tf: tarfile.TarFile, dest: Path, max_size: int) -> int:
    """Extract member-by-member with path-traversal and symlink guards.

    Link members (symlink/hardlink/device) are skipped entirely so a single
    malicious link can't abort the whole archive or escape the dest dir.
    File modes (incl. setuid/world-writable, which tarfile's "data" filter
    would strip) are preserved so permission detectors can inspect them.
    """
    total = 0
    dest.mkdir(parents=True, exist_ok=True)
    for member in tf.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            continue
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            continue
        total += member.size
        if total > max_size:
            raise ValueError(f"archive exceeds size cap ({max_size} bytes)")
        target = dest / member_path
        try:
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            os.chmod(target, member.mode & 0o7777)
        except (OSError, tarfile.TarError, ValueError):
            continue
    return total


def safe_extract_tar(path: Path, dest: Path, max_size: int = MAX_EXTRACT_SIZE) -> int:
    with tarfile.open(path, "r:*") as tf:
        return _safe_tar_extract(tf, dest, max_size)


def safe_extract_zip(path: Path, dest: Path, max_size: int = MAX_EXTRACT_SIZE) -> int:
    total = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            parts = Path(name).parts
            if name.startswith("/") or any(p in (".", "..") for p in parts):
                continue
            total += info.file_size
            if total > max_size:
                raise ValueError(f"archive exceeds size cap ({max_size} bytes)")
        zf.extractall(dest)
    return total


def extract_archive(path: Path, dest: Path) -> int:
    """Dispatch on archive type. Returns extracted byte count."""
    if tarfile.is_tarfile(path):
        return safe_extract_tar(path, dest)
    if zipfile.is_zipfile(path):
        return safe_extract_zip(path, dest)
    raise ValueError(f"unsupported archive format: {path.name}")


def safe_token(value, default: str = "x") -> str:
    """Sanitize a string for use as a single path component (tmp filenames)."""
    v = str(value)
    if not v or v in (".", "..") or "/" in v or "\\" in v or "\x00" in v:
        return default
    return v


def hoist_single_dir(dest: Path) -> None:
    """If dest contains exactly one directory, move its contents up into dest.

    npm tarballs wrap everything in package/; sdists wrap in name-version/.
    Wheels (multiple top-level entries) are left untouched.
    """
    entries = [p for p in Path(dest).iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        top = entries[0]
        for child in top.iterdir():
            shutil.move(str(child), str(Path(dest) / child.name))
        top.rmdir()


def file_magic(path: Path) -> Optional[str]:
    """Detect binary format from magic bytes: ELF/PE/Mach-O or None."""
    with open(path, "rb") as f:
        head = f.read(8)
    for magic, label in MAGIC.items():
        if head.startswith(magic):
            return label
    return None


def levenshtein(a: str, b: str) -> int:
    """Edit distance. Used for typosquat similarity. Bounded to save time."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 4:
        return abs(la - lb)
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def looks_binary(data: bytes) -> bool:
    """Heuristic: file contains NUL bytes or non-text sequences in first 8KB."""
    sample = data[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    textish = sum(1 for b in sample if b >= 32 or b in (9, 10, 13))
    return (textish / len(sample)) < 0.9
