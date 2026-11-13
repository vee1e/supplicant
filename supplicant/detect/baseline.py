"""Self-baseline deviation detector.

Compares one version bump against the package's own release history
(profile learned from registry metadata + prior scans). A package that
suddenly breaks its own cadence, author, repo, or payload habits is the
classic account-takeover / supply-chain attack shape.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ..detect.base import Detector
from ..models import KIND_BASELINE, Signal
from ..utils import looks_binary
from .install import manifest_script_hooks

if TYPE_CHECKING:
    from ..context import ScanContext

INSTALL_HOOK_TOKENS = (
    "install.js", "install.sh", "postinstall", "preinstall", "setup.py",
    "setup.mjs", "setup.js", "prepare.js",
)
BINARY_SUFFIXES = (".so", ".dll", ".exe", ".dylib", ".bin", ".node", ".wasm", ".o")


def _iso_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _repo_url(value) -> str:
    if isinstance(value, dict):
        value = value.get("url") or ""
    return str(value or "")


def _author_name(value) -> str:
    if isinstance(value, dict):
        value = value.get("name") or value.get("email") or ""
    return str(value or "")


def _publisher_name(version_diff) -> str:
    """Prefer the per-version npm `_npmUser` publisher over package.json author."""
    raw = getattr(version_diff, "raw_after", None) or {}
    if not isinstance(raw, dict):
        raw = {}
    user = raw.get("_npmUser") or raw.get("npmUser")
    name = _author_name(user)
    if name:
        return name
    return ""


def _is_install_hook(path: str) -> bool:

    lowered = path.lower()
    return any(token in lowered for token in INSTALL_HOOK_TOKENS)


def _is_binary_content(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
    except OSError:
        return False
    return looks_binary(head)


def warm_from_metadata(ctx: "ScanContext", ecosystem: str, name: str, metadata: dict) -> None:
    """Learn a package's release-history habits from registry metadata."""
    profile = ctx.baseline(ecosystem, name)
    release_times: list[float] = []
    if ecosystem == "npm":
        versions = metadata.get("versions") or {}
        time_map = metadata.get("time") or {}
        for version in versions:
            ts = _iso_timestamp(time_map.get(version))
            if ts is not None:
                release_times.append(ts)
        for m in metadata.get("maintainers") or []:
            if isinstance(m, dict) and m.get("name"):
                profile.author_set.add(str(m["name"]).lower())
        if metadata.get("repository"):
            profile.repo_urls.add(_repo_url(metadata["repository"]))
        for v in versions.values():
            if isinstance(v, dict) and v.get("repository"):
                profile.repo_urls.add(_repo_url(v["repository"]))
    else:
        releases = metadata.get("releases") or {}
        for files in releases.values():
            if not files:
                continue
            ts = _iso_timestamp(files[0].get("upload_time"))
            if ts is not None:
                release_times.append(ts)
        info = metadata.get("info") or {}
        email = info.get("author_email")
        if email:
            profile.author_set.add(str(email).lower())
        for url in (info.get("project_urls") or {}).values():
            if url:
                profile.repo_urls.add(str(url))

    release_times.sort()
    gaps = [
        (release_times[i + 1] - release_times[i]) / 86400.0
        for i in range(len(release_times) - 1)
    ]
    profile.num_releases = len(release_times)
    profile.release_gaps_days = gaps
    if len(gaps) >= 2:
        profile.mean_gap_days = sum(gaps) / len(gaps)
        profile.std_gap_days = statistics.stdev(gaps)
    else:
        profile.mean_gap_days = None
        profile.std_gap_days = None
    profile.last_gap_days = gaps[-1] if gaps else None


class BaselineDetector(Detector):
    name = "baseline"

    def scan_version(self, artifact, extract_dir: Path, ctx: "ScanContext") -> list[Signal]:
        profile = ctx.baseline(artifact.ecosystem, artifact.name)
        for p in extract_dir.rglob("*"):
            if not p.is_file():
                continue
            rel = str(p.relative_to(extract_dir)).lower()
            if any(token in rel for token in INSTALL_HOOK_TOKENS):
                profile.install_hooks_ever = True
            if rel.endswith(BINARY_SUFFIXES) or _is_binary_content(p):
                profile.binaries_ever = True
        return []

    def scan_diff(self, version_diff, ctx: "ScanContext") -> list[Signal]:
        profile = ctx.baseline(version_diff.artifact.ecosystem, version_diff.artifact.name)
        if profile.num_releases < 3 or profile.mean_gap_days is None:
            return []

        reasons: list[str] = []
        strong = False
        medium_flags: list[str] = []

        last_gap = getattr(profile, "last_gap_days", None)
        if (
            last_gap is not None
            and profile.mean_gap_days > 0
            and last_gap < profile.mean_gap_days * 0.1
            and profile.num_releases >= 5
        ):
            strong = True
            reasons.append(f"release {last_gap:.1f}d after previous vs mean {profile.mean_gap_days:.1f}d")

        author_after = _publisher_name(version_diff).lower() or _author_name(
            version_diff.manifest_after.get("author")
        ).lower()
        authors = {a.lower() for a in profile.author_set if a}
        if (
            author_after
            and authors
            and not any(a in author_after or author_after in a for a in authors)
        ):
            medium_flags.append("author")
            reasons.append(f"author changed to {author_after!r}")

        repo_after = _repo_url(version_diff.manifest_after.get("repository")).lower()
        repos = {r.lower() for r in profile.repo_urls if r}
        if (
            repo_after
            and repos
            and not any(r in repo_after or repo_after in r for r in repos)
        ):
            medium_flags.append("repo")
            reasons.append(f"repository changed to {repo_after!r}")

        added_hooks = [c.path for c in version_diff.added if _is_install_hook(c.path)]
        before_hooks = manifest_script_hooks(version_diff.manifest_before)
        after_hooks = manifest_script_hooks(version_diff.manifest_after)
        for name, script in after_hooks.items():
            if before_hooks.get(name) != script:
                added_hooks.append(f"package.json#scripts.{name}")
        if added_hooks and not profile.install_hooks_ever:
            medium_flags.append("hook")
            reasons.append(f"new install hooks: {', '.join(added_hooks)}")

        added_bins = [c.path for c in version_diff.added if c.path.lower().endswith(BINARY_SUFFIXES)]
        if added_bins and not profile.binaries_ever:
            medium_flags.append("binary")
            reasons.append(f"new binary files: {', '.join(added_bins)}")

        deps_before = set((version_diff.manifest_before.get("dependencies") or {}).keys()) \
            if isinstance(version_diff.manifest_before.get("dependencies"), dict) else set()
        deps_after = set((version_diff.manifest_after.get("dependencies") or {}).keys()) \
            if isinstance(version_diff.manifest_after.get("dependencies"), dict) else set()
        deps_added = len(deps_after - deps_before)
        if deps_added > 3:
            medium_flags.append("deps")
            reasons.append(f"dependency surge (+{deps_added} deps)")

        payload_added = sum(c.size_after or 0 for c in version_diff.added)

        # ChainDrop shape: a package that NEVER shipped install hooks suddenly
        # ships one alongside a large payload (obfuscated loader + bump).
        first_hook_plus_payload = (
            "hook" in medium_flags
            and payload_added > 512 * 1024
        )
        takeover_shape = "hook" in medium_flags and ("author" in medium_flags or "repo" in medium_flags)
        if first_hook_plus_payload:
            reasons.append(f"first-ever install hook with {payload_added} bytes of new payload")

        if not reasons and not strong and not medium_flags:
            return []

        if first_hook_plus_payload or takeover_shape:
            severity = "critical"
        elif strong and (medium_flags or payload_added > 256 * 1024):
            severity = "high"
        elif len(medium_flags) >= 2:
            severity = "high"
        elif strong:
            severity = "medium"
        elif "hook" in medium_flags or "binary" in medium_flags:
            severity = "medium"
        elif medium_flags:
            severity = "low"
        else:
            severity = "low"

        confidence = min(0.98, 0.8 + 0.05 * len(reasons) + (0.1 if strong else 0))
        explanation = "; ".join(reasons) or "no significant deviation"

        return [
            Signal(
                kind=KIND_BASELINE,
                artifact=version_diff.artifact,
                severity=severity,
                confidence=confidence,
                evidence={
                    "reasons": reasons,
                    "fingerprint": version_diff.delta_fingerprint,
                    "profile_releases": profile.num_releases,
                },
                reported_by=self.name,
                explanation=explanation,
            )
        ]
