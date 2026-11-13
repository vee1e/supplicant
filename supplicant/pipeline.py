"""Pipeline: orchestrates registries, resolvers, diff engine and detectors.

This module binds every component into the three core flows:
  - scan:        resolve a dependency tree, scan each artifact, diff the target
  - diff:        the flagship "what changed between 4.1.2 and 4.1.3?"
  - forensics:   reconstruct a (possibly yanked) version from the archive
"""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path

from .cache import Cache
from .context import ScanContext
from .models import Artifact, DiffOutcome, ScanReport, severity_rank
from .registries.archive import Archive
from .registries.npm import NpmRegistry
from .registries.pypi import PyPiRegistry

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "supplicant"


# --------------------------------------------------------------------------
# context + target parsing
# --------------------------------------------------------------------------

def build_context(cache_dir: Path, config: dict | None = None) -> ScanContext:
    config = dict(config or {})
    cache_dir = Path(cache_dir)
    cache = Cache(cache_dir)
    archive = Archive(cache_dir / "archive")
    registries = {
        "npm": NpmRegistry(cache, archive),
        "pypi": PyPiRegistry(cache, archive),
    }
    return ScanContext(cache=cache, archive=archive, registries=registries, config=config)


def parse_target(target: str) -> Artifact:
    """Parse 'pkg', 'pkg@1.2.3', 'npm:pkg@1.2.3', 'pypi:pkg==1.2.3'.

    Handles scoped npm names ('@scope/pkg' and '@scope/pkg@1.0.0').
    """
    ecosystem, body = "npm", target
    if ":" in target and target.split(":", 1)[0] in ("npm", "pypi", "rubygems"):
        ecosystem, body = target.split(":", 1)
    if ecosystem == "pypi" and "==" in body:
        name, version = body.split("==", 1)
        return Artifact(ecosystem, name, version)
    if body.startswith("@"):
        # scoped name: '@scope/pkg' or '@scope/pkg@1.0.0'
        rest = body[1:]
        scope, _, tail = rest.partition("/")
        if not tail:
            raise ValueError(f"invalid scoped package name: {target!r}")
        name = f"@{scope}/{tail}"
        if "@" in tail:
            tail_name, _, version = tail.rpartition("@")
            return Artifact(ecosystem, f"@{scope}/{tail_name}", version)
        return Artifact(ecosystem, name, "latest")
    if "@" in body:
        name, version = body.rsplit("@", 1)
        return Artifact(ecosystem, name, version)
    return Artifact(ecosystem, body, "latest")


def _resolve_latest(ctx: ScanContext, artifact: Artifact) -> Artifact:
    """Replace version 'latest'/None with the registry's actual latest version."""
    if artifact.version not in (None, "latest"):
        return artifact
    meta = ctx.registry(artifact.ecosystem).metadata(artifact.name)
    if artifact.ecosystem == "npm":
        latest = meta.get("dist-tags", {}).get("latest") or max(meta.get("versions", {}).keys(), default=None)
    else:
        # pypi has no dist-tags; pick the newest by upload time, falling back
        # to numeric ordering.
        releases = meta.get("releases", {})
        latest = _newest_pypi_version(releases)
    if latest is None:
        return artifact
    return Artifact(artifact.ecosystem, artifact.name, latest)


def _newest_pypi_version(releases: dict) -> str | None:
    """Newest release by upload_time; fall back to numeric (not lexical) order."""
    if not releases:
        return None
    by_time = []
    for version, files in releases.items():
        ts = None
        for f in files or []:
            if isinstance(f, dict):
                ts = f.get("upload_time")
            if ts:
                break
        by_time.append((ts or "", version))
    by_time.sort()
    if by_time[-1][0]:
        return by_time[-1][1]
    return max(by_time, key=lambda t: _ver_key_numeric(t[1]))[1]


def _ver_key_numeric(v: str):
    parts = []
    for chunk in str(v).replace("-", ".").split("."):
        parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
    return tuple(parts)


def _previous_version(ctx: ScanContext, artifact: Artifact) -> str | None:
    """Best-effort: the release published immediately before `artifact`."""
    meta = ctx.registry(artifact.ecosystem).metadata(artifact.name)
    if artifact.ecosystem == "npm":
        tm = meta.get("time", {})
        versions = [v for v in meta.get("versions", {}) if v != artifact.version]
        versions.sort(key=lambda v: tm.get(v, ""))
        target_ts = tm.get(artifact.version, "")
        before = [v for v in versions if tm.get(v, "") <= target_ts]
        return before[-1] if before else None
    releases = meta.get("releases", {})
    ordered = sorted(releases.keys(), key=lambda v: _release_time(releases, v))
    if artifact.version in ordered:
        idx = ordered.index(artifact.version)
        return ordered[idx - 1] if idx > 0 else None
    return ordered[-1] if ordered else None


def _release_time(releases: dict, version: str) -> str:
    for f in releases.get(version) or []:
        if f.get("upload_time"):
            return str(f["upload_time"])
    return ""


def build_edges(ctx: ScanContext, artifacts: list[Artifact]) -> list[tuple]:
    """Reconstruct depends_on edges from cached metadata (no extra downloads)."""
    from .resolvers.tree import _resolve_npm_version

    keys = {a.key for a in artifacts}
    edges: list[tuple] = []
    for a in artifacts:
        if a.ecosystem != "npm":
            continue
        try:
            meta = ctx.registry("npm").metadata(a.name)
            v = meta.get("versions", {}).get(a.version) or {}
            deps = v.get("dependencies") or {}
        except Exception:
            continue
        for dep_name, dep_range in deps.items():
            try:
                child_ver = _resolve_npm_version(ctx, dep_name, dep_range)
            except Exception:
                continue
            if child_ver is None:
                continue
            child = Artifact("npm", dep_name, child_ver)
            if child.key in keys:
                edges.append((a, child))
    return edges


# --------------------------------------------------------------------------
# detector wiring
# --------------------------------------------------------------------------

def _version_detectors():
    from .detect.cve import CveDetector
    from .detect.identity import IdentityFenceDetector
    from .detect.install import InstallScriptDetector
    from .detect.native import NativeBinaryDetector
    from .detect.obfuscate import ObfuscationDetector
    from .detect.perms import PermissionsDetector
    from .detect.typosquat import TyposquatDetector

    return [
        CveDetector(),
        InstallScriptDetector(),
        ObfuscationDetector(),
        NativeBinaryDetector(),
        PermissionsDetector(),
        TyposquatDetector(),
        IdentityFenceDetector(),
    ]


def _diff_detectors():
    from .detect.baseline import BaselineDetector
    from .detect.cve import CveDetector
    from .detect.fingerprint import FingerprintDetector
    from .detect.install import InstallScriptDetector
    from .detect.native import NativeBinaryDetector
    from .detect.obfuscate import ObfuscationDetector
    from .detect.perms import PermissionsDetector

    return [
        BaselineDetector(),
        FingerprintDetector(),
        InstallScriptDetector(),
        ObfuscationDetector(),
        NativeBinaryDetector(),
        PermissionsDetector(),
        CveDetector(),
    ]


def _run_version_detectors(ctx: ScanContext, artifact: Artifact, extract_dir: Path, errors: list[str]) -> None:
    for detector in _version_detectors():
        try:
            for signal in detector.scan_version(artifact, extract_dir, ctx):
                ctx.add(signal)
        except Exception as e:  # detector failure never kills a scan
            errors.append(f"{detector.name}: {artifact.key}: {e}")


def _verdict(signals: list) -> str:
    if any(severity_rank(s.severity) >= severity_rank("critical") for s in signals):
        return "block"
    if any(severity_rank(s.severity) >= severity_rank("medium") for s in signals):
        return "review"
    return "ok"


# --------------------------------------------------------------------------
# core flows
# --------------------------------------------------------------------------

def compute_diff(ctx: ScanContext, ecosystem: str, name: str, v_before: str, v_after: str) -> DiffOutcome:
    """The flagship flow: diff two versions, score the delta, emit a verdict."""
    import shutil

    from .detect.baseline import BaselineDetector, warm_from_metadata
    from .diff.engine import diff_versions

    registry = ctx.registry(ecosystem)
    meta = registry.metadata(name)
    warm_from_metadata(ctx, ecosystem, name, meta)
    profile = ctx.baseline(ecosystem, name)

    try:
        rec_a = registry.release_info(name, v_before)
        rec_b = registry.release_info(name, v_after)
        time_map = meta.get("time", {})

        def _ts(release_ts, version):
            ts = release_ts
            if not ts:
                ts = time_map.get(version)
            if not ts:
                return None
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()

        ta = _ts(rec_a.published_at, v_before)
        tb = _ts(rec_b.published_at, v_after)
        if ta is not None and tb is not None and tb >= ta:
            profile.last_gap_days = (tb - ta) / 86400.0
    except Exception:
        pass

    dir_a = Path(tempfile.mkdtemp(prefix="supplicant-a-"))
    dir_b = Path(tempfile.mkdtemp(prefix="supplicant-b-"))
    try:
        registry.download_and_extract(name, v_before, dir_a)
        registry.download_and_extract(name, v_after, dir_b)

        # Learn hook/binary history from the BEFORE version so a bump that adds
        # a hook for the first time is distinguishable from one that always had it.
        try:
            BaselineDetector().scan_version(
                Artifact(ecosystem, name, v_before), dir_a, ctx
            )
        except Exception:
            pass

        version_diff = diff_versions(dir_a, dir_b, ecosystem, name, v_before, v_after)
        outcome = DiffOutcome(
            artifact=Artifact(ecosystem, name, v_after),
            from_version=v_before,
            to_version=v_after,
            diff=version_diff,
            baseline=profile,
        )

        for detector in _diff_detectors():
            try:
                for signal in detector.scan_diff(version_diff, ctx):
                    ctx.add(signal)
                    outcome.signals.append(signal)
            except Exception as e:  # detector failure never kills a diff
                ctx.config.setdefault("_errors", []).append(
                    f"{detector.name}: {artifact_key(ecosystem, name, v_after)}: {e}"
                )

        outcome.verdict = _verdict(outcome.signals)
        return outcome
    finally:
        shutil.rmtree(dir_a, ignore_errors=True)
        shutil.rmtree(dir_b, ignore_errors=True)


def artifact_key(ecosystem: str, name: str, version: str) -> str:
    return Artifact(ecosystem, name, version).key


def _download_and_scan(ctx: ScanContext, artifact: Artifact, errors: list[str]) -> None:
    """Download one artifact into a temp dir, run version detectors, clean up."""
    import shutil

    extract_dir = Path(tempfile.mkdtemp(prefix="supplicant-ver-"))
    try:
        ctx.registry(artifact.ecosystem).download_and_extract(artifact.name, artifact.version, extract_dir)
        _run_version_detectors(ctx, artifact, extract_dir, errors)
    except Exception as e:
        errors.append(f"{artifact.key}: {e}")
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)


def scan_target(ctx: ScanContext, target: str, max_depth: int = 10) -> ScanReport:
    """Resolve a dependency tree, scan every artifact, and diff the target vs
    its previous release."""
    from .resolvers.tree import resolve_tree

    report = ScanReport()
    try:
        root = parse_target(target)
        root = _resolve_latest(ctx, root)
    except Exception as e:
        report.errors.append(f"resolve {target}: {e}")
        report.signals = ctx.signals
        return report

    ctx.config["target_name"] = root.name
    try:
        artifacts = resolve_tree(ctx, root, max_depth=max_depth)
    except Exception as e:
        artifacts = [root]
        report.errors.append(f"tree resolution: {e}")

    resolved = [_resolve_latest(ctx, a) for a in artifacts]
    report.artifacts = resolved
    report.edges = build_edges(ctx, resolved)

    for a in resolved:
        _download_and_scan(ctx, a, report.errors)

    previous = _previous_version(ctx, root)
    if previous:
        try:
            outcome = compute_diff(ctx, root.ecosystem, root.name, previous, root.version)
            report.diffs.append(outcome)
        except Exception as e:
            report.errors.append(f"diff {root.key} vs {previous}: {e}")

    # Diff signals are already reported under report.diffs[].signals; don't
    # also list them in the top-level Signals section (double-counting).
    diff_signal_ids = {s.id for d in report.diffs for s in d.signals}
    report.signals = [s for s in ctx.signals if s.id not in diff_signal_ids]
    report.fingerprints = ctx.fingerprints
    report.errors.extend(ctx.config.get("_errors", []))
    return report


def scan_lockfile(ctx: ScanContext, path: str) -> ScanReport:
    """Scan every pinned dependency in a lockfile (no recursive resolution)."""
    from .resolvers.lockfile import parse_lockfile

    report = ScanReport()
    try:
        artifacts = parse_lockfile(path)
    except Exception as e:
        report.errors.append(f"parse {path}: {e}")
        report.signals = ctx.signals
        return report

    # Broad lockfile scans skip name-based detectors (typosquat/identity fence):
    # they are informational and would cost extra metadata fetches per dep.
    ctx.config["target_name"] = "__lockfile__"

    resolved, seen = [], set()
    for a in artifacts:
        r = _resolve_latest(ctx, a)
        if r.key in seen:
            continue
        seen.add(r.key)
        resolved.append(r)
    report.artifacts = resolved
    if not resolved:
        report.errors.append(f"resolved 0 artifacts from {path}")

    for a in resolved:
        _download_and_scan(ctx, a, report.errors)

    report.signals = ctx.signals
    report.fingerprints = ctx.fingerprints
    report.errors.extend(ctx.config.get("_errors", []))
    return report


def scan_manifest(ctx: ScanContext, path: str, max_depth: int = 10) -> ScanReport:
    """Scan a package.json / requirements.txt-style manifest, resolving deps."""
    from .resolvers.lockfile import parse_manifest_tree
    from .resolvers.tree import resolve_tree

    report = ScanReport()
    try:
        roots = parse_manifest_tree(path)
    except Exception as e:
        report.errors.append(f"parse {path}: {e}")
        report.signals = ctx.signals
        return report

    if not roots:
        report.errors.append(f"no dependencies found in {path}")
        report.signals = ctx.signals
        return report

    ctx.config["target_name"] = roots[0].name
    resolved_all: list[Artifact] = []
    seen: set[str] = set()
    for a in roots:
        resolved = _resolve_latest(ctx, a)
        try:
            artifacts = resolve_tree(ctx, resolved, max_depth=max_depth)
        except Exception:
            artifacts = [resolved]
        for art in artifacts:
            if art.key not in seen:
                seen.add(art.key)
                resolved_all.append(art)

    report.artifacts = resolved_all
    for art in resolved_all:
        _download_and_scan(ctx, art, report.errors)

    report.edges = build_edges(ctx, report.artifacts)
    report.signals = ctx.signals
    report.fingerprints = ctx.fingerprints
    report.errors.extend(ctx.config.get("_errors", []))
    return report


def run_forensics(ctx: ScanContext, target: str) -> dict:
    """Reconstruct and describe a (possibly yanked) version."""
    artifact = parse_target(target)
    artifact = _resolve_latest(ctx, artifact)
    info: dict = {
        "artifact": artifact.key,
        "ecosystem": artifact.ecosystem,
        "name": artifact.name,
        "version": artifact.version,
        "archived_versions": ctx.archive.releases(artifact.ecosystem, artifact.name),
    }
    if not ctx.archive.has(artifact):
        try:
            extract_dir = Path(tempfile.mkdtemp(prefix="supplicant-forensics-"))
            try:
                ctx.registry(artifact.ecosystem).download_and_extract(artifact.name, artifact.version, extract_dir)
                info["reconstructed"] = True
            finally:
                import shutil

                shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception as e:
            info["reconstructed"] = False
            info["error"] = str(e)
            return info
    else:
        info["reconstructed"] = True

    extracted = ctx.archive.get_extracted(artifact)
    files = sorted(str(p.relative_to(extracted)) for p in extracted.rglob("*") if p.is_file()) if extracted else []
    info["files"] = files
    info["file_count"] = len(files)
    return info


def run_fence(ctx: ScanContext, name: str) -> list[dict]:
    from .detect.identity import identity_for

    return identity_for(ctx, name)
