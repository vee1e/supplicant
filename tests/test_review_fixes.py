"""Regression tests for bugs found in adversarial code review."""

from __future__ import annotations

import json

import pytest

from supplicant.detect.baseline import BaselineDetector
from supplicant.detect.fingerprint import FingerprintDetector
from supplicant.detect.perms import PermissionsDetector
from supplicant.detect.typosquat import TyposquatDetector
from supplicant.diff.engine import diff_versions
from supplicant.models import Artifact
from supplicant.pipeline import parse_target
from supplicant.resolvers.tree import _best_match, _version_tuple

from .conftest import make_context, make_tree


# --- parse_target / manifest --------------------------------------------------
def test_parse_target_scoped_names():
    assert parse_target("@scope/pkg").key == "npm:@scope/pkg@latest"
    assert parse_target("@scope/pkg@1.0.0").key == "npm:@scope/pkg@1.0.0"
    with pytest.raises(ValueError):
        parse_target("@just-a-name")


def test_scan_manifest_emits_latest_not_none(tmp_path):
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"dependencies": {"debug": "^4.0.0"}}))
    from supplicant.resolvers.lockfile import parse_manifest_tree

    artifacts = parse_manifest_tree(str(p))
    assert artifacts[0].version == "latest"


# --- baseline ----------------------------------------------------------------
def test_baseline_no_signal_for_noop_bump(tmp_path):
    ctx = make_context(tmp_path)
    profile = ctx.baseline("npm", "pkg")
    profile.num_releases = 10
    profile.mean_gap_days = 90.0
    profile.author_set = {"alice"}
    profile.repo_urls = {"https://github.com/alice/pkg"}
    profile.last_gap_days = 88.0

    before = make_tree(tmp_path / "b", {"package.json": '{"author":"alice"}'})
    after = make_tree(tmp_path / "a", {"package.json": '{"author":"alice"}'})
    diff = diff_versions(before, after, "npm", "pkg", "1.0.0", "1.0.1")
    assert BaselineDetector().scan_diff(diff, ctx) == []


# --- fingerprint obfuscation (was permanently 0) ------------------------------
def test_fingerprint_obfuscation_not_dead(tmp_path):
    before = make_tree(tmp_path / "b", {"package.json": '{"name":"p"}'})
    after = make_tree(tmp_path / "a", {
        "package.json": '{"name":"p"}',
        "evil.js": 'eval(atob("' + "QVRUQVNTS0VZ" * 20 + '"));\n',
    })
    diff = diff_versions(before, after, "npm", "p", "1.0.0", "1.0.1")
    # engine computes the canonical signature including obfuscation
    assert "obf:1" in diff.delta_fingerprint
    ctx = make_context(tmp_path)
    FingerprintDetector().scan_diff(diff, ctx)
    # the recorded signature must carry the obfuscation feature intact
    recorded = ctx.fingerprints.get(diff.delta_fingerprint, [])
    assert diff.artifact.key in recorded
    assert "obf:1" in diff.delta_fingerprint


# --- perms -------------------------------------------------------------------
def test_perms_env_example_not_flagged(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        ".env.example": "SECRET_KEY=change-me\n",
        ".env": "AWS_SECRET_ACCESS_KEY=AKIA1234\n",
    })
    sigs = PermissionsDetector().scan_version(Artifact("npm", "p", "1.0.0"), tree, ctx)
    flagged = {s.evidence.get("file") for s in sigs}
    assert ".env" in flagged
    assert ".env.example" not in flagged


def test_perms_world_writable_flagged(tmp_path):
    import os

    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {"tool": "#!/bin/sh\n"})
    os.chmod(tree / "tool", 0o777)
    sigs = PermissionsDetector().scan_version(Artifact("npm", "p", "1.0.0"), tree, ctx)
    assert any("unexpected permission" in s.explanation for s in sigs)


# --- semver ------------------------------------------------------------------
def test_version_tuple_prerelease_ordering():
    assert _version_tuple("1.2.3") > _version_tuple("1.2.3-rc.1")
    assert _version_tuple("1.0.0+build") == _version_tuple("1.0.0")


def test_range_matching():
    vers = ["1.2.0", "1.2.2", "1.5.0", "2.0.0"]
    assert _best_match(vers, "^1.2.3") == "1.5.0"
    assert _best_match(vers, ">=1.0.0 <2.0.0") == "1.5.0"
    assert _best_match(vers, "1.x") == "1.5.0"
    assert _best_match(vers, "~1.2.3") is None
    assert _best_match(vers, "1.2.3") is None  # exact pin that doesn't exist


# --- cve severity ------------------------------------------------------------
def test_cve_moderate_and_vector_parsing():
    from supplicant.detect.cve import _vuln_severity

    assert _vuln_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    vector = {"affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}
    assert _vuln_severity(vector) == "critical"  # ~9.8 under the v3 approximation
    low_vector = {"affected": [{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"}]}]}
    assert _vuln_severity(low_vector) in ("low", "medium")


# --- archive traversal -------------------------------------------------------
def test_archive_rejects_traversal(tmp_path):
    from supplicant.registries.archive import Archive

    arc = Archive(tmp_path / "arc")
    with pytest.raises(ValueError):
        arc.store_tarball(Artifact("npm", "../../../evil", "1.0.0"), tmp_path / "x")


# --- typosquat gating --------------------------------------------------------
def test_typosquat_only_for_target(tmp_path):
    ctx = make_context(tmp_path, config={"target_name": "someother"})
    sigs = TyposquatDetector().scan_version(Artifact("npm", "lodashx", "1.0.0"), tmp_path, ctx)
    assert sigs == []  # transitive dep: not the scanned target


# --- cli behaviors -----------------------------------------------------------
def test_detect_scan_kind_routing():
    from supplicant.cli import _detect_scan_kind

    assert _detect_scan_kind("yarn.lock") == "lockfile"
    assert _detect_scan_kind("weird.lock") == "lockfile"
    assert _detect_scan_kind("node_modules") == "target"
    assert _detect_scan_kind("package.json") == "manifest"


def test_cli_usage_error_exit_code():
    from supplicant.cli import main

    with pytest.raises(SystemExit) as exc:
        main(["--definitely-not-a-flag"])
    assert exc.value.code == 3


def test_diff_swaps_wrong_order(tmp_path, monkeypatch):
    from supplicant.cli import _parse_diff_pair

    # 6.0.0 given first must swap to oldest->newest
    eco, name, va, vb = _parse_diff_pair("keyv@6.0.0", "keyv@5.2.0")
    assert (va, vb) == ("5.2.0", "6.0.0")
    with pytest.raises(ValueError):
        _parse_diff_pair("keyv@latest", "keyv@6.0.0")


# --- regression: dist-info normalization must not crash wheel diffs ----------
def test_diff_file_trees_wheel_dist_info(tmp_path):
    from supplicant.diff.engine import diff_file_trees

    before = make_tree(tmp_path / "b", {
        "pkg/__init__.py": "v1\n",
        "pkg-1.0.0.dist-info/METADATA": "Name: pkg\nVersion: 1.0.0\n",
        "pkg-1.0.0.dist-info/RECORD": "a\n",
    })
    after = make_tree(tmp_path / "a", {
        "pkg/__init__.py": "v2\n",
        "pkg-1.0.1.dist-info/METADATA": "Name: pkg\nVersion: 1.0.1\n",
        "pkg-1.0.1.dist-info/RECORD": "a\n",
    })
    changes = diff_file_trees(before, after)
    # No crash; version-qualified dist-info dirs normalize to the same key.
    paths = {c.path: c.status for c in changes}
    assert "pkg/.dist-info/METADATA" not in paths  # normalized form
    assert "pkg-1.0.0.dist-info/METADATA" not in paths
    assert "pkg/__init__.py" in paths


# --- regression: fresh (uncached) download must succeed on first call ---------
def test_npm_download_first_attempt(tmp_path, monkeypatch):
    """download_and_extract must not unlink the tmp tarball before extracting."""
    import tarfile as _tarfile

    from supplicant.cache import Cache
    from supplicant.registries.archive import Archive
    from supplicant.registries.npm import NpmRegistry

    cache = Cache(tmp_path / "cache")
    archive = Archive(tmp_path / "archive")
    reg = NpmRegistry(cache, archive)

    # Build a fake tarball in the cache tmp dir the way _fetch_live_tarball would.
    tar_path = cache.root / "tmp" / "npm-fakepkg-1.0.0.tgz"
    tar_path.parent.mkdir(parents=True, exist_ok=True)
    with _tarfile.open(tar_path, "w:gz") as tf:
        info = _tarfile.TarInfo("package/index.js")
        data = b"module.exports = 1;\n"
        info.size = len(data)
        tf.addfile(info, __import__("io").BytesIO(data))

    # Simulate the fetch+archive+extract flow without network.
    reg._fetch_live_tarball = lambda name, version, dist_url: tar_path  # type: ignore[method-assign]
    reg.metadata = lambda name: {"versions": {"1.0.0": {"dist": {}}}, "time": {}}  # type: ignore[method-assign]
    dest = tmp_path / "out"
    reg.download_and_extract("fakepkg", "1.0.0", dest)
    assert (dest / "index.js").exists()


def test_diff_flags_package_json_postinstall(tmp_path):
    from supplicant.detect.install import InstallScriptDetector
    from supplicant.models import VersionDiff

    before = make_tree(tmp_path / "b", {"package.json": json.dumps({"name": "x", "scripts": {"test": "echo ok"}})})
    after = make_tree(tmp_path / "a", {"package.json": json.dumps({"name": "x", "scripts": {"test": "echo ok", "postinstall": "node lib/telemetry.js"}})})
    diff = diff_versions(before, after, "npm", "x", "1.0.0", "2.0.0")
    signals = InstallScriptDetector().scan_diff(diff, make_context(tmp_path))
    assert any("scripts.postinstall" in (s.evidence or {}).get("file", "") or "postinstall" in s.explanation for s in signals)


def test_vuln_severity_word_boundary_and_mal():
    from supplicant.detect.cve import _vuln_severity

    assert _vuln_severity({"summary": "resource exhaustion", "severity": "LOW"}) == "low"
    assert _vuln_severity({"id": "MAL-2024-1", "summary": "malicious package"}) == "critical"
    assert _vuln_severity({"summary": "remote code execution"}) == "critical"


def test_project_urls_null_does_not_crash(monkeypatch, tmp_path):
    from supplicant.cache import Cache
    from supplicant.registries.archive import Archive
    from supplicant.registries.pypi import PyPiRegistry

    cache = Cache(tmp_path / "cache")
    reg = PyPiRegistry(cache, Archive(tmp_path / "archive"))
    payload = {
        "info": {"project_urls": None, "author": "a"},
        "releases": {"1.0.0": [{"filename": "p-1.0.0.tar.gz", "url": "https://example.invalid/p.tgz", "digests": {}}]},
        "urls": [{"filename": "p-1.0.0.tar.gz", "url": "https://example.invalid/p.tgz", "digests": {}}],
    }
    reg.metadata = lambda name: payload  # type: ignore[method-assign]
    reg._version_metadata = lambda name, version: payload  # type: ignore[method-assign]
    rec = reg.release_info("p", "1.0.0")
    assert rec.artifact.version == "1.0.0"


def test_lockfile_uses_alias_package_name(tmp_path):
    from supplicant.resolvers.lockfile import parse_lockfile

    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({
        "packages": {
            "": {"name": "app"},
            "node_modules/foo": {"version": "1.0.0", "name": "evil", "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"},
        }
    }))
    arts = parse_lockfile(str(p))
    assert arts[0].name == "evil"


def test_extract_strips_setuid(tmp_path):
    import io, os, tarfile
    from supplicant.utils import extract_archive, normalize_mode

    tar_path = tmp_path / "a.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("bin/tool")
        data = b"#!/bin/sh\n"
        info.size = len(data)
        info.mode = 0o4755
        tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "out"
    extract_archive(tar_path, dest)
    mode = (dest / "bin/tool").stat().st_mode & 0o7777
    assert mode == 0o755
    assert mode & 0o4000 == 0


def test_extract_then_perms_flags_original_setuid(tmp_path):
    import io, tarfile
    from supplicant.detect.perms import PermissionsDetector
    from supplicant.models import Artifact
    from supplicant.utils import extract_archive

    tar_path = tmp_path / "a.tgz"
    with tarfile.open(tar_path, "w:gz") as tf:
        info = tarfile.TarInfo("bin/tool")
        data = b"#!/bin/sh\n"
        info.size = len(data)
        info.mode = 0o4755
        tf.addfile(info, io.BytesIO(data))
    dest = tmp_path / "out"
    extract_archive(tar_path, dest)
    # On disk the setuid bit is gone, but the detector must still fire.
    assert ((dest / "bin/tool").stat().st_mode & 0o4000) == 0
    signals = PermissionsDetector().scan_version(
        Artifact("npm", "x", "1.0.0"), dest, make_context(tmp_path)
    )
    assert any("permission" in s.explanation for s in signals)
