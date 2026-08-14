"""Unit tests for baseline + fingerprint detectors (the core novel signals)."""

from __future__ import annotations

from supplicant.detect.baseline import BaselineDetector, warm_from_metadata
from supplicant.detect.fingerprint import FingerprintDetector, delta_signature
from supplicant.diff.engine import diff_versions
from supplicant.models import Artifact, FileChange, VersionDiff

from .conftest import make_context, make_tree

MANIFEST_BEFORE = {
    "name": "pkg",
    "version": "1.0.0",
    "author": "alice",
    "repository": {"url": "https://github.com/alice/pkg"},
    "dependencies": {},
}
MANIFEST_AFTER = {
    "name": "pkg",
    "version": "1.0.1",
    "author": "alice",
    "repository": {"url": "https://github.com/alice/pkg"},
    "dependencies": {"newdep": "1.0.0"},
}


def _worm_diff(tmp_path, author="alice"):
    before = make_tree(tmp_path / "before", {
        "package.json": '{"name":"pkg","version":"1.0.0","author":"alice","repository":{"url":"https://github.com/alice/pkg"},"dependencies":{}}',
        "index.js": "ok\n",
    })
    after = make_tree(tmp_path / "after", {
        "package.json": f'{{"name":"pkg","version":"1.0.1","author":"{author}","repository":{{"url":"https://github.com/alice/pkg"}},"dependencies":{{"newdep":"1.0.0"}},"scripts":{{"preinstall":"node setup.mjs"}}}}',
        "index.js": "ok\n",
        "setup.mjs": "eval(atob('QVRUQUNL'));\n",
        "Math_Symbol.js": bytes([0] * 600000),
    })
    return diff_versions(before, after, "npm", "pkg", "1.0.0", "1.0.1")


def test_baseline_flags_cadence_and_shape(tmp_path):
    ctx = make_context(tmp_path)
    profile = ctx.baseline("npm", "pkg")
    profile.num_releases = 10
    profile.mean_gap_days = 90.0
    profile.std_gap_days = 20.0
    profile.author_set = {"alice"}
    profile.repo_urls = {"https://github.com/alice/pkg"}
    profile.last_gap_days = 0.01  # hours after previous release
    profile.install_hooks_ever = False

    diff = _worm_diff(tmp_path)
    sigs = BaselineDetector().scan_diff(diff, ctx)
    assert len(sigs) == 1
    assert sigs[0].severity in ("critical", "high")
    assert "install hook" in sigs[0].explanation


def test_baseline_requires_history(tmp_path):
    ctx = make_context(tmp_path)
    diff = _worm_diff(tmp_path)
    sigs = BaselineDetector().scan_diff(diff, ctx)  # profile not established
    assert sigs == []


def test_baseline_warm_from_metadata(tmp_path):
    ctx = make_context(tmp_path)
    metadata = {
        "versions": {"1.0.0": {}, "1.0.1": {}, "1.0.2": {}},
        "time": {"1.0.0": "2020-01-01T00:00:00Z", "1.0.1": "2020-04-01T00:00:00Z", "1.0.2": "2020-07-01T00:00:00Z"},
        "maintainers": [{"name": "alice"}],
        "repository": {"url": "https://github.com/alice/pkg"},
    }
    warm_from_metadata(ctx, "npm", "pkg", metadata)
    p = ctx.baseline("npm", "pkg")
    assert p.num_releases == 3
    assert p.mean_gap_days == 91.0  # 90-91 day gaps
    assert "alice" in p.author_set


def test_fingerprint_clusters_worm_across_packages(tmp_path):
    ctx = make_context(tmp_path)
    det = FingerprintDetector()
    results = []
    for name in ("pkg-a", "pkg-b", "pkg-c"):
        before = make_tree(tmp_path / f"{name}-before", {
            "package.json": f'{{"name":"{name}","version":"1.0.0","author":"alice"}}',
            "index.js": "ok\n",
        })
        after = make_tree(tmp_path / f"{name}-after", {
            "package.json": f'{{"name":"{name}","version":"1.0.1","author":"alice"}}',
            "index.js": "ok\n",
            "setup.mjs": "eval(atob('QVRUQUNL'));\n",
        })
        diff = diff_versions(before, after, "npm", name, "1.0.0", "1.0.1")
        results.extend(det.scan_diff(diff, ctx))

    severities = [s.severity for s in results]
    assert "critical" in severities  # third package sees a 3-package worm signature
    fp_keys = list(ctx.fingerprints.keys())
    assert len(fp_keys) == 1
    assert len(ctx.fingerprints[fp_keys[0]]) == 3


def test_delta_signature_stable():
    vd = VersionDiff(
        artifact=Artifact("npm", "p", "2.0.0"),
        from_version="1.0.0",
        to_version="2.0.0",
        changes=[
            FileChange(path="install.js", status="added", size_after=1000),
            FileChange(path="package.json", status="modified", size_before=100, size_after=200),
        ],
        manifest_before={"author": "a"},
        manifest_after={"author": "a"},
    )
    sig = delta_signature(vd)
    assert sig.startswith("hooks:+1/-0")
    assert "bins:+0" in sig
    assert "author:+0" in sig
