"""Unit tests for lockfile parsing, target parsing, and the pipeline verdicts."""

from __future__ import annotations

import json

from supplicant.models import Signal
from supplicant.pipeline import parse_target



def test_parse_target_variants():
    assert parse_target("lodash@4.17.21").key == "npm:lodash@4.17.21"
    assert parse_target("npm:lodash@4.17.21").key == "npm:lodash@4.17.21"
    assert parse_target("pypi:requests==2.32.3").key == "pypi:requests@2.32.3"
    assert parse_target("@scope/pkg@1.0.0").name == "@scope/pkg"
    assert parse_target("lodash").version == "latest"


def test_parse_npm_lock(tmp_path):
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app"},
            "node_modules/debug": {"version": "4.3.4"},
            "node_modules/ms": {"version": "2.1.2"},
            "node_modules/@scope/pkg": {"version": "0.1.0"},
        },
    }
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(lock))

    from supplicant.resolvers.lockfile import parse_lockfile

    artifacts = parse_lockfile(str(path))
    keys = {a.key for a in artifacts}
    assert "npm:debug@4.3.4" in keys
    assert "npm:ms@2.1.2" in keys
    assert "npm:@scope/pkg@0.1.0" in keys


def test_parse_requirements(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_text("# comment\nrequests==2.32.3\nflask>=2.0\n")
    from supplicant.resolvers.lockfile import parse_lockfile

    artifacts = parse_lockfile(str(path))
    by_name = {a.name: a.version for a in artifacts}
    assert by_name["requests"] == "2.32.3"
    assert by_name["flask"] == "latest"


def test_unsupported_lockfile_raises(tmp_path):
    path = tmp_path / "weird.lock"
    path.write_text("nope")
    from supplicant.resolvers.lockfile import parse_lockfile

    try:
        parse_lockfile(str(path))
        assert False, "should have raised"
    except ValueError:
        pass


def test_pipeline_parse_and_verdict(tmp_path):
    from supplicant.pipeline import _verdict

    assert _verdict([]) == "ok"
    assert _verdict([Signal(kind="x", artifact=None, severity="high", confidence=0.8)]) == "review"
    assert _verdict([Signal(kind="x", artifact=None, severity="critical", confidence=0.9)]) == "block"
    assert _verdict([
        Signal(kind="x", artifact=None, severity="high", confidence=0.8),
        Signal(kind="y", artifact=None, severity="medium", confidence=0.6),
    ]) == "review"
