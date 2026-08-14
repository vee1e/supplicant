"""Unexpected permissions and shipped credential-like files.

Flags setuid/setgid or world-executable modes, and files whose name looks like
an access credential (.env, .npmrc, private keys, tokens, passwords, ...).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from ..models import Artifact, KIND_PERMS, Signal
from ._archive import archive_mode
from .base import Detector

SECRET_PATTERNS = [
    ".env",
    "id_rsa",
    "id_dsa",
    "*.pem",
    "*.key",
    ".npmrc",
    ".pypirc",
    "credentials",
    "secret",
    "token",
    "password",
    ".htpasswd",
]

# A file matching one of these names is suspicious on name alone.
STRICT_PATTERNS = {".env", ".npmrc", ".pypirc", "id_rsa", "id_dsa", ".htpasswd"}
# These match by name too, but a file legitimately named e.g. certifi/cacert.pem
# is a CA bundle, and .env.example is a template — require credential *content*
# before flagging.
CONTENT_PATTERNS = {"*.pem", "*.key", "credentials", "secret", "token", "password", ".env.*"}

# Context-aware credential patterns: 4-char markers like "sk-" or "AIza"
# match inside ordinary words ("risk-assessment"), so require real credential
# shapes (long token runs / PEM headers).
CREDENTIAL_RE = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
    re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{16,}"),
    re.compile(rb"AIza[A-Za-z0-9_-]{20,}"),
    re.compile(rb"AWS_SECRET"),
    re.compile(rb"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
)
CONTENT_SAMPLE = 8192

SETUID_BITS = 0o6000
WORLD_WRITABLE = 0o002


def _matched_pattern(path_str: str) -> str | None:
    """Return the SECRET_PATTERNS entry that matches, or None.

    Exact `.env` is strict; `.env.example`/`.env.production` variants become a
    content-gated ".env.*" pattern so common templates don't fire on name alone.
    """
    name = Path(path_str).name.lower()
    path_l = path_str.lower()
    for pat in SECRET_PATTERNS:
        p = pat.lower()
        if "*" in p:
            if fnmatch.fnmatchcase(name, p) or fnmatch.fnmatchcase(path_l, p):
                return pat
        elif p in name or p in path_l:
            if pat == ".env" and name != ".env":
                return ".env.*"
            return pat
    return None


def _has_credential_content(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            sample = f.read(CONTENT_SAMPLE)
    except OSError:
        return False
    return any(pattern.search(sample) for pattern in CREDENTIAL_RE)


def _matches_secret(path_str: str, path: Path | None = None) -> bool:
    """True when a path looks like a shipped credential.

    Strict names (.env, id_rsa, ...) flag on name alone. Content-ambiguous
    names (*.pem, *.key, secret, token, ...) additionally require a credential
    marker in the file's first 8KB, so certifi's cacert.pem doesn't fire.
    """
    pat = _matched_pattern(path_str)
    if pat is None:
        return False
    if pat in STRICT_PATTERNS:
        return True
    if pat in CONTENT_PATTERNS and path is not None:
        return _has_credential_content(path)
    return False


class PermissionsDetector(Detector):
    name = "perms"

    @staticmethod
    def _suspicious_mode(mode: int) -> bool:
        return bool(mode & SETUID_BITS) or bool(mode & WORLD_WRITABLE)

    def scan_version(self, artifact, extract_dir: Path, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for p in sorted(extract_dir.rglob("*")):
            if not p.is_file():
                continue
            try:
                mode = p.stat().st_mode
            except OSError:
                continue
            relpath = str(p.relative_to(extract_dir))
            if self._suspicious_mode(mode):
                signals.append(
                    Signal(
                        kind=KIND_PERMS,
                        artifact=artifact,
                        severity="high",
                        confidence=0.8,
                        evidence={"file": relpath, "mode": oct(mode)},
                        reported_by=self.name,
                        explanation="unexpected permission bits",
                    )
                )
            if _matches_secret(relpath, p):
                signals.append(
                    Signal(
                        kind=KIND_PERMS,
                        artifact=artifact,
                        severity="high",
                        confidence=0.9,
                        evidence={"file": relpath},
                        reported_by=self.name,
                        explanation="credential-like file shipped in package",
                    )
                )
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for change in version_diff.added:
            added_path = None
            base = ctx.archive.get_extracted(
                Artifact(
                    ecosystem=version_diff.artifact.ecosystem,
                    name=version_diff.artifact.name,
                    version=version_diff.to_version,
                )
            )
            if base is not None and (base / change.path).is_file():
                added_path = base / change.path
            if _matches_secret(change.path, added_path):
                signals.append(
                    Signal(
                        kind=KIND_PERMS,
                        artifact=version_diff.artifact,
                        severity="high",
                        confidence=0.95,
                        evidence={"file": change.path},
                        reported_by=self.name,
                        explanation="credential-like file newly introduced in this version",
                    )
                )
                continue
            mode = archive_mode(ctx, version_diff, change.path)
            if mode is not None and self._suspicious_mode(mode):
                signals.append(
                    Signal(
                        kind=KIND_PERMS,
                        artifact=version_diff.artifact,
                        severity="high",
                        confidence=0.8,
                        evidence={"file": change.path, "mode": oct(mode)},
                        reported_by=self.name,
                        explanation="unexpected permission bits on newly added file",
                    )
                )
        return signals
