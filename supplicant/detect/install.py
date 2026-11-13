"""Install-hook and network-at-install detection.

Flags conventional install hooks (preinstall/postinstall/setup.py/...) and
risky hook content: download-and-execute pipelines, raw network URLs,
child-process spawning, writes outside the package, and obfuscation.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from ..models import KIND_INSTALL, Signal
from .base import Detector

HOOK_NAMES = [
    "install.js",
    "install.sh",
    "postinstall.js",
    "postinstall.sh",
    "preinstall.js",
    "preinstall.sh",
    "postinstall",
    "preinstall",
    "prepare.js",
    "setup.py",
    "setup.cfg",
    "bootstrap.sh",
    "bootstrap",
]

NPM_SCRIPT_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublishOnly")
DIFF_SCRIPT_HOOKS = ("preinstall", "install", "postinstall")

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "nodejs.org",
    "github.com",
    "registry.yarnpkg.com",
    "unpkg.com",
}

RE_DOWNLOAD_EXEC = re.compile(
    r"(curl|wget|powershell|Invoke-WebRequest).{0,200}?"
    r"(\||>\s*(/dev/null)?\s*(sh|bash|python|node|powershell))",
    re.IGNORECASE,
)
# curl/wget -o <file> ... && sh <file> (download-then-execute, no pipe)
RE_DOWNLOAD_SAVE = re.compile(r"(curl|wget|Invoke-WebRequest).{0,120}?(-o|--output)\s+\S+", re.IGNORECASE)
RE_RUN_SAVED = re.compile(r"&&\s*(sh|bash|python|node)\s+\S+", re.IGNORECASE)
RE_URL = re.compile(r"https?://[^\s'\"]{5,}", re.IGNORECASE)
RE_SPAWN = re.compile(
    r"child_process|exec\(|execSync|spawn\(|system\(|popen|subprocess\.", re.IGNORECASE
)
# Writing to a sensitive out-of-package location: a redirect (or export/tee)
# into $HOME/~ or any sensitive path, or mkdir/install/cp into a sensitive path.
RE_REDIRECT_OUTSIDE = re.compile(
    r"(>>?|tee|Add-Content|Out-File|export).{0,60}?(\$HOME|~|/etc/|\.bashrc|\.zshrc|crontab|LaunchAgents|autorun|\.profile)",
    re.IGNORECASE,
)
RE_WRITE_OUTSIDE = re.compile(
    r"(mkdir|install|cp).{0,60}?(/etc/|\.bashrc|\.zshrc|crontab|LaunchAgents|autorun|\.profile)",
    re.IGNORECASE,
)
OBFUSCATION_MARKERS = ("eval(", "b64decode", "atob(", "base64", "hex")

# Build invocations in install scripts that are routine and not suspicious.
BUILD_TOOLS = ("node-gyp", "npm run", "npm ci", "npm install", "npx ")

# Only these hook names warrant a high-signal "newly introduced" diff finding.
# setup.cfg/setup.py/bootstrap are routine in legitimate bumps and are covered
# by content analysis in scan_version instead; setup.mjs/setup.js are JS
# loaders (the ChainDrop shape) and are flagged.
DIFF_HOOK_NAMES = {
    "install.js", "install.sh", "postinstall.js", "postinstall.sh",
    "preinstall.js", "preinstall.sh", "postinstall", "preinstall", "prepare.js",
    "setup.mjs", "setup.js",
}


def manifest_script_hooks(manifest, hook_names: tuple[str, ...] | None = None) -> dict[str, str]:
    """Return lifecycle hook name -> script text from a package.json manifest."""
    if not isinstance(manifest, dict):
        return {}
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    out: dict[str, str] = {}
    names = hook_names if hook_names is not None else NPM_SCRIPT_HOOKS
    for name in names:
        script = scripts.get(name)
        if isinstance(script, str) and script.strip():
            out[name] = script
    return out


class InstallScriptDetector(Detector):

    name = "install"

    def find_hooks(self, extract_dir: Path) -> list[tuple[str, str | bytes]]:
        """Locate install hooks under extract_dir.

        Returns (relpath, content) pairs. Content is bytes for real files and
        the raw script string for npm package.json script hooks.
        """
        hooks: list[tuple[str, str | bytes]] = []
        hook_names = {h.lower() for h in HOOK_NAMES}
        for p in sorted(extract_dir.rglob("*")):
            if not p.is_file():
                continue
            relpath = str(p.relative_to(extract_dir))
            if Path(p.name).name.lower() in hook_names:
                try:
                    hooks.append((relpath, p.read_bytes()))
                except OSError:
                    continue
        for p in sorted(extract_dir.rglob("package.json")):
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            for name in NPM_SCRIPT_HOOKS:
                script = scripts.get(name)
                if isinstance(script, str) and script.strip():
                    hooks.append((f"package.json#scripts.{name}", script))
        return hooks

    def _analyze_hook(self, relpath: str, content: str | bytes) -> list[tuple[str, str, str]]:
        """Return (severity, evidence_label, explanation) findings for a hook.

        Allowed-host URLs are recorded with severity "info" so they are visible
        as evidence ("known_host") but never emitted as signals.
        """
        data = content.encode("utf-8", errors="replace") if isinstance(content, str) else content
        text = data.decode("utf-8", errors="replace")
        # Drop full-line comments, and strip trailing JS // comments (keeping
        # "://" intact) so URLs in comments don't fire.
        clean_lines = [
            line
            for line in text.splitlines()
            if not line.lstrip().startswith(("#", "//", "<!--", "*"))
        ]
        text = "\n".join(clean_lines)
        url_text = "\n".join(re.sub(r"(?<!:)//[^\"']*$", "", line) for line in clean_lines)
        findings: list[tuple[str, str, str]] = []
        seen: set[str] = set()

        def add(severity: str, label: str, explanation: str) -> None:
            if label in seen:
                return
            seen.add(label)
            findings.append((severity, label, explanation))

        if RE_DOWNLOAD_EXEC.search(text):
            add("high", "download_and_execute", "downloads and executes code during install")
        elif RE_DOWNLOAD_SAVE.search(text) and RE_RUN_SAVED.search(text):
            add("high", "download_and_execute", "downloads a file then executes it during install")

        for url in RE_URL.findall(url_text):
            host = (urllib.parse.urlparse(url).hostname or "").lower()
            if host in ALLOWED_HOSTS:
                add("info", "known_host", f"contains network URL to allowed package host: {url}")
            else:
                add("medium", f"network_url:{url}", f"contains network URL: {url}")

        for m in RE_SPAWN.finditer(text):
            context = text[max(0, m.start() - 40):m.start() + 40]
            if any(tool in context for tool in BUILD_TOOLS):
                continue
            add("medium", "spawns_process", "spawns a child process")
            break

        if RE_REDIRECT_OUTSIDE.search(text) or RE_WRITE_OUTSIDE.search(text):
            add("medium", "writes_outside_package", "writes to files or paths outside the package")

        if sum(1 for m in OBFUSCATION_MARKERS if m in text) >= 2:
            add("medium", "obfuscated", "contains obfuscated code")

        return findings

    def scan_version(self, artifact, extract_dir: Path, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for relpath, content in self.find_hooks(extract_dir):
            for severity, pattern, explanation in self._analyze_hook(relpath, content):
                if severity == "info":
                    continue
                signals.append(
                    Signal(
                        kind=KIND_INSTALL,
                        artifact=artifact,
                        severity=severity,
                        confidence=0.85 if severity == "high" else 0.6,
                        evidence={"file": relpath, "pattern": pattern},
                        reported_by=self.name,
                        explanation=f"install hook {relpath}: {explanation}",
                    )
                )
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:  # noqa: ANN001
        signals: list[Signal] = []
        for change in version_diff.added:
            if Path(change.path).name.lower() in DIFF_HOOK_NAMES:
                signals.append(
                    Signal(
                        kind=KIND_INSTALL,
                        artifact=version_diff.artifact,
                        severity="high",
                        confidence=0.9,
                        evidence={
                            "file": change.path,
                            "added_in": f"{version_diff.from_version}->{version_diff.to_version}",
                        },
                        reported_by=self.name,
                        explanation="install hook newly introduced in this version",
                    )
                )
        before = manifest_script_hooks(getattr(version_diff, "manifest_before", None), DIFF_SCRIPT_HOOKS)
        after = manifest_script_hooks(getattr(version_diff, "manifest_after", None), DIFF_SCRIPT_HOOKS)
        for name, script in after.items():
            if before.get(name) == script:
                continue
            kind = "added" if name not in before else "changed"
            path = f"package.json#scripts.{name}"
            findings = self._analyze_hook(path, script)
            if not findings:
                severity = "high" if kind == "added" else "medium"
                findings = [
                    (
                        severity,
                        f"scripts.{name}",
                        f"package.json scripts.{name} {kind} in this version",
                    )
                ]
            for severity, pattern, explanation in findings:
                if severity == "info":
                    continue
                signals.append(
                    Signal(
                        kind=KIND_INSTALL,
                        artifact=version_diff.artifact,
                        severity=severity,
                        confidence=0.9,
                        evidence={
                            "file": path,
                            "pattern": pattern,
                            "added_in": f"{version_diff.from_version}->{version_diff.to_version}",
                        },
                        reported_by=self.name,
                        explanation=f"install hook {path}: {explanation}",
                    )
                )
        return signals
