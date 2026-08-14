"""Parse dependency manifests/lockfiles into a flat list of Artifacts.

Supported inputs: npm package-lock.json, requirements.txt, Pipfile.lock,
poetry.lock (best-effort), and package.json (via parse_manifest_tree).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Artifact

_VERSIONS_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def parse_lockfile(path: str) -> list[Artifact]:
    """Dispatch on filename and parse into Artifacts."""
    p = Path(path)
    filename = p.name

    try:
        if filename == "package-lock.json":
            return _parse_npm_lock(p)
        if filename.endswith(".lock.json"):
            data = json.loads(p.read_text())
            if isinstance(data, dict) and ("packages" in data or "dependencies" in data):
                return _parse_npm_lock(p)
            raise ValueError(f"unsupported lockfile: {filename}")
        if filename == "requirements.txt":
            return _parse_requirements(p)
        if filename == "Pipfile.lock":
            return _parse_pipfile(p)
        if filename == "poetry.lock":
            try:
                return _parse_poetry(p.read_text())
            except Exception:
                return []
        raise ValueError(f"unsupported lockfile: {filename}")
    except ValueError:
        raise
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"failed to parse lockfile {filename}: {e}") from e


def _parse_npm_lock(p: Path) -> list[Artifact]:
    data = json.loads(p.read_text())
    out: list[Artifact] = []
    if not isinstance(data, dict):
        return out

    # modern: {"packages": {"node_modules/<name>": {"version": ...}, ...}}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, entry in packages.items():
            if not key.startswith("node_modules/"):
                continue  # skip root "" and any non-node_modules keys
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if version:
                # Nested deps look like "node_modules/a/node_modules/b": the
                # artifact name is the last node_modules component.
                name = key.rsplit("node_modules/", 1)[1]
                out.append(Artifact("npm", name, version))
        return out

    # legacy: {"dependencies": {<name>: {"version": ..., "dependencies": {...}}}}
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        return _walk_npm_deps(deps)
    return out


def _walk_npm_deps(deps: dict) -> list[Artifact]:
    out: list[Artifact] = []
    for name, entry in deps.items():
        if isinstance(entry, dict):
            version = entry.get("version")
            if version:
                out.append(Artifact("npm", name, version))
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                out.extend(_walk_npm_deps(nested))
    return out


def _parse_requirements(p: Path) -> list[Artifact]:
    out: list[Artifact] = []
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        name = re.split(r"[<>=!~;]", line, maxsplit=1)[0].strip().split("[", 1)[0].strip()
        if not name:
            continue
        if "==" in line:
            version = line.split("==", 1)[1].strip()
            # Drop environment markers ('; python_version >= ...') and pip
            # options (' --index-url ...') that trail the version.
            version = version.split(";", 1)[0].strip().split()[0] if version else ""
            if version:
                out.append(Artifact("pypi", name, version))
        else:
            out.append(Artifact("pypi", name, "latest"))
    return out


def _parse_pipfile(p: Path) -> list[Artifact]:
    data = json.loads(p.read_text())
    out: list[Artifact] = []
    if not isinstance(data, dict):
        return out
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            if not isinstance(entry, dict):
                continue
            version = str(entry.get("version") or "").removeprefix("==")
            if not version:
                version = "latest"
            out.append(Artifact("pypi", name, version))
    return out


def _parse_poetry(text: str) -> list[Artifact]:
    out: list[Artifact] = []
    for chunk in re.split(r"^\s*\[\[package\]\]\s*$", text, flags=re.MULTILINE):
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', chunk, re.MULTILINE)
        version = re.search(r'^\s*version\s*=\s*"([^"]+)"', chunk, re.MULTILINE)
        if name and version:
            out.append(Artifact("pypi", name.group(1), version.group(1)))
    return out


def parse_manifest_tree(path: str) -> list[Artifact]:
    """package.json -> flat list of npm Artifacts.

    Exact pins ("4.3.4") keep their version; ranges/wildcards become "latest"
    and are resolved by the registry at scan time.
    """
    import re as _re

    data = json.loads(Path(path).read_text())
    out: list[Artifact] = []
    if not isinstance(data, dict):
        return out
    for section in _VERSIONS_SECTIONS:
        for name, constraint in (data.get(section) or {}).items():
            constraint = str(constraint).strip()
            if _re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?", constraint):
                out.append(Artifact("npm", name, constraint))
            else:
                out.append(Artifact("npm", name, "latest"))
    return out
