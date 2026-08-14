"""Typosquatting detection: edit-distance to well-known package names."""

from __future__ import annotations

from ..models import KIND_TYPOSQUAT, Signal
from ..utils import levenshtein
from .base import Detector

POPULAR: dict[str, set[str]] = {
    "npm": {
        "lodash", "express", "react", "axios", "request", "chalk", "async",
        "moment", "debug", "commander", "typescript", "webpack", "uuid",
        "semver", "mkdirp", "colors", "faker", "node-fetch", "ws",
        "body-parser", "cors", "dotenv", "electron", "next", "vue", "svelte",
        "jest", "mocha", "eslint", "prettier", "glob", "yargs", "through",
        "inherits", "minimist", "tslib",
    },
    "pypi": {
        "requests", "flask", "django", "numpy", "scipy", "pandas", "urllib3",
        "certifi", "six", "pip", "setuptools", "wheel", "click", "jinja2",
        "markupsafe", "itsdangerous", "werkzeug", "sqlalchemy", "redis",
        "celery", "boto3", "fastapi", "pydantic", "torch", "tensorflow",
        "matplotlib", "scikit-learn", "beautifulsoup4", "pyyaml",
        "cryptography",
    },
}


def _suspects(name: str, ecosystem: str) -> list[tuple[str, int]]:
    """Popular names within edit distance 1..2 of the given name. Max 5."""
    needle = name.lower()
    out: list[tuple[str, int]] = []
    for popular in POPULAR.get(ecosystem, ()) or ():
        distance = levenshtein(needle, popular.lower())
        if 0 < distance <= 2:
            out.append((popular, distance))
    out.sort(key=lambda t: (t[1], t[0]))
    return out[:5]


class TyposquatDetector(Detector):
    name = "typosquat"

    def _first_published(self, ctx, artifact) -> str | None:
        """First-publish date for the package, if the registry provides it."""
        try:
            meta = ctx.registry(artifact.ecosystem).metadata(artifact.name)
        except Exception:
            return None
        if artifact.ecosystem == "npm":
            created = (meta.get("time") or {}).get("created")
        else:
            info = meta.get("info") or {}
            created = info.get("created") or info.get("upload_time")
        return str(created)[:10] if created else None

    def scan_version(self, artifact, extract_dir, ctx) -> list[Signal]:
        # Typosquatting is meaningful for the explicitly-scanned package, not
        # for every transitive dep (a legit dep one edit away from a popular
        # name floods the report).
        target_name = ctx.config.get("target_name")
        if target_name and artifact.name != target_name:
            return []
        suspects = _suspects(artifact.name, artifact.ecosystem)
        if not suspects:
            return []

        # A long-established package is unlikely to be a typosquat; recency is
        # the discriminator the spec requires. Established names downgrade to
        # informational so benign scans can exit 0.
        established = False
        created = self._first_published(ctx, artifact)
        if created:
            try:
                from datetime import date

                age_days = (date.today() - date.fromisoformat(created)).days
                established = age_days > 180
            except ValueError:
                established = False

        signals: list[Signal] = []
        for popular, distance in suspects:
            severity = "low" if established else ("medium" if distance == 1 else "low")
            confidence = 0.4 if established else (0.7 if distance == 1 else 0.5)
            signals.append(
                Signal(
                    kind=KIND_TYPOSQUAT,
                    artifact=artifact,
                    severity=severity,
                    confidence=confidence,
                    evidence={
                        "name": artifact.name,
                        "similar_to": popular,
                        "distance": distance,
                        "first_published": created,
                    },
                    reported_by=self.name,
                    explanation=f"name {artifact.name} is edit-distance {distance} from popular package {popular}",
                )
            )
        return signals

    def scan_diff(self, version_diff, ctx) -> list[Signal]:
        return []
