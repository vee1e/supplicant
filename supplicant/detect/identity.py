"""Cross-ecosystem identity fencing.

Checks whether the same package name is owned by different parties on
different ecosystems (npm / pypi / rubygems). Also exposes ``identity_for``
for the CLI ``fence`` command.
"""

from __future__ import annotations

from ..models import KIND_IDENTITY, Signal
from .base import Detector

ECOSYSTEMS = {"npm", "pypi", "rubygems"}


def _norm(value: str) -> str:
    return value.strip().lower()


def identity_for(ctx, name: str) -> list[dict]:
    """Owner + first-publish metadata for ``name`` across every ecosystem."""
    results: list[dict] = []
    for ecosystem in sorted(ECOSYSTEMS):
        reg = ctx.registries.get(ecosystem)
        if reg is None:
            continue
        try:
            meta = reg.metadata(name)
        except Exception:
            meta = None
        if meta is None:
            results.append(
                {
                    "ecosystem": ecosystem,
                    "exists": False,
                    "owners": [],
                    "first_published": None,
                    "name": name,
                }
            )
            continue
        owners: list[str] = []
        first_published = None
        if ecosystem == "npm":
            for maintainer in meta.get("maintainers") or []:
                if isinstance(maintainer, dict) and maintainer.get("name"):
                    owners.append(str(maintainer["name"]))
            time_meta = meta.get("time") or {}
            if time_meta.get("created"):
                first_published = str(time_meta["created"])[:10]
        elif ecosystem == "pypi":
            info = meta.get("info") or {}
            email = (
                info.get("author_email")
                or info.get("author")
                or info.get("maintainer_email")
                or info.get("maintainer")
            )
            if email:
                owners.append(str(email))
            if info.get("created"):
                first_published = str(info["created"])[:10]
        elif ecosystem == "rubygems":
            info = meta.get("info") or {}
            authors = info.get("authors") or meta.get("authors")
            if authors:
                owners.append(str(authors))
        results.append(
            {
                "ecosystem": ecosystem,
                "exists": True,
                "owners": owners,
                "first_published": first_published,
                "name": name,
            }
        )
    return results


def _owner_set(identity: dict) -> set[str]:
    return {_norm(o) for o in identity.get("owners") or [] if _norm(o)}


class IdentityFenceDetector(Detector):
    name = "identity"

    def scan_version(self, artifact, extract_dir, ctx) -> list[Signal]:
        # Cross-ecosystem owner splits are meaningful for the explicitly-scanned
        # package; nearly every dual-published name has a different owner on npm
        # vs PyPI, so flagging transitive deps would make exit 0 unreachable.
        target = ctx.config.get("target_name")
        if target and artifact.name != target:
            return []
        seen = ctx.config.setdefault("identity_seen", [])
        key = f"{artifact.ecosystem}:{artifact.name}"
        if key in seen:
            return []
        identities = identity_for(ctx, artifact.name)
        registered = [i for i in identities if i.get("exists")]
        if len(registered) < 2:
            return []
        owner_sets = {i["ecosystem"]: _owner_set(i) for i in registered}
        for i in range(len(registered)):
            for j in range(i + 1, len(registered)):
                a, b = registered[i], registered[j]
                owners_a = owner_sets[a["ecosystem"]]
                owners_b = owner_sets[b["ecosystem"]]
                if not owners_a or not owners_b:
                    continue
                if owners_a.isdisjoint(owners_b):
                    seen.append(key)
                    return [
                        Signal(
                            kind=KIND_IDENTITY,
                            artifact=artifact,
                            severity="low",
                            confidence=0.5,
                            evidence={
                                "name": artifact.name,
                                "registries": [
                                    {"ecosystem": r["ecosystem"], "owners": r["owners"]}
                                    for r in registered
                                ],
                            },
                            reported_by=self.name,
                            explanation=(
                                f"same name {artifact.name} owned by different parties on "
                                + ", ".join(r["ecosystem"] for r in registered)
                                + " (identity fence)"
                            ),
                        )
                    ]
        return []

    def scan_diff(self, version_diff, ctx) -> list[Signal]:
        return []
