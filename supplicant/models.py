"""supplicant — supply-chain dependency forensics.

Core data model shared by every registry, resolver, detector and renderer.
Keep this module dependency-free (stdlib only) so all subagents import cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Detector kinds (stable string ids used in signals and policies)
KIND_BASELINE = "baseline_deviation"
KIND_FINGERPRINT = "fingerprint_match"
KIND_INSTALL = "install_script_network"
KIND_OBFUSCATE = "obfuscation"
KIND_NATIVE = "native_binary"
KIND_PERMS = "unexpected_permissions"
KIND_CVE = "known_vulnerability"
KIND_TYPOSQUAT = "typosquatting"
KIND_IDENTITY = "identity_fence"
KIND_ABANDONED = "abandoned"
KIND_CONFUSION = "dependency_confusion"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else -1


@dataclass(frozen=True)
class Artifact:
    """A concrete, versioned, downloadable thing."""

    ecosystem: str  # "npm" | "pypi" | "rubygems" | ...
    name: str
    version: str

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class ReleaseRecord:
    """Everything known about one published version, before any download."""

    artifact: Artifact
    published_at: Optional[str] = None
    author: Optional[str] = None
    repo_url: Optional[str] = None
    dist_url: Optional[str] = None
    dist_sha: Optional[str] = None
    dist_size: Optional[int] = None
    raw: dict = field(default_factory=dict)


@dataclass
class Signal:
    """A single structured detection finding."""

    kind: str
    artifact: Optional[Artifact]
    severity: str
    confidence: float  # 0..1
    evidence: dict = field(default_factory=dict)
    reported_by: str = "detector"
    explanation: str = ""

    @property
    def id(self) -> str:
        import hashlib

        blob = f"{self.kind}|{self.artifact.key if self.artifact else ''}|{self.reported_by}|{sorted(str(self.evidence.items()))}"
        return "sig-" + hashlib.sha1(blob.encode()).hexdigest()[:12]


@dataclass
class FileChange:
    """One file's delta in a version bump."""

    path: str
    status: str  # "added" | "modified" | "removed"
    size_before: Optional[int] = None
    size_after: Optional[int] = None
    hash_before: Optional[str] = None
    hash_after: Optional[str] = None


@dataclass
class VersionDiff:
    """Normalized file-by-file diff of two versions of one package."""

    artifact: Artifact  # the package (name + ecosystem); from/to in the fields below
    from_version: str
    to_version: str
    changes: list[FileChange] = field(default_factory=list)
    manifest_before: dict = field(default_factory=dict)
    manifest_after: dict = field(default_factory=dict)
    delta_fingerprint: Optional[str] = None

    @property
    def added(self) -> list[FileChange]:
        return [c for c in self.changes if c.status == "added"]

    @property
    def modified(self) -> list[FileChange]:
        return [c for c in self.changes if c.status == "modified"]

    @property
    def removed(self) -> list[FileChange]:
        return [c for c in self.changes if c.status == "removed"]


@dataclass
class BaselineProfile:
    """The learned 'habit' of one package across its own release history.

    Deliberately per-package: the comparative baseline is a package's own
    history, never the rest of the ecosystem.
    """

    ecosystem: str
    name: str
    num_releases: int = 0
    release_gaps_days: list[float] = field(default_factory=list)
    mean_gap_days: Optional[float] = None
    std_gap_days: Optional[float] = None
    last_gap_days: Optional[float] = None
    author_set: set[str] = field(default_factory=set)
    repo_urls: set[str] = field(default_factory=set)
    install_hooks_ever: bool = False
    binaries_ever: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}"

    def is_established(self) -> bool:
        return self.num_releases >= 3


@dataclass
class DiffOutcome:
    """Result of a version diff: the diff itself + signals that fired on it."""

    artifact: Artifact
    from_version: str
    to_version: str
    diff: Optional[VersionDiff] = None
    signals: list[Signal] = field(default_factory=list)
    baseline: Optional[BaselineProfile] = None
    verdict: str = "review"  # "ok" | "review" | "block"


@dataclass
class ScanReport:
    """Aggregated result of a scan or diff run, consumed by renderers."""

    artifacts: list[Artifact] = field(default_factory=list)
    edges: list[tuple] = field(default_factory=list)  # (parent: Artifact, child: Artifact)
    signals: list[Signal] = field(default_factory=list)
    diffs: list[DiffOutcome] = field(default_factory=list)
    fingerprints: dict = field(default_factory=dict)  # fp_id -> [artifact keys]
    errors: list[str] = field(default_factory=list)

    def signals_at_or_above(self, min_severity: str) -> list[Signal]:
        floor = severity_rank(min_severity)
        return [s for s in self.signals if severity_rank(s.severity) >= floor]
