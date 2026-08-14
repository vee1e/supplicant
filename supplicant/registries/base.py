"""Registry adapter interface.

A Registry knows how to: enumerate a package's version history, describe one
release (metadata only), and download+extract one version's archive. Every
concrete registry (npm, pypi, ...) implements this against a Cache and Archive.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from ..cache import Cache
from ..models import ReleaseRecord

if TYPE_CHECKING:
    from .archive import Archive


class RegistryError(Exception):
    pass


class NotFoundError(RegistryError):
    pass


class FetchError(RegistryError):
    pass


class Registry(ABC):
    ecosystem: str = ""

    def __init__(self, cache: Cache, archive: "Archive"):
        self.cache = cache
        self.archive = archive

    @abstractmethod
    def metadata(self, name: str) -> dict:
        """Full registry metadata for a package (versions, dists, times, authors)."""

    @abstractmethod
    def release_info(self, name: str, version: str) -> ReleaseRecord:
        """Describe one version from metadata, without downloading anything."""

    @abstractmethod
    def download_and_extract(self, name: str, version: str, dest: Path) -> Path:
        """Download + verify + extract one version into dest.

        Returns the path of the extracted directory (usually == dest).
        Must consult self.archive when the version is missing from the live
        registry (yanked/unpublished), and must persist to self.archive any
        newly fetched artifact so it survives future yanks.
        """

    def versions(self, name: str) -> list[str]:
        raise NotImplementedError
