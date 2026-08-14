"""PyPI registry adapter (pypi.org JSON API).

Fetches metadata/artifacts through the disk Cache; immutable files are stored
in the Archive so a yanked version stays reconstructable.
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

from ..cache import Cache
from ..models import Artifact, ReleaseRecord
from ..registries.base import FetchError, NotFoundError, Registry
from ..utils import extract_archive, safe_token, sha256_file

METADATA_TTL = 86400
ARTIFACT_TTL = 0  # sdist/wheel files are immutable


class PyPiRegistry(Registry):
    ecosystem = "pypi"

    def __init__(self, cache: Cache, archive) -> None:
        super().__init__(cache, archive)
        self._tmp_dir = self.cache.root / "tmp"
        self._tmp_dir.mkdir(parents=True, exist_ok=True)

    def _url(self, name: str) -> str:
        return "https://pypi.org/pypi/" + urllib.parse.quote(name, safe="") + "/json"

    # ---- metadata ----------------------------------------------------------
    def metadata(self, name: str) -> dict:
        cached = self.cache.get_json(f"pypi:meta:{name}")
        if cached is not None:
            return cached
        data = self.cache.http_get(self._url(name), ttl=METADATA_TTL)
        meta = json.loads(data)
        if not isinstance(meta, dict):
            raise ValueError(f"invalid pypi metadata for {name}")
        self.cache.put_json(f"pypi:meta:{name}", meta)
        return meta

    def versions(self, name: str) -> list[str]:
        return sorted(self.metadata(name).get("releases", {}).keys())

    @staticmethod
    def _pick_file(files: list[dict]) -> dict | None:
        """Prefer a wheel (.whl), else the sdist (.tar.gz), else any file."""
        if not files:
            return None
        clean = [f for f in files if isinstance(f, dict)]
        if not clean:
            return None
        return min(
            clean,
            key=lambda f: (
                0 if str(f.get("filename", "")).endswith(".whl")
                else 1 if str(f.get("filename", "")).endswith((".tar.gz", ".tgz"))
                else 2,
            ),
        )

    def release_info(self, name: str, version: str) -> ReleaseRecord:
        meta = self.metadata(name)
        files = meta.get("releases", {}).get(version) or []
        file = self._pick_file(files)
        if file is None:
            raise NotFoundError(f"{name}@{version} not found")
        info = meta.get("info", {})
        author = (
            info.get("author_email")
            or info.get("author")
            or info.get("maintainer")
            or None
        )
        repo = info.get("project_urls", {}).get("Source") or info.get("home_page") or None
        digests = file.get("digests") or {}
        return ReleaseRecord(
            artifact=Artifact("pypi", name, version),
            published_at=file.get("upload_time"),
            author=author,
            repo_url=repo,
            dist_url=file.get("url"),
            dist_sha=digests.get("sha256"),
            dist_size=file.get("size"),
            raw={"info": info, "file": file},
        )

    # ---- download/extract ---------------------------------------------------
    @staticmethod
    def _flatten_single_dir(dest: Path) -> None:
        from ..utils import hoist_single_dir

        hoist_single_dir(dest)

    def download_and_extract(self, name: str, version: str, dest: Path) -> Path:
        artifact = Artifact("pypi", name, version)
        tarball = self.archive.get_tarball(artifact)
        if tarball is None:
            rec = self.release_info(name, version)
            file = rec.raw.get("file", {})
            filename = safe_token(file.get("filename") or f"{name}-{version}.tar.gz")
            tmp = self._tmp_dir / filename
            data = self.cache.http_get(rec.dist_url, ttl=ARTIFACT_TTL)
            tmp.write_bytes(data)
            if rec.dist_sha:
                actual = sha256_file(tmp)
                if actual != rec.dist_sha:
                    raise FetchError(
                        f"sha256 mismatch for {name}@{version}: expected {rec.dist_sha}, got {actual}"
                    )
            self.archive.store_tarball(artifact, tmp)
            try:
                tmp.unlink(missing_ok=True)  # keep only the archived copy
            except OSError:
                pass
            tarball = self.archive.get_tarball(artifact) or tmp

        extract_archive(tarball, dest)
        self._flatten_single_dir(dest)
        self.archive.store_extracted(artifact, dest)

        try:
            rec = self.release_info(name, version)
            self.archive.record(artifact, rec.raw)
        except NotFoundError:
            # version gone from live metadata; record what we know
            self.archive.record(artifact, {"version": version})
        return dest
