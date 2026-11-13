"""npm registry adapter (registry.npmjs.org + unpkg fallback).

Fetches metadata/tarballs through the disk Cache. Immutable tarballs are stored
in the Archive so a malicious/yanked version stays reconstructable.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import urllib.error
import urllib.parse
from pathlib import Path

from ..cache import Cache, _HttpGone
from ..models import Artifact, ReleaseRecord
from ..registries.base import FetchError, NotFoundError, Registry
from ..utils import extract_archive, safe_token

METADATA_TTL = 86400  # npm metadata changes rarely
TARBALL_TTL = 0  # tarballs are immutable


class NpmRegistry(Registry):
    ecosystem = "npm"

    def __init__(self, cache: Cache, archive) -> None:
        super().__init__(cache, archive)
        self._tmp_dir = self.cache.root / "tmp"
        from ..cache import _secure_mkdir
        _secure_mkdir(self._tmp_dir)

    # ---- helpers ---------------------------------------------------------
    def _url(self, name: str) -> str:
        """Registry URL for a package; scoped names (@scope/pkg) get quoted."""
        return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="")

    @staticmethod
    def _author_name(v: dict, meta: dict) -> str | None:
        """Best-effort author name from metadata maintainers or version fields."""
        maintainers = meta.get("maintainers") or v.get("maintainers")
        names = []
        for m in maintainers or []:
            if isinstance(m, dict):
                names.append(m.get("name") or m.get("email") or "")
            else:
                names.append(str(m))
        if any(names):
            return ", ".join(n for n in names if n)

        author = v.get("author")
        if isinstance(author, dict):
            return author.get("name") or author.get("email")
        if isinstance(author, str) and author.strip():
            return author.strip()
        return None

    @staticmethod
    def _repo_url(v: dict) -> str | None:
        """Normalize repository field ({url,type} or string) to a url string."""
        repo = v.get("repository")
        if isinstance(repo, dict):
            repo = repo.get("url") or repo.get("repository")
        if not isinstance(repo, str) or not repo.strip():
            return None
        url = repo.strip()
        if url.startswith("git+"):
            url = url[4:]
        return url

    # ---- metadata ----------------------------------------------------------
    def metadata(self, name: str) -> dict:
        cached = self.cache.get_json(f"npm:meta:{name}", ttl=METADATA_TTL)
        if cached is not None:
            return cached
        data = self.cache.http_get(self._url(name), ttl=METADATA_TTL)
        meta = json.loads(data)
        self.cache.put_json(f"npm:meta:{name}", meta)
        return meta

    def versions(self, name: str) -> list[str]:
        return sorted(self.metadata(name).get("versions", {}).keys())

    def release_info(self, name: str, version: str) -> ReleaseRecord:
        meta = self.metadata(name)
        v = meta.get("versions", {}).get(version)
        if v is None:
            raise NotFoundError(f"{name}@{version} not found")
        dist = v.get("dist", {})
        return ReleaseRecord(
            artifact=Artifact("npm", name, version),
            published_at=meta.get("time", {}).get(version),
            author=self._author_name(v, meta),
            repo_url=self._repo_url(v),
            dist_url=dist.get("tarball"),
            dist_sha=dist.get("shasum"),
            dist_size=dist.get("unpackedSize"),
            raw=v,
        )

    # ---- download/extract ---------------------------------------------------
    def _fetch_live_tarball(self, name: str, version: str, dist_url: str | None) -> Path | None:
        """Step 3: fetch the immutable tarball from the registry. None on 404."""
        if not dist_url:
            return None
        tmp = self._tmp_dir / f"npm-{name.replace('/', '__')}-{safe_token(version)}.tgz"
        try:
            data = self.cache.http_get(dist_url, ttl=TARBALL_TTL)
        except _HttpGone:
            return None
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError) as exc:
            raise FetchError(f"failed to fetch tarball for {name}@{version}: {exc}") from exc
        tmp.write_bytes(data)
        return tmp

    def _verify_integrity(self, dist: dict, tarball: Path) -> bool:
        """Verify the fetched tarball against npm's published checksums.

        Fails closed: if an integrity field was published but we can't verify
        it (unknown algo and no shasum), the download is rejected rather than
        silently accepted.
        """
        integrity = dist.get("integrity")  # e.g. "sha512-<base64>"
        shasum = dist.get("shasum")  # sha1 hex
        try:
            if integrity and str(integrity).startswith("sha512-"):
                _, _, expected = str(integrity).partition("-")
                digest = base64.b64encode(hashlib.sha512(tarball.read_bytes()).digest()).decode().rstrip("=")
                return digest == expected.rstrip("=")
            if shasum:
                return hashlib.sha1(tarball.read_bytes()).hexdigest() == str(shasum).lower()
            if integrity:
                return False  # published an integrity we can't verify
        except OSError:
            return False
        return True  # no checksum published at all: nothing to verify against

    def _reconstruct_unpkg(self, name: str, version: str) -> Path | None:
        """Step 4: rebuild a yanked tarball from a CDN archive listing.

        npm unpublishes malicious versions (event-stream@3.3.6, keyv@6.0.0),
        so the live registry cannot serve them. Both unpkg and jsDelivr keep
        an immutable copy of every published version; walk the file listing
        and reassemble a tar.gz. Returns a fresh tarball or None.
        """
        for base_url, meta_url in (
            ("https://unpkg.com", f"https://unpkg.com/{name}@{version}/?meta"),
            (
                "https://cdn.jsdelivr.net/npm",
                f"https://data.jsdelivr.com/v1/packages/npm/{name}@{version}",
            ),
        ):
            listing = self._fetch_listing(meta_url)
            if listing is None:
                continue
            entries = self._flatten_listing(listing)
            if not entries:
                continue
            tmp = self._tmp_dir / f"mirror-{name.replace('/', '__')}-{safe_token(version)}.tgz"
            files_written = 0
            try:
                with tarfile.open(tmp, "w:gz") as tf:
                    for fpath in entries:
                        try:
                            fbytes = self.cache.http_get(
                                f"{base_url}/{name}@{version}/{fpath}", ttl=TARBALL_TTL
                            )
                        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError, ValueError):
                            continue
                        info = tarfile.TarInfo("package/" + fpath)
                        info.size = len(fbytes)
                        tf.addfile(info, io.BytesIO(fbytes))
                        files_written += 1
            finally:
                if files_written == 0:
                    try:
                        tmp.unlink(missing_ok=True)
                    except OSError:
                        pass
            if files_written > 0:
                return tmp
        return None

    def _fetch_listing(self, meta_url: str) -> list | None:
        try:
            data = self.cache.http_get(meta_url, ttl=86400)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, TimeoutError, ValueError):
            return None
        try:
            listing = json.loads(data)
        except (ValueError, TypeError):
            return None
        return listing

    @staticmethod
    def _flatten_listing(listing) -> list[str]:
        """Flatten a file-tree listing into relative file paths.

        Handles unpkg's flat {"files":[{"path","type"}]} shape (paths carry a
        leading "/") and jsDelivr's nested {"files":[{"name","type","files":[...]}]}
        shape. Entries that would escape (..) or contain empty components are
        dropped.
        """
        out: list[str] = []

        def walk(entries, prefix: str) -> None:
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("path") or entry.get("name")
                if not name:
                    continue
                name = str(name).lstrip("/")
                if not name or ".." in name.split("/") or "\\" in name:
                    continue
                if entry.get("type") == "directory":
                    nested = entry.get("files") or []
                    walk(nested, prefix + name.rstrip("/") + "/")
                    continue
                out.append(prefix + name)

        if isinstance(listing, dict):
            root = listing.get("files")
            if isinstance(root, list):
                walk(root, "")
                return out
            # jsDelivr sometimes nests the file list at top-level keys: only
            # walk a dict whose "type" marks it as a container.
            if not out and listing.get("type") in ("package", "directory"):
                walk([listing], "")
        return out

    @staticmethod
    def _flatten(dest: Path) -> None:
        from ..utils import hoist_single_dir

        hoist_single_dir(dest)

    def download_and_extract(self, name: str, version: str, dest: Path) -> Path:
        artifact = Artifact("npm", name, version)
        meta = self.metadata(name)
        v = meta.get("versions", {}).get(version) or {}
        dist = v.get("dist", {}) if isinstance(v, dict) else {}

        # 1) archived copy wins (survives yanks) if its digest still matches.
        expected = None
        try:
            expected = (self.archive.read_record(artifact) or {}).get("supplicant_sha256")
        except Exception:
            expected = None
        tarball = self.archive.get_tarball(artifact, expected_sha256=expected)
        from_archive = tarball is not None
        from_cdn = False
        if from_archive and dist and not self._verify_integrity(dist, tarball):
            tarball = None
            from_archive = False
        # 2) live registry tarball
        if tarball is None:
            tarball = self._fetch_live_tarball(name, version, dist.get("tarball"))
            if tarball is not None and not self._verify_integrity(dist, tarball):
                # Bad cached bytes would otherwise be reused forever (TTL 0).
                if dist.get("tarball"):
                    self.cache.delete_blob(f"http:{dist.get('tarball')}")
                try:
                    tarball.unlink(missing_ok=True)
                except OSError:
                    pass
                raise FetchError(f"integrity check failed for {name}@{version}")
        # 3) CDN reconstruction only when the version is truly absent.
        if tarball is None:
            version_missing = not (isinstance(v, dict) and v)
            if not version_missing:
                raise FetchError(
                    f"{name}@{version} has registry metadata but the tarball could not be fetched"
                )
            tarball = self._reconstruct_unpkg(name, version)
            from_cdn = tarball is not None
        if tarball is None:
            raise NotFoundError(
                f"{name}@{version} not found in the registry, unpkg, or jsDelivr archives"
            )

        # Extract BEFORE deleting the tmp copy; then keep only the archived one.
        extract_archive(tarball, dest)
        digest = None
        if not from_archive and not from_cdn:
            stored = self.archive.store_tarball(artifact, tarball)
            from ..utils import sha256_file
            digest = sha256_file(stored)
            try:
                tarball.unlink(missing_ok=True)  # keep only the archived copy
            except OSError:
                pass
        self._flatten(dest)
        self.archive.store_extracted(artifact, dest)

        record = {"version": version}
        if isinstance(v, dict):
            record.update(v)
            record["dist"] = record.get("dist") or dist
        digest = digest or (self.archive.read_record(artifact) or {}).get("supplicant_sha256")
        if digest:
            record["supplicant_sha256"] = digest
        self.archive.record(artifact, record)
        return dest
