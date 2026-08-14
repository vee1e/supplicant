"""Content-addressed disk cache + cached HTTP GET.

Network policy: this is the ONLY module that touches the network for
registries. Everything downstream talks to the cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

DEFAULT_ROOT = Path.home() / ".cache" / "supplicant"
UA = "supplicant/0.1 (+https://github.com/supplicant)"


class Cache:
    def __init__(self, root: Path = DEFAULT_ROOT):
        self.root = Path(root)
        self.blobs = self.root / "blobs"
        self.meta = self.root / "meta"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.meta.mkdir(parents=True, exist_ok=True)

    # ---- generic key/value blobs --------------------------------------
    def _blob_path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.blobs / digest[:2] / digest

    def get_blob(self, key: str) -> Optional[bytes]:
        p = self._blob_path(key)
        if p.exists():
            try:
                return p.read_bytes()
            except OSError:
                return None
        return None

    def put_blob(self, key: str, data: bytes) -> Path:
        p = self._blob_path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + f".{time.time_ns()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        return p

    # ---- metadata (small JSON, keyed by e.g. registry:name) ------------
    def get_json(self, key: str) -> Optional[dict]:
        data = self.get_blob(f"json:{key}")
        if data is None:
            return None
        try:
            return json.loads(data)
        except (ValueError, TypeError):
            return None

    def put_json(self, key: str, value: dict) -> None:
        self.put_blob(f"json:{key}", json.dumps(value, sort_keys=True).encode())

    # ---- HTTP -----------------------------------------------------------
    def http_get(self, url: str, timeout: int = 30, retries: int = 2, ttl: int = 3600) -> bytes:
        """GET with disk caching. ttl<=0 disables freshness checks (immutable).

        On a transient network failure a stale-but-usable cached copy is
        served instead of raising. A hard 4xx raises _HttpGone unless a cached
        copy exists, in which case the stale copy is served (registry metadata
        for yanked versions may linger until evicted by a revalidate).
        """
        key = f"http:{url}"
        cached = self.get_blob(key)
        meta = self.get_json(f"httpmeta:{url}")
        if cached is not None:
            fresh = meta is not None and (ttl <= 0 or (time.time() - meta.get("ts", 0)) < ttl)
            if fresh:
                return cached
        try:
            data = self._do_get(url, timeout, retries)
        except _HttpGone as e:
            # Permanently missing (404/410): don't retry, don't cache.
            if cached is not None:
                return cached
            raise e
        except Exception:
            # Transient failure: fall back to stale bytes if we have them.
            if cached is not None:
                return cached
            raise
        self.put_blob(key, data)
        self.put_json(f"httpmeta:{url}", {"ts": time.time()})
        return data

    @staticmethod
    def _do_get(url: str, timeout: int, retries: int) -> bytes:
        last: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json, */*"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                if e.code in (404, 410):
                    raise _HttpGone(url) from e
                last = e
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = e
            if attempt < retries:
                time.sleep(0.5 * (attempt + 1))
        raise last if last else RuntimeError(f"failed to fetch {url}")


class _HttpGone(urllib.error.HTTPError):
    """Permanent 404/410 for a URL: nothing to retry.

    Fully initializes the HTTPError base so str()/e.reason work in error
    formatting paths. Subclassing HTTPError keeps existing registry code that
    catches HTTPError (treating it as "missing from the live registry")
    working unchanged.
    """

    def __init__(self, url: str) -> None:
        urllib.error.HTTPError.__init__(self, url, 404, "Not Found", {}, None)
        self.url = url
