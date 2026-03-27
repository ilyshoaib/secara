"""
SHA-256-based file cache to avoid reprocessing unchanged files.
Cache is stored at: ~/.secara/cache.json

Format:
{
  "/abs/path/to/file.py": {
    "sha256": "abc123...",
    "findings": [ ... serialized Finding dicts ... ]
  },
  ...
}
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger("secara.cache")

CACHE_DIR = Path.home() / ".secara"
CACHE_FILE = CACHE_DIR / "cache.json"


def _compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_cache_file() -> Path:
    """
    Pick a writable cache file path.
    Priority: $SECARA_CACHE_FILE -> ~/.secara/cache.json -> ./.secara/cache.json -> /tmp
    """
    env_file = os.environ.get("SECARA_CACHE_FILE")
    candidates = []
    if env_file:
        candidates.append(Path(env_file).expanduser())
    candidates.extend(
        [
            CACHE_FILE,
            Path.cwd() / ".secara" / "cache.json",
            Path("/tmp") / f"secara-cache-{os.getuid()}.json",
        ]
    )

    for candidate in candidates:
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            with open(candidate, "a", encoding="utf-8"):
                pass
            return candidate
        except OSError:
            continue
    return candidates[-1]


class FileCache:
    """Persistent file-level scan cache keyed by absolute path + SHA-256 hash."""

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._data: dict = {}
        self._dirty: bool = False
        self._lock = threading.Lock()
        self._cache_file = _resolve_cache_file()
        self._hits: int = 0
        self._misses: int = 0
        self._sets: int = 0
        if self._enabled:
            self._load()

    def _load(self) -> None:
        if self._cache_file.exists():
            try:
                with open(self._cache_file, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                if isinstance(loaded, dict):
                    self._data = loaded
                else:
                    self._data = {}
                logger.debug("Loaded cache with %d entries", len(self._data))
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Cache load failed (%s), starting fresh", exc)
                self._data = {}

    def save(self) -> None:
        """Flush the in-memory cache to disk. Call once after a scan completes."""
        if not self._enabled or not self._dirty:
            return
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                snapshot = dict(self._data)
            with open(self._cache_file, "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh, indent=2)
            logger.debug("Cache saved (%d entries)", len(self._data))
        except OSError as exc:
            logger.warning("Could not save cache: %s", exc)

    def get(
        self,
        file_path: Path,
        *,
        file_hash: str | None = None,
        stat_result: os.stat_result | None = None,
    ) -> Optional[list]:
        """
        Return cached findings list if *file_path* hasn't changed, else None.
        Fast path uses mtime+size; optional SHA-256 check validates content identity.
        """
        if not self._enabled:
            return None
        key = str(file_path.resolve())
        with self._lock:
            entry = self._data.get(key)
        if entry is None:
            with self._lock:
                self._misses += 1
            return None

        try:
            st = stat_result or file_path.stat()
        except OSError:
            with self._lock:
                self._misses += 1
            return None

        if (
            entry.get("size") == st.st_size
            and entry.get("mtime_ns") == st.st_mtime_ns
        ):
            logger.debug("Cache hit: %s", file_path.name)
            with self._lock:
                self._hits += 1
            return entry.get("findings", [])

        # Optional stronger identity check for mtime changes without content changes.
        if file_hash is not None and entry.get("sha256") == file_hash:
            logger.debug("Cache hit (sha): %s", file_path.name)
            with self._lock:
                self._hits += 1
            return entry.get("findings", [])
        with self._lock:
            self._misses += 1
        return None

    def set(
        self,
        file_path: Path,
        findings: list,
        *,
        file_hash: str | None = None,
        stat_result: os.stat_result | None = None,
    ) -> None:
        """Store findings for *file_path* in the cache."""
        if not self._enabled:
            return
        try:
            st = stat_result or file_path.stat()
        except OSError:
            return
        key = str(file_path.resolve())
        with self._lock:
            self._data[key] = {
                "sha256": file_hash or _compute_sha256(file_path),
                "size": st.st_size,
                "mtime_ns": st.st_mtime_ns,
                "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
            }
            self._dirty = True
            self._sets += 1

    def clear(self) -> None:
        """Wipe the cache entirely."""
        with self._lock:
            self._data = {}
            self._dirty = True
        self.save()

    def stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self._enabled,
                "entries": len(self._data),
                "hits": self._hits,
                "misses": self._misses,
                "sets": self._sets,
            }
