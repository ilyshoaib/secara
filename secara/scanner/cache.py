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


class FileCache:
    """Persistent file-level scan cache keyed by absolute path + SHA-256 hash."""

    def __init__(self, enabled: bool = True):
        self._enabled = enabled
        self._data: dict = {}
        self._dirty: bool = False
        if self._enabled:
            self._load()

    def _load(self) -> None:
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as fh:
                    self._data = json.load(fh)
                logger.debug("Loaded cache with %d entries", len(self._data))
            except (json.JSONDecodeError, OSError) as exc:
                logger.debug("Cache load failed (%s), starting fresh", exc)
                self._data = {}

    def save(self) -> None:
        """Flush the in-memory cache to disk. Call once after a scan completes."""
        if not self._enabled or not self._dirty:
            return
        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(CACHE_FILE, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=2)
            logger.debug("Cache saved (%d entries)", len(self._data))
        except OSError as exc:
            logger.warning("Could not save cache: %s", exc)

    def get(self, file_path: Path) -> Optional[list]:
        """
        Return cached findings list if *file_path* hasn't changed, else None.
        """
        if not self._enabled:
            return None
        key = str(file_path.resolve())
        entry = self._data.get(key)
        if entry is None:
            return None
        current_sha = _compute_sha256(file_path)
        if entry.get("sha256") == current_sha:
            logger.debug("Cache hit: %s", file_path.name)
            return entry.get("findings", [])
        return None

    def set(self, file_path: Path, findings: list) -> None:
        """Store findings for *file_path* in the cache."""
        if not self._enabled:
            return
        key = str(file_path.resolve())
        self._data[key] = {
            "sha256": _compute_sha256(file_path),
            "findings": [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
        }
        self._dirty = True

    def clear(self) -> None:
        """Wipe the cache entirely."""
        self._data = {}
        self._dirty = True
        self.save()
