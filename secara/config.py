"""
secara.config — Project-level configuration loader.

Reads 'secara.yaml' from the current directory (or a given root).
Falls back to safe defaults if no config file is found.

Config file format:
  severity_threshold: MEDIUM
  exclude_paths:
    - "tests/**"
    - "migrations/**"
  rules:
    disable: [SEC014, CRY003]
    custom_rules_dir: ".secara/rules/"
  output:
    format: rich
    fail_on: HIGH
  policy: balanced
  workers: 8
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("secara.config")

# ── Defaults ──────────────────────────────────────────────────────────────────
_DEFAULTS: Dict[str, Any] = {
    "severity_threshold": "LOW",
    "exclude_paths": [],
    "rules": {
        "disable": [],
        "custom_rules_dir": None,
    },
    "output": {
        "format": "rich",
        "fail_on": "LOW",
    },
    "policy": "balanced",
    "workers": 8,
}


class SecaraConfig:
    """Parsed and validated Secara project configuration."""

    def __init__(self, data: Dict[str, Any]) -> None:
        self._data = data

    # ── Accessors ─────────────────────────────────────────────────────────

    @property
    def severity_threshold(self) -> str:
        return str(self._data.get("severity_threshold", _DEFAULTS["severity_threshold"])).upper()

    @property
    def exclude_paths(self) -> List[str]:
        return list(self._data.get("exclude_paths", []))

    @property
    def disabled_rules(self) -> List[str]:
        return list(self._data.get("rules", {}).get("disable", []))

    @property
    def custom_rules_dir(self) -> Optional[Path]:
        d = self._data.get("rules", {}).get("custom_rules_dir")
        return Path(d) if d else None

    @property
    def workers(self) -> int:
        return int(self._data.get("workers", _DEFAULTS["workers"]))

    @property
    def fail_on(self) -> str:
        return str(self._data.get("output", {}).get("fail_on", "LOW")).upper()

    @property
    def policy(self) -> str:
        return str(self._data.get("policy", _DEFAULTS["policy"])).lower()

    def is_rule_disabled(self, rule_id: str) -> bool:
        return rule_id in self.disabled_rules

    def is_path_excluded(self, path: Path, root: Path) -> bool:
        """Return True if the path matches any exclude_path glob."""
        try:
            rel = path.relative_to(root)
        except ValueError:
            return False
        for pattern in self.exclude_paths:
            if rel.match(pattern):
                return True
        return False


# ── Singleton loader ──────────────────────────────────────────────────────────
_config_cache: Optional[SecaraConfig] = None


def load_config(root: Optional[Path] = None) -> SecaraConfig:
    """
    Load secara.yaml from *root* (or cwd). Returns default config if not found.
    Result is cached per process — safe for parallel scanning.
    """
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    search_root = root or Path.cwd()
    candidate = search_root / "secara.yaml"

    if not candidate.exists():
        # Also try secara.yml
        candidate = search_root / "secara.yml"

    if candidate.exists():
        try:
            import yaml
            with open(candidate, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            logger.debug("Loaded config from %s", candidate)
            _config_cache = SecaraConfig(raw)
            return _config_cache
        except Exception as e:
            logger.warning("Failed to parse %s: %s — using defaults", candidate, e)

    _config_cache = SecaraConfig({})
    return _config_cache


def reset_config() -> None:
    """Reset config cache (useful for testing)."""
    global _config_cache
    _config_cache = None
