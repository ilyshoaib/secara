"""
Language engine: maps file extensions to the appropriate analyzer tier.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


class LanguageTier:
    TIER1 = "tier1"   # Deep AST + taint analysis
    TIER2 = "tier2"   # Basic regex detection only
    SECRETS_ONLY = "secrets"  # Just run secrets detector


# Extension → (tier, canonical_language_name)
EXTENSION_MAP: dict[str, tuple[str, str]] = {
    # Tier 1
    ".py":   (LanguageTier.TIER1, "python"),
    ".js":   (LanguageTier.TIER1, "javascript"),
    ".ts":   (LanguageTier.TIER1, "typescript"),
    ".jsx":  (LanguageTier.TIER1, "javascript"),
    ".tsx":  (LanguageTier.TIER1, "typescript"),
    ".mjs":  (LanguageTier.TIER1, "javascript"),
    ".cjs":  (LanguageTier.TIER1, "javascript"),

    # Tier 2 — Shell
    ".sh":   (LanguageTier.TIER2, "bash"),
    ".bash": (LanguageTier.TIER2, "bash"),
    ".zsh":  (LanguageTier.TIER2, "bash"),

    # Tier 2 — Config / Data
    ".json": (LanguageTier.TIER2, "json"),
    ".yaml": (LanguageTier.TIER2, "yaml"),
    ".yml":  (LanguageTier.TIER2, "yaml"),

    # Tier 2 — Go
    ".go":   (LanguageTier.TIER2, "go"),

    # Tier 2 — Java / Kotlin
    ".java": (LanguageTier.TIER2, "java"),
    ".kt":   (LanguageTier.TIER2, "kotlin"),
    ".kts":  (LanguageTier.TIER2, "kotlin"),

    # Tier 2 — PHP
    ".php":  (LanguageTier.TIER2, "php"),
    ".phtml": (LanguageTier.TIER2, "php"),
    ".php3": (LanguageTier.TIER2, "php"),
    ".php4": (LanguageTier.TIER2, "php"),
    ".php5": (LanguageTier.TIER2, "php"),

    # Tier 2 — Ruby
    ".rb":   (LanguageTier.TIER2, "ruby"),
    ".erb":  (LanguageTier.TIER2, "ruby"),
    ".rake": (LanguageTier.TIER2, "ruby"),

    # Config / Secrets-only
    ".env":  (LanguageTier.SECRETS_ONLY, "env"),
    ".ini":  (LanguageTier.SECRETS_ONLY, "ini"),
    ".cfg":  (LanguageTier.SECRETS_ONLY, "ini"),
    ".toml": (LanguageTier.SECRETS_ONLY, "toml"),
    ".conf": (LanguageTier.SECRETS_ONLY, "conf"),
}


def get_language_info(file_path: Path) -> tuple[Optional[str], Optional[str]]:
    """
    Return (tier, language) for *file_path*, or (None, None) if unsupported.
    Also handles files named '.env', '.envrc', 'Dockerfile', etc. by name.
    """
    suffix = file_path.suffix.lower()
    name_lower = file_path.name.lower()

    # Explicit name checks
    if name_lower in {".env", ".envrc"} or name_lower.startswith(".env."):
        return LanguageTier.SECRETS_ONLY, "env"

    return EXTENSION_MAP.get(suffix, (None, None))
