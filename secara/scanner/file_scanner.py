"""
File scanner: recursive directory traversal with filtering, caching, and
parallel execution. This is the entry point for all file discovery.
"""
from __future__ import annotations

import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional
import logging

logger = logging.getLogger("secara.scanner")

# ── Directories to always skip ──────────────────────────────────────────────
SKIP_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__", ".pytest_cache",
    "venv", ".venv", "env", ".env",
    "dist", "build", ".tox", ".mypy_cache",
    "vendor", "third_party", "bower_components",
    ".idea", ".vscode",
}

# ── File-size limit: skip files larger than this (bytes) ─────────────────────
MAX_FILE_BYTES = 512 * 1024  # 512 KB

# ── Extensions we care about ─────────────────────────────────────────────────
SUPPORTED_EXTENSIONS: set[str] = {
    # Tier 1
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    # Tier 2
    ".sh", ".bash", ".zsh",
    ".json", ".yaml", ".yml",
    ".go",
    ".java", ".kt", ".kts",
    ".php", ".phtml", ".php3", ".php4", ".php5",
    ".rb", ".erb", ".rake",
    # Config-style secrets
    ".env", ".ini", ".cfg", ".toml", ".conf",
}


def _is_binary(file_path: Path) -> bool:
    """Quick binary-file check by reading the first 8KB and looking for null bytes."""
    try:
        with open(file_path, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except OSError:
        return True


def _should_skip_dir(dir_name: str) -> bool:
    return dir_name in SKIP_DIRS or dir_name.startswith(".")


def collect_files(root: Path) -> List[Path]:
    """
    Walk *root* recursively and return paths of all scannable files.
    Respects SKIP_DIRS, SUPPORTED_EXTENSIONS, MAX_FILE_BYTES, and binary check.
    """
    collected: List[Path] = []

    if root.is_file():
        if _should_include_file(root):
            collected.append(root)
        return collected

    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        # Prune skipped dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            if _should_include_file(file_path):
                collected.append(file_path)

    logger.debug("Collected %d files from %s", len(collected), root)
    return collected


def _should_include_file(file_path: Path) -> bool:
    """Return True if this file should be scanned."""
    suffix = file_path.suffix.lower()

    # Extension filter — also allow extensionless files named ".env", etc.
    name_lower = file_path.name.lower()
    if suffix not in SUPPORTED_EXTENSIONS and name_lower not in {
        ".env", "dockerfile", ".envrc"
    }:
        # Still allow .env files without a proper extension match
        if not name_lower.startswith(".env"):
            return False

    # Size filter
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            logger.debug("Skipping large file: %s", file_path)
            return False
    except OSError:
        return False

    # Binary probe is relatively expensive. For known textual extensions
    # we skip this extra read and rely on decoding with replacement later.
    # Keep probe for extensionless files like Dockerfile/.envrc.
    if suffix == "" and _is_binary(file_path):
        return False

    return True


def scan_files_parallel(
    files: List[Path],
    analyze_fn: Callable[[Path], list],
    max_workers: int = 8,
) -> list:
    """
    Run *analyze_fn* on each file in parallel using a thread pool.
    Returns a flat list of all findings from all files.
    """
    all_findings: list = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(analyze_fn, fp): fp for fp in files}
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                results = future.result()
                if results:
                    all_findings.extend(results)
            except Exception as exc:
                logger.warning("Error scanning %s: %s", path, exc)

    return all_findings
