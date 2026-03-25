"""Incremental scan helpers (changed files only)."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Set

from secara.scanner.file_scanner import _should_include_file


def _git_output(root: Path, args: list[str]) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]


def collect_changed_files(root: Path) -> List[Path]:
    """
    Return scannable changed/untracked files under *root* using git.
    Includes staged, unstaged, and untracked files.
    """
    diff_files = _git_output(root, ["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD"])
    untracked = _git_output(root, ["ls-files", "--others", "--exclude-standard"])
    paths: Set[Path] = set()
    for rel in diff_files + untracked:
        p = (root / rel).resolve()
        if p.exists() and p.is_file() and _should_include_file(p):
            paths.add(p)
    return sorted(paths)
