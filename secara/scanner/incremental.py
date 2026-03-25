"""Incremental scan helpers (changed files only)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Set

from secara.scanner.file_scanner import collect_files
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


def select_shard(files: Iterable[Path], shard_index: int, shard_count: int) -> List[Path]:
    """Deterministically select files for a shard."""
    ordered = sorted(str(p.resolve()) for p in files)
    selected = [Path(p) for i, p in enumerate(ordered) if i % shard_count == shard_index]
    return selected


def collect_impacted_files(root: Path) -> List[Path]:
    """
    Return changed files plus dependents based on a basic reverse import graph.
    Covers Python and JS/TS relative import patterns.
    """
    changed = set(collect_changed_files(root))
    if not changed:
        return []

    all_files = collect_files(root)
    rev_graph = _build_reverse_dependency_graph(root, all_files)

    impacted = set(changed)
    queue = list(changed)
    while queue:
        cur = queue.pop(0)
        for dep in rev_graph.get(cur.resolve(), set()):
            if dep not in impacted:
                impacted.add(dep)
                queue.append(dep)
    return sorted(impacted)


def _build_reverse_dependency_graph(root: Path, files: List[Path]) -> Dict[Path, Set[Path]]:
    rev: Dict[Path, Set[Path]] = {}
    for f in files:
        src = f.resolve()
        for target in _extract_local_dependencies(root, f):
            rev.setdefault(target.resolve(), set()).add(src)
    return rev


def _extract_local_dependencies(root: Path, file_path: Path) -> Set[Path]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    ext = file_path.suffix.lower()
    if ext == ".py":
        return _extract_python_local_imports(root, file_path, text)
    if ext in {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}:
        return _extract_js_local_imports(root, file_path, text)
    return set()


def _extract_python_local_imports(root: Path, file_path: Path, text: str) -> Set[Path]:
    deps: Set[Path] = set()
    # import a.b / from a.b import c
    for m in re.finditer(r"(?m)^\s*import\s+([A-Za-z_][A-Za-z0-9_\.]*)", text):
        deps.update(_resolve_python_module(root, m.group(1)))
    for m in re.finditer(r"(?m)^\s*from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\s+", text):
        deps.update(_resolve_python_module(root, m.group(1)))
    # Relative imports: from .foo import bar / from ..pkg import x
    for m in re.finditer(r"(?m)^\s*from\s+(\.+)([A-Za-z_][A-Za-z0-9_\.]*)?\s+import\s+", text):
        dots = len(m.group(1))
        module = m.group(2) or ""
        base = file_path.parent
        for _ in range(max(0, dots - 1)):
            base = base.parent
        if module:
            candidate = base / (module.replace(".", "/") + ".py")
            init_candidate = base / module.replace(".", "/") / "__init__.py"
            for c in (candidate, init_candidate):
                if c.exists() and c.is_file():
                    deps.add(c.resolve())
    return deps


def _resolve_python_module(root: Path, module: str) -> Set[Path]:
    rel = module.replace(".", "/")
    candidates = [
        root / f"{rel}.py",
        root / rel / "__init__.py",
    ]
    out = set()
    for c in candidates:
        if c.exists() and c.is_file():
            out.add(c.resolve())
    return out


def _extract_js_local_imports(root: Path, file_path: Path, text: str) -> Set[Path]:
    deps: Set[Path] = set()
    patterns = [
        r"""(?m)^\s*import\s+.*?\s+from\s+['"]([^'"]+)['"]""",
        r"""(?m)^\s*import\s+['"]([^'"]+)['"]""",
        r"""require\(\s*['"]([^'"]+)['"]\s*\)""",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text):
            target = m.group(1)
            if target.startswith("."):
                deps.update(_resolve_js_module(file_path.parent, target))
    return deps


def _resolve_js_module(base_dir: Path, target: str) -> Set[Path]:
    out: Set[Path] = set()
    p = (base_dir / target).resolve()
    candidates = [p]
    if p.suffix == "":
        for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            candidates.append(Path(str(p) + ext))
        for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            candidates.append(p / f"index{ext}")
    for c in candidates:
        if c.exists() and c.is_file():
            out.add(c.resolve())
    return out
