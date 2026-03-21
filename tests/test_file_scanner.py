"""
Tests for the file scanner (traversal, filtering).
"""
import os
import tempfile
from pathlib import Path
import pytest
from secara.scanner.file_scanner import collect_files


def make_file(base: Path, relative: str, content: str = "x = 1\n") -> Path:
    p = base / relative
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_collects_python_files():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "app.py")
        make_file(base, "utils.py")
        files = collect_files(base)
        names = [f.name for f in files]
        assert "app.py" in names
        assert "utils.py" in names


def test_skips_git_directory():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "app.py")
        make_file(base, ".git/config", "[core]")
        files = collect_files(base)
        paths = [str(f) for f in files]
        assert not any(".git" in p for p in paths), "Should skip .git directory"


def test_skips_node_modules():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "index.js")
        make_file(base, "node_modules/lodash/lodash.js", "// minified")
        files = collect_files(base)
        paths = [str(f) for f in files]
        assert not any("node_modules" in p for p in paths)


def test_skips_venv():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "app.py")
        make_file(base, "venv/lib/python3.10/site.py")
        files = collect_files(base)
        paths = [str(f) for f in files]
        assert not any("venv" in p for p in paths)


def test_skips_large_files():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        # Create a file larger than 512KB
        large = base / "large.py"
        large.write_bytes(b"x = 1\n" * 100_000)
        files = collect_files(base)
        assert large not in files, "Should skip files > 512KB"


def test_skips_unsupported_extensions():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "image.png", "PNGDATA")
        make_file(base, "doc.pdf", "PDFDATA")
        make_file(base, "app.py")
        files = collect_files(base)
        names = [f.name for f in files]
        assert "image.png" not in names
        assert "doc.pdf" not in names
        assert "app.py" in names


def test_scans_single_file():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        f = make_file(base, "script.py")
        files = collect_files(f)
        assert len(files) == 1
        assert files[0].name == "script.py"


def test_collects_js_ts_yaml():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        make_file(base, "app.js")
        make_file(base, "config.ts")
        make_file(base, "docker-compose.yaml")
        files = collect_files(base)
        names = [f.name for f in files]
        assert "app.js" in names
        assert "config.ts" in names
        assert "docker-compose.yaml" in names
