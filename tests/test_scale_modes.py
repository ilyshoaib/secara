import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from secara.cli import cli
from secara.scanner.incremental import collect_impacted_files, select_shard


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_collect_impacted_files_python_reverse_dependency(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True, capture_output=True)

    _write(root / "a.py", "def source(request):\n    return request.args.get('id')\n")
    _write(root / "b.py", "from a import source\n\ndef f(request, cursor):\n    x = source(request)\n    cursor.execute(\"SELECT * FROM t WHERE id=\" + x)\n")
    _write(root / "c.py", "print('safe')\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "base"], cwd=root, check=True, capture_output=True)

    # Change only a.py so impact expansion should include b.py but not c.py.
    _write(root / "a.py", "def source(request):\n    return request.args.get('uid')\n")

    impacted = collect_impacted_files(root)
    names = {p.name for p in impacted}
    assert "a.py" in names
    assert "b.py" in names
    assert "c.py" not in names


def test_select_shard_is_deterministic(tmp_path: Path):
    files = []
    for i in range(6):
        p = tmp_path / f"f{i}.py"
        p.write_text("x=1\n", encoding="utf-8")
        files.append(p)

    shard0 = select_shard(files, shard_index=0, shard_count=2)
    shard1 = select_shard(files, shard_index=1, shard_count=2)
    assert set(shard0).isdisjoint(set(shard1))
    assert set(shard0) | set(shard1) == {f.resolve() for f in files}


def test_scan_impacted_only_and_sharding(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)

    _write(root / "a.py", "def source(request):\n    return request.args.get('id')\n")
    _write(root / "b.py", "from a import source\n\ndef f(request, cursor):\n    x = source(request)\n    cursor.execute(\"SELECT * FROM t WHERE id=\" + x)\n")
    _write(root / "c.py", "print('safe')\n")

    runner = CliRunner()

    impacted = runner.invoke(cli, ["scan", str(root), "--impacted-only", "--json", "--no-cache"])
    assert impacted.exit_code == 1
    payload = json.loads(impacted.output)
    assert any(Path(f["file_path"]).name == "b.py" for f in payload)

    shard_a = runner.invoke(
        cli,
        ["scan", str(root), "--impacted-only", "--json", "--no-cache", "--shard-index", "0", "--shard-count", "2"],
    )
    shard_b = runner.invoke(
        cli,
        ["scan", str(root), "--impacted-only", "--json", "--no-cache", "--shard-index", "1", "--shard-count", "2"],
    )
    assert shard_a.exit_code in {0, 1}
    assert shard_b.exit_code in {0, 1}

    files_a = {Path(f["file_path"]).name for f in json.loads(shard_a.output)} if shard_a.output.strip() else set()
    files_b = {Path(f["file_path"]).name for f in json.loads(shard_b.output)} if shard_b.output.strip() else set()
    assert files_a.isdisjoint(files_b)
