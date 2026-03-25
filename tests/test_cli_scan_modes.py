import json
import subprocess
from pathlib import Path

from click.testing import CliRunner

from secara.cli import cli


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _invoke_scan(runner: CliRunner, root: Path, *args: str):
    return runner.invoke(
        cli,
        ["scan", str(root), "--json", "--no-cache", *args],
    )


def test_scan_changed_only_scans_untracked_files(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    _write(
        root / "vuln.py",
        "def f(request, cursor):\n"
        "    x = request.args.get('id')\n"
        "    cursor.execute(\"SELECT * FROM users WHERE id='\" + x + \"'\")\n",
    )

    runner = CliRunner()
    result = _invoke_scan(runner, root, "--changed-only")
    assert result.exit_code == 1
    findings = json.loads(result.output)
    assert any(f["rule_id"] == "SQL001" for f in findings)


def test_scan_baseline_filters_existing_findings(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(
        root / "vuln.py",
        'token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"\n',
    )
    baseline = root / ".secara" / "baseline.json"

    runner = CliRunner()
    first = _invoke_scan(runner, root, "--write-baseline", str(baseline))
    assert first.exit_code == 1
    assert baseline.exists()

    second = _invoke_scan(runner, root, "--baseline", str(baseline))
    assert second.exit_code == 0
    assert json.loads(second.output) == []


def test_scan_policy_strict_filters_low_confidence_findings(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(
        root / "vuln.py",
        'blob = "Xk9mP2wQzR4nV7tY1aL8cF0jH6bN3eD5"\n',
    )
    runner = CliRunner()

    balanced = _invoke_scan(runner, root, "--policy", "balanced")
    assert balanced.exit_code == 1
    assert any(f["rule_id"] == "SEC014" for f in json.loads(balanced.output))

    strict = _invoke_scan(runner, root, "--policy", "strict")
    assert strict.exit_code == 0
    assert json.loads(strict.output) == []


def test_scan_enforce_suppression_metadata(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    _write(
        root / "vuln.py",
        "def f(request, cursor):\n"
        "    x = request.args.get('id')\n"
        "    cursor.execute(\"SELECT * FROM users WHERE id='\" + x + \"'\")  # secara: ignore[SQL001]\n",
    )
    runner = CliRunner()

    default_mode = _invoke_scan(runner, root)
    assert default_mode.exit_code == 0

    enforced = _invoke_scan(runner, root, "--enforce-suppression-metadata")
    assert enforced.exit_code == 1
    findings = json.loads(enforced.output)
    assert any(f["rule_id"] == "SQL001" for f in findings)
