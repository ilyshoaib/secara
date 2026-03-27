import json
from pathlib import Path

from click.testing import CliRunner

import secara.cli as cli_module
from secara.cli import cli


def test_scan_sarif_output_file_contains_fingerprint_and_confidence(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "vuln.py").write_text('token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"\n', encoding="utf-8")
    sarif_path = root / "results.sarif"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(root), "--sarif", "--output", str(sarif_path), "--no-cache"])

    assert result.exit_code == 1
    assert sarif_path.exists()

    payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    assert run["results"], "Expected at least one SARIF result"
    assert "secaraFingerprint" in run["results"][0]["fingerprints"]
    assert any("confidence:" in tag for tag in run["tool"]["driver"]["rules"][0]["properties"]["tags"])


def test_scan_json_output_writes_file(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "vuln.py").write_text('token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"\n', encoding="utf-8")
    json_path = root / "results.json"

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(root), "--json", "--output", str(json_path), "--no-cache"])

    assert result.exit_code == 1
    assert json_path.exists()
    assert "JSON results written to" in result.output
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and payload


def test_metrics_command_json_and_plain(monkeypatch):
    rows = [
        {
            "timestamp": "2026-03-25T00:00:00+00:00",
            "files_scanned": 10,
            "findings_shown": 2,
            "duration_s": 0.5,
            "policy": "strict",
        }
    ]
    monkeypatch.setattr(cli_module, "read_history", lambda _path: rows)

    runner = CliRunner()
    as_json = runner.invoke(cli, ["metrics", "--json"])
    assert as_json.exit_code == 0
    parsed = json.loads(as_json.output)
    assert parsed[0]["files_scanned"] == 10

    as_plain = runner.invoke(cli, ["metrics", "--limit", "5"])
    assert as_plain.exit_code == 0
    assert "Recent Scan Metrics:" in as_plain.output
    assert "files=10" in as_plain.output


def test_metrics_command_rules_mode():
    runner = CliRunner()
    result = runner.invoke(cli, ["metrics", "--rules"])
    assert result.exit_code == 0
    assert "Per-Rule Quality Metrics:" in result.output
    assert "SQL001" in result.output


def test_benchmark_command_plain_and_json(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")

    runner = CliRunner()
    plain = runner.invoke(cli, ["benchmark", str(root), "--runs", "2", "--warmup", "0", "--no-cache"])
    assert plain.exit_code == 0
    assert "Benchmark results:" in plain.output

    as_json = runner.invoke(
        cli,
        ["benchmark", str(root), "--runs", "2", "--warmup", "0", "--no-cache", "--json"],
    )
    assert as_json.exit_code == 0
    parsed = json.loads(as_json.output)
    assert parsed["runs"] == 2
    assert "timings_s" in parsed
