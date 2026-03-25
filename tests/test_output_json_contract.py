import json
from pathlib import Path

from click.testing import CliRunner

from secara.cli import cli


def test_scan_json_output_contract_includes_fingerprint_and_confidence(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "vuln.py").write_text(
        'token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"\n',
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(root), "--json", "--no-cache"])

    assert result.exit_code == 1

    payload = json.loads(result.output)
    assert isinstance(payload, list)
    assert payload, "Expected at least one finding"

    finding = payload[0]
    required = {
        "rule_id",
        "rule_name",
        "severity",
        "file_path",
        "line_number",
        "snippet",
        "description",
        "fix",
        "language",
        "confidence",
        "fingerprint",
    }
    assert required.issubset(finding.keys())
    assert finding["confidence"] in {"HIGH", "MEDIUM", "LOW"}
    assert isinstance(finding["fingerprint"], str)
    assert len(finding["fingerprint"]) == 40
