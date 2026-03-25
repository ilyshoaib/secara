from pathlib import Path

from click.testing import CliRunner

from secara.cli import cli


def test_scan_command_runs_without_callback_arg_mismatch(tmp_path: Path):
    target = tmp_path / "sample.py"
    target.write_text("print('ok')\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", str(tmp_path), "--json", "--no-cache"])

    # Scan may return 0 or 1 depending on findings; this test is for runtime integrity.
    assert result.exception is None
    assert result.exit_code in {0, 1}
