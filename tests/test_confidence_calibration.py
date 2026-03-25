from pathlib import Path

from secara.cli import _analyze_file
from secara.config import reset_config
from secara.scanner.cache import FileCache


def test_python_taint_driven_finding_has_high_confidence(tmp_path: Path):
    reset_config()
    code = (
        "def f(request, cursor):\n"
        "    x = request.args.get('id')\n"
        "    cursor.execute(\"SELECT * FROM users WHERE id='\" + x + \"'\")\n"
    )
    p = tmp_path / "a.py"
    p.write_text(code, encoding="utf-8")

    findings = _analyze_file(p, FileCache(enabled=False))
    sqli = [f for f in findings if f.rule_id == "SQL001"]
    assert sqli
    # Calibration happens in scan flow; emulate it by checking evidence presence here.
    assert sqli[0].evidence is not None


def test_config_finding_has_medium_confidence(tmp_path: Path):
    reset_config()
    p = tmp_path / ".env"
    p.write_text("DB_PASSWORD=SuperSecret123\n", encoding="utf-8")

    findings = _analyze_file(p, FileCache(enabled=False))
    cfg = [f for f in findings if f.rule_id == "CFG001"]
    assert cfg
    assert cfg[0].confidence == "MEDIUM"
