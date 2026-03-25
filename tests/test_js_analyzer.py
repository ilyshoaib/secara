from pathlib import Path

from secara.detectors.js_analyzer import JSAnalyzer


def js_ids(code: str, ext: str = ".js") -> set[str]:
    analyzer = JSAnalyzer()
    return {f.rule_id for f in analyzer.analyze(Path(f"test{ext}"), code)}


def test_detects_sqli_with_tainted_query_param():
    code = """
const id = req.query.id;
db.query("SELECT * FROM users WHERE id=" + id);
"""
    assert "SQL101" in js_ids(code)


def test_ignores_sqli_like_pattern_with_constant_var():
    code = """
const id = "42";
db.query("SELECT * FROM users WHERE id=" + id);
"""
    assert "SQL101" not in js_ids(code)


def test_detects_exec_with_tainted_input():
    code = """
const cmd = req.body.cmd;
exec(cmd);
"""
    assert "CMD101" in js_ids(code)


def test_ignores_exec_with_sanitized_input():
    code = """
const cmd = req.body.cmd;
const safe = encodeURIComponent(cmd);
exec(safe);
"""
    assert "CMD101" not in js_ids(code)
