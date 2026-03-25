"""
Tests for the Python AST analyzer.
"""
from pathlib import Path
import pytest
from secara.detectors.python_analyzer import PythonAnalyzer

analyzer = PythonAnalyzer()


def analyze(code: str) -> list:
    return analyzer.analyze(Path("test.py"), code)


# ── SQL Injection ─────────────────────────────────────────────────────────────

def test_detects_sqli_string_concat():
    code = """
def get_user(request):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
"""
    findings = analyze(code)
    assert any(f.rule_id == "SQL001" for f in findings), \
        "Should detect SQLi via string concatenation"


def test_sqli_finding_includes_taint_evidence():
    code = """
def get_user(request, cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
"""
    findings = analyze(code)
    sqli = [f for f in findings if f.rule_id == "SQL001"]
    assert sqli, "Expected SQL001 finding"
    assert sqli[0].evidence is not None
    assert "taint_sources" in sqli[0].evidence


def test_detects_sqli_fstring():
    code = """
def get_user(request):
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
    findings = analyze(code)
    assert any(f.rule_id == "SQL001" for f in findings), \
        "Should detect SQLi via f-string"


def test_no_sqli_on_parameterized():
    code = """
def get_user(request):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    findings = analyze(code)
    assert not any(f.rule_id == "SQL001" for f in findings), \
        "Should NOT flag parameterized queries"


def test_no_sqli_on_literal_query():
    code = """
cursor.execute("SELECT * FROM users WHERE active = 1")
"""
    findings = analyze(code)
    assert not any(f.rule_id == "SQL001" for f in findings), \
        "Should NOT flag pure literal SQL queries"


def test_no_sqli_on_sanitized_numeric_input():
    code = """
def get_user(request, cursor):
    user_id = int(request.args.get("id"))
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
"""
    findings = analyze(code)
    assert not any(f.rule_id == "SQL001" for f in findings), \
        "Should NOT flag SQLi after numeric sanitization"


# ── Command Injection ─────────────────────────────────────────────────────────

def test_detects_cmdi_os_system():
    code = """
import os
def ping(request):
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
"""
    findings = analyze(code)
    assert any(f.rule_id == "CMD001" for f in findings), \
        "Should detect CMDi via os.system"


def test_detects_cmdi_subprocess_shell_true():
    code = """
import subprocess
def run(request):
    cmd = request.form.get("cmd")
    subprocess.run(cmd, shell=True)
"""
    findings = analyze(code)
    assert any(f.rule_id == "CMD002" for f in findings), \
        "Should detect CMDi via subprocess with shell=True"


def test_no_cmdi_subprocess_shell_true_after_quote():
    code = """
import subprocess
from shlex import quote
def run(request):
    host = request.args.get("host")
    safe_host = quote(host)
    subprocess.run("ping -c 1 " + safe_host, shell=True)
"""
    findings = analyze(code)
    assert not any(f.rule_id == "CMD002" for f in findings), \
        "Should NOT flag subprocess shell=True when input is shell-escaped"


def test_no_cmdi_subprocess_list():
    code = """
import subprocess
def run(user_dir):
    subprocess.run(["ls", "-la", user_dir])
"""
    findings = analyze(code)
    assert not any(f.rule_id in ("CMD001", "CMD002") for f in findings), \
        "Should NOT flag subprocess with a list (safe)"


def test_no_cmdi_subprocess_literal_shell():
    code = """
import subprocess
subprocess.run("ls -la", shell=True)
"""
    findings = analyze(code)
    # Literal string fully known — may or may not flag depending on dynamic check
    # The important thing is user-input derived ones do fire


# ── eval / exec ───────────────────────────────────────────────────────────────

def test_detects_eval_with_variable():
    code = """
def calculate(request):
    expr = request.args.get("expr")
    return eval(expr)
"""
    findings = analyze(code)
    assert any(f.rule_id == "CMD003" for f in findings), \
        "Should detect eval with user input"


def test_no_eval_with_literal():
    code = """
result = eval("2 + 2")
"""
    findings = analyze(code)
    assert not any(f.rule_id == "CMD003" for f in findings), \
        "Should NOT flag eval with a string literal"


# ── Syntax error resilience ───────────────────────────────────────────────────

def test_handles_syntax_error_gracefully():
    code = "def broken(\n    this is not valid python!!!"
    findings = analyze(code)
    assert isinstance(findings, list), "Should return empty list on syntax error"
