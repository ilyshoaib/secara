"""
Tests for the secrets detector.
"""
from pathlib import Path
import pytest
from secara.detectors.secrets_detector import SecretsDetector

detector = SecretsDetector()


def analyze(code: str, ext: str = ".py") -> list:
    return detector.analyze(Path(f"test{ext}"), code)


# ── Named tokens ──────────────────────────────────────────────────────────────

def test_detects_aws_access_key():
    code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
    findings = analyze(code)
    assert any(f.rule_id == "SEC001" for f in findings), "Should detect AWS key"


def test_detects_github_token():
    code = 'token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"\n'
    findings = analyze(code)
    assert any(f.rule_id == "SEC002" for f in findings), "Should detect GitHub PAT"


def test_detects_google_api_key():
    code = 'key = "AIzaSyDEADBEEFabcdefg12345678901234567"\n'
    findings = analyze(code)
    assert any(f.rule_id == "SEC010" for f in findings), "Should detect Google API key"


def test_detects_private_key_header():
    code = "-----BEGIN RSA PRIVATE KEY-----\n"
    findings = analyze(code)
    assert any(f.rule_id == "SEC008" for f in findings), "Should detect private key"


# ── Keyword proximity ─────────────────────────────────────────────────────────

def test_detects_hardcoded_password():
    code = 'password = "SuperSecretPass123"\n'
    findings = analyze(code)
    assert any(f.rule_id == "SEC013" for f in findings), "Should detect hardcoded password"


def test_detects_api_key_assignment():
    code = 'api_key = "prod_live_abc123xyz456"\n'
    findings = analyze(code)
    assert any(f.rule_id == "SEC013" for f in findings), "Should detect hardcoded api_key"


# ── Placeholder detection (should NOT trigger) ────────────────────────────────

def test_ignores_placeholder_password():
    code = 'password = "your_password"\n'
    findings = analyze(code)
    rule13 = [f for f in findings if f.rule_id == "SEC013"]
    assert not rule13, "Should not flag placeholder values"


def test_ignores_empty_value():
    code = 'api_key = ""\n'
    findings = analyze(code)
    assert not findings, "Should not flag empty string"


def test_ignores_comment_line():
    code = '# password = "SomeRealPassword123"\n'
    findings = analyze(code)
    assert not findings, "Should not flag values in comments"


# ── Entropy ───────────────────────────────────────────────────────────────────

def test_detects_high_entropy_string():
    # A base64-like high entropy string
    code = 'token = "Xk9mP2wQzR4nV7tY1aL8cF0jH6bN3eD5"\n'
    findings = analyze(code)
    rule14 = [f for f in findings if f.rule_id == "SEC014"]
    assert rule14, "Should detect high-entropy string as possible secret"


def test_ignores_low_entropy_constant():
    code = 'title = "Hello World"\n'
    findings = analyze(code)
    assert not any(f.rule_id == "SEC014" for f in findings), \
        "Should not flag low-entropy regular strings"


# ── Cross-file type ───────────────────────────────────────────────────────────

def test_detects_secret_in_js_file():
    code = 'const token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7";\n'
    findings = analyze(code, ext=".js")
    assert findings, "Should detect GitHub token in JS file"


def test_detects_secret_in_env_file():
    code = "API_KEY=prod_live_5f3a1b2c4d6e7f8a\n"
    findings = analyze(code, ext=".env")
    assert findings, "Should detect secret in .env file"
