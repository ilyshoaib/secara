from pathlib import Path

from secara.detectors.python_analyzer import PythonAnalyzer
from secara.detectors.secrets_detector import SecretsDetector


def test_python_sqli_does_not_flag_constant_query_variable():
    analyzer = PythonAnalyzer()
    code = """
def list_users(cursor):
    query = "SELECT * FROM users WHERE active = 1"
    cursor.execute(query)
"""
    findings = analyzer.analyze(Path("safe.py"), code)
    assert not any(f.rule_id == "SQL001" for f in findings)


def test_secrets_detector_ignores_env_reference_assignment():
    detector = SecretsDetector()
    code = 'api_key = process.env.API_KEY\n'
    findings = detector.analyze(Path("safe.js"), code)
    assert not any(f.rule_id == "SEC013" for f in findings)


def test_secrets_detector_ignores_uppercase_env_pointer():
    detector = SecretsDetector()
    code = "TOKEN=SERVICE_API_TOKEN\n"
    findings = detector.analyze(Path("safe.env"), code)
    assert not any(f.rule_id == "SEC013" for f in findings)
