"""
Extended tests for Python analyzer — all new OWASP v0.2 detections.
"""
from pathlib import Path
import pytest
from secara.detectors.python_analyzer import PythonAnalyzer

analyzer = PythonAnalyzer()


def analyze(code: str) -> list:
    return analyzer.analyze(Path("test.py"), code)


def rule_ids(code: str) -> set:
    return {f.rule_id for f in analyze(code)}


# ── Weak Cryptography [CRY001] ────────────────────────────────────────────────

def test_detects_hashlib_md5():
    code = "import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n"
    assert "CRY001" in rule_ids(code)


def test_detects_hashlib_sha1():
    code = "import hashlib\nhashed = hashlib.sha1(data).hexdigest()\n"
    assert "CRY001" in rule_ids(code)


def test_detects_hashlib_new_md5():
    code = "import hashlib\nh = hashlib.new('md5')\n"
    assert "CRY001" in rule_ids(code)


def test_no_flag_hashlib_sha256():
    code = "import hashlib\nhashed = hashlib.sha256(data).hexdigest()\n"
    assert "CRY001" not in rule_ids(code)


# ── Insecure SSL [CRY002] ─────────────────────────────────────────────────────

def test_detects_verify_false():
    code = """
def fetch(url):
    import requests
    return requests.get(url, verify=False)
"""
    assert "CRY002" in rule_ids(code)


def test_no_flag_verify_true():
    code = """
def fetch(url):
    import requests
    return requests.get(url, verify=True)
"""
    assert "CRY002" not in rule_ids(code)


def test_no_flag_verify_default():
    code = """
import requests
requests.get('https://example.com')
"""
    assert "CRY002" not in rule_ids(code)


# ── Insecure PRNG [CRY003] ────────────────────────────────────────────────────

def test_detects_random_random():
    code = "import random\ntoken = random.random()\n"
    assert "CRY003" in rule_ids(code)


def test_detects_random_randint():
    code = "import random\notp = random.randint(100000, 999999)\n"
    assert "CRY003" in rule_ids(code)


def test_no_flag_secrets_module():
    code = "import secrets\ntoken = secrets.token_hex(32)\n"
    assert "CRY003" not in rule_ids(code)


# ── SSRF [SSRF001] ────────────────────────────────────────────────────────────

def test_detects_ssrf_requests_get():
    code = """
def proxy(request):
    url = request.args.get('url')
    import requests
    return requests.get(url)
"""
    assert "SSRF001" in rule_ids(code)


def test_detects_ssrf_requests_post():
    code = """
def webhook(request):
    target = request.form.get('target')
    import requests
    return requests.post(target, json={})
"""
    assert "SSRF001" in rule_ids(code)


def test_no_ssrf_literal_url():
    code = """
import requests
requests.get('https://api.example.com/data')
"""
    assert "SSRF001" not in rule_ids(code)


# ── Insecure Deserialization [DSER001] ────────────────────────────────────────

def test_detects_pickle_loads():
    code = "import pickle\nobj = pickle.loads(data)\n"
    assert "DSER001" in rule_ids(code)


def test_detects_pickle_load():
    code = "import pickle\nwith open('f', 'rb') as f: obj = pickle.load(f)\n"
    assert "DSER001" in rule_ids(code)


def test_detects_marshal_loads():
    code = "import marshal\nobj = marshal.loads(raw_data)\n"
    assert "DSER002" in rule_ids(code)


# ── yaml.load without SafeLoader [DSER004] ───────────────────────────────────

def test_detects_yaml_load_no_loader():
    code = """
import yaml
with open('config.yaml') as f:
    data = yaml.load(f)
"""
    assert "DSER004" in rule_ids(code)


def test_no_flag_yaml_safe_load():
    code = """
import yaml
data = yaml.safe_load(content)
"""
    assert "DSER004" not in rule_ids(code)


def test_no_flag_yaml_load_with_safeloader():
    code = """
import yaml
data = yaml.load(content, Loader=yaml.SafeLoader)
"""
    assert "DSER004" not in rule_ids(code)


# ── Path Traversal [PATH001] ──────────────────────────────────────────────────

def test_detects_path_traversal_open():
    code = """
def read(request):
    filename = request.args.get('file')
    with open(filename) as f:
        return f.read()
"""
    assert "PATH001" in rule_ids(code)


def test_no_path_traversal_literal():
    code = "with open('config.txt') as f: data = f.read()\n"
    assert "PATH001" not in rule_ids(code)


# ── SSTI [SSTI001] ────────────────────────────────────────────────────────────

def test_detects_ssti_render_template_string():
    code = """
from flask import render_template_string
def page(request):
    name = request.args.get('name')
    return render_template_string(f'Hello {name}!')
"""
    # f-string with tainted name passed to rts
    findings = analyze(code)
    assert any(f.rule_id == "SSTI001" for f in findings)


# ── Sensitive Data in Logs [LOG001] ──────────────────────────────────────────

def test_detects_password_in_log():
    code = """
import logging
logger = logging.getLogger(__name__)
def login(request):
    password = request.form.get('password')
    logger.info('Login: %s', password)
"""
    assert "LOG001" in rule_ids(code)


def test_detects_token_in_log():
    code = """
import logging
logger = logging.getLogger(__name__)
token = get_auth_token()
logger.debug('Auth token: %s', token)
"""
    assert "LOG001" in rule_ids(code)


def test_no_log_flag_safe_names():
    code = """
import logging
logger = logging.getLogger(__name__)
username = 'john'
logger.info('User logged in: %s', username)
"""
    assert "LOG001" not in rule_ids(code)


# ── Syntax error resilience ───────────────────────────────────────────────────

def test_handles_syntax_error_gracefully():
    code = "def broken(\n    this is not valid python!!!"
    findings = analyze(code)
    assert isinstance(findings, list)
