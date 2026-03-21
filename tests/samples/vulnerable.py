"""
Intentionally vulnerable Python samples for testing ALL new OWASP detections.
DO NOT deploy in production.
"""
import os
import subprocess
import hashlib
import pickle
import yaml
import random
import requests

# ── Hardcoded Secrets ────────────────────────────────────────────────────────
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                              # SEC001
openai_key = "sk-abcdefghijklmnopqrstuvwxyz012345678901234567"  # SEC015
hf_token = "hf_abcdefghijklmnopqrstuvwxyz123456"              # SEC025
db_url = "postgres://admin:SuperSecret123@db.prod.internal/app"  # SEC031
gh_token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7"           # SEC002
jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc" # SEC012

# ── Weak Cryptography [CRY001] ───────────────────────────────────────────────
def store_password(password):
    hashed = hashlib.md5(password.encode()).hexdigest()  # VULN: CRY001
    return hashed

def verify_password(password, stored_hash):
    return hashlib.sha1(password.encode()).hexdigest() == stored_hash  # VULN: CRY001

# ── Insecure PRNG [CRY003] ───────────────────────────────────────────────────
def generate_session_token():
    return random.random()  # VULN: CRY003 — use secrets.token_hex()

def generate_otp():
    return random.randint(100000, 999999)  # VULN: CRY003 — predictable OTP

# ── Insecure SSL [CRY002] ────────────────────────────────────────────────────
def fetch_data(url):
    return requests.get(url, verify=False)  # VULN: CRY002 — MitM vulnerable

# ── SSRF [SSRF001] ──────────────────────────────────────────────────────────
def proxy_request(request):
    target = request.args.get("url")
    return requests.get(target)  # VULN: SSRF001 — user controls URL

def fetch_profile(request):
    user_url = request.form.get("profile_url")
    # Attacker can use: http://169.254.169.254/latest/meta-data/
    return requests.post(user_url, json={"data": "test"})  # VULN: SSRF001

# ── Insecure Deserialization [DSER001, DSER004] ──────────────────────────────
def load_session(cookie_data):
    return pickle.loads(cookie_data)  # VULN: DSER001 — arbitrary code execution

def load_config(config_file):
    with open(config_file) as f:
        return yaml.load(f)  # VULN: DSER004 — yaml.load without SafeLoader

# ── Path Traversal [PATH001] ─────────────────────────────────────────────────
def read_file(request):
    filename = request.args.get("file")
    with open(filename) as f:  # VULN: PATH001 — ../../etc/passwd
        return f.read()

def serve_file(request):
    filename = request.args.get("path")
    return send_file(filename)  # VULN: PATH002

# ── SSTI / Template Injection [SSTI001] ──────────────────────────────────────
from flask import render_template_string

def render_page(request):
    name = request.args.get("name")
    template = f"Hello {name}!"
    return render_template_string(template)  # VULN: SSTI001 — name={{7*7}}

# ── Sensitive Data in Logs [LOG001] ─────────────────────────────────────────
import logging
logger = logging.getLogger(__name__)

def login(request):
    username = request.form.get("username")
    password = request.form.get("password")     # tainted
    logger.info("Login attempt: %s / %s", username, password)  # VULN: LOG001

# ── SQL Injection [SQL001] ───────────────────────────────────────────────────
def get_user(request, cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")  # VULN: SQL001

# ── Command Injection [CMD001] ───────────────────────────────────────────────
def ping_host(request):
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # VULN: CMD001

def run_scan(request):
    target = request.form.get("target")
    subprocess.run(f"nmap {target}", shell=True)  # VULN: CMD002
