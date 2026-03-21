"""
INTENTIONALLY VULNERABLE Python file for Secara testing.

⚠️  DO NOT USE IN PRODUCTION — Contains deliberate security vulnerabilities ⚠️
This file is used to verify that Secara correctly detects real issues.
"""
import os
import subprocess
import sqlite3

# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 1: Hardcoded AWS Access Key (SEC001 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 2: Hardcoded credentials in variables (SEC013 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
database_password = "SuperSecretPass123!"
api_key = "prod_live_5f3a1b2c4d6e7f8a"

# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 3: SQL Injection via string concatenation (SQL001 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
def get_user_by_name(request):
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 4: SQL Injection via f-string (SQL001 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
def get_user_by_id(request):
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABLE: f-string interpolation in SQL
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 5: Command Injection via os.system (CMD001 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
def ping_host(request):
    hostname = request.args.get("host")

    # VULNERABLE: User input directly in os.system()
    os.system("ping -c 1 " + hostname)


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 6: Command Injection via subprocess shell=True (CMD002 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
def run_report(request):
    report_name = request.form.get("report")

    # VULNERABLE: shell=True with dynamic string
    subprocess.run("generate_report.sh " + report_name, shell=True)


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 7: eval() with user input (CMD003 - HIGH)
# ──────────────────────────────────────────────────────────────────────────────
def calculate(request):
    expression = request.args.get("expr")

    # VULNERABLE: eval with user-controlled input
    result = eval(expression)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# VULNERABILITY 8: High-entropy string that looks like a secret (SEC014)
# ──────────────────────────────────────────────────────────────────────────────
SIGNING_SECRET = "Xk9mP2wQzR4nV7tY1aL8cF0jH6bN3eD5"


# ──────────────────────────────────────────────────────────────────────────────
# SAFE CODE BELOW — Expected: Zero findings from these functions
# ──────────────────────────────────────────────────────────────────────────────

def safe_get_user(request):
    """✅ SAFE: Parameterized query — not vulnerable to SQL injection."""
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchall()


def safe_ping(request):
    """✅ SAFE: subprocess list args, no shell=True."""
    hostname = request.args.get("host")
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True)
    return result.stdout


def safe_eval():
    """✅ SAFE: eval with a literal constant."""
    return eval("2 + 2")
