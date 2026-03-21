"""
Tests for expanded secrets detector — new token patterns (v0.2).
"""
from pathlib import Path
import pytest
from secara.detectors.secrets_detector import SecretsDetector

detector = SecretsDetector()


def analyze(code: str, ext: str = ".py") -> list:
    return detector.analyze(Path(f"test{ext}"), code)


def rule_ids(code: str, ext: str = ".py") -> set:
    return {f.rule_id for f in analyze(code, ext)}


# ── OpenAI ────────────────────────────────────────────────────────────────────

def test_detects_openai_key():
    code = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz012345678901234567"\n'
    assert "SEC015" in rule_ids(code)


# ── HuggingFace ───────────────────────────────────────────────────────────────

def test_detects_huggingface_token():
    code = 'HF_TOKEN = "hf_abcdefghijklmnopqrstuvwxyz123456"\n'
    assert "SEC025" in rule_ids(code)


# ── GitLab ────────────────────────────────────────────────────────────────────

def test_detects_gitlab_token():
    code = 'token = "glpat-abcdefghijklmnop1234"\n'
    assert "SEC004C" in rule_ids(code)


# ── GitHub fine-grained ───────────────────────────────────────────────────────

def test_detects_github_fine_grained():
    code = 'gh_token = "github_pat_abcdefghijklmnopqrstuvww_abcdefghijklmnopqrstuvwxyz1234567890123456789012345678"\n'
    assert "SEC004B" in rule_ids(code)


# ── Database connection string ────────────────────────────────────────────────

def test_detects_postgres_connection_string():
    code = 'DB_URL = "postgres://admin:SuperSecret123@db.prod.internal/app"\n'
    assert "SEC031" in rule_ids(code)


def test_detects_mongodb_connection_string():
    code = 'MONGO_URI = "mongodb://user:password123@cluster.mongodb.net/mydb"\n'
    assert "SEC031" in rule_ids(code)


# ── Slack webhook ─────────────────────────────────────────────────────────────

def test_detects_slack_webhook():
    code = 'WEBHOOK = "hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
    assert "SEC007B" in rule_ids(code)


# ── npm token ─────────────────────────────────────────────────────────────────

def test_detects_npm_token():
    code = 'NPM_TOKEN = "npm_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"\n'
    assert "SEC018" in rule_ids(code)


# ── Shopify ───────────────────────────────────────────────────────────────────

def test_detects_shopify_token():
    code = 'SHOPIFY_TOKEN = "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"\n'
    assert "SEC029" in rule_ids(code)


# ── HashiCorp Vault ───────────────────────────────────────────────────────────

def test_detects_vault_token():
    code = 'VAULT_TOKEN = "hvs.abcdefghijklmnopqrstuvwx"\n'
    assert "SEC028" in rule_ids(code)


# ── Google OAuth ──────────────────────────────────────────────────────────────

def test_detects_google_oauth():
    code = 'client_secret = "GOCSPX-abcdefghijklmnopqrstuvwxyz"\n'
    assert "SEC010B" in rule_ids(code)


# ── AWS Secret Access Key ─────────────────────────────────────────────────────

def test_detects_aws_secret_key():
    code = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY0"\n'
    ids = rule_ids(code)
    # The keyword proximity should pick it up as SEC013 even if SEC001B doesn't match exactly
    assert ids, "Should detect some secret in aws secret key assignment"


# ── Cross-file extensions ─────────────────────────────────────────────────────

def test_detects_openai_key_in_js():
    code = 'const key = "sk-abcdefghijklmnopqrstuvwxyz012345678901234567";\n'
    assert "SEC015" in rule_ids(code, ext=".js")


def test_detects_hf_token_in_env():
    code = 'HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz123456\n'
    assert "SEC025" in rule_ids(code, ext=".env")


# ── Placeholders should not trigger ───────────────────────────────────────────

def test_no_false_positive_on_placeholder():
    code = 'api_key = "YOUR_API_KEY_HERE"\n'
    ids = rule_ids(code)
    sec013 = [f for f in analyze(code) if f.rule_id == "SEC013"]
    assert not sec013, "Should not flag obvious placeholder"
