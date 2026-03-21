"""
Secrets Detector — runs on ALL file types.

Detection strategies:
  1. Named-pattern matching  — known token formats (AWS, GitHub, Stripe, etc.)
  2. Keyword-proximity match — variable assignments near secret-sounding keys
  3. Shannon entropy          — long, dense strings that look like secrets
"""
from __future__ import annotations

import math
import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding

logger = logging.getLogger("secara.secrets")

# ── Known token patterns ──────────────────────────────────────────────────────
# Each entry: (rule_id, rule_name, severity, regex_pattern)
KNOWN_TOKEN_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "SEC001",
        "Hardcoded AWS Access Key",
        "HIGH",
        r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
    ),
    (
        "SEC002",
        "Hardcoded GitHub Personal Access Token",
        "HIGH",
        r"ghp_[a-zA-Z0-9]{36}",
    ),
    (
        "SEC003",
        "Hardcoded GitHub OAuth Token",
        "HIGH",
        r"gho_[a-zA-Z0-9]{36}",
    ),
    (
        "SEC004",
        "Hardcoded GitHub Actions Token",
        "HIGH",
        r"ghs_[a-zA-Z0-9]{36}",
    ),
    (
        "SEC005",
        "Hardcoded Stripe Secret Key",
        "HIGH",
        r"sk_live_[0-9a-zA-Z]{24,}",
    ),
    (
        "SEC006",
        "Hardcoded Stripe Test Key",
        "MEDIUM",
        r"sk_test_[0-9a-zA-Z]{24,}",
    ),
    (
        "SEC007",
        "Hardcoded Slack Token",
        "HIGH",
        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    ),
    (
        "SEC008",
        "Hardcoded Private Key Header",
        "HIGH",
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "SEC009",
        "Hardcoded SendGrid API Key",
        "HIGH",
        r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
    ),
    (
        "SEC010",
        "Hardcoded Google API Key",
        "HIGH",
        r"AIza[0-9A-Za-z\-_]{35}",
    ),
    (
        "SEC011",
        "Hardcoded Twilio Account SID",
        "MEDIUM",
        r"AC[a-z0-9]{32}",
    ),
    (
        "SEC012",
        "Hardcoded JWT Token",
        "HIGH",
        r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    ),
]

# ── Generic keyword-proximity patterns ────────────────────────────────────────
# Match: key_word = "value"  (various quote styles)
_KEYWORD_PATTERN = re.compile(
    r"""(?ix)
    (?:^|\s|,|;|\()                    # word boundary or statement start
    (?P<key>
        (?:api[_\-]?key|api[_\-]?secret|access[_\-]?key|secret[_\-]?key|
           auth[_\-]?token|private[_\-]?key|client[_\-]?secret|
           app[_\-]?secret|token|password|passwd|pwd|secret|
           db[_\-]?pass(?:word)?|database[_\-]?password)
    )
    \s*[:=]\s*
    (?P<quote>['"`])
    (?P<value>[^'"`\s]{6,200})         # at least 6 chars, not a template
    (?P=quote)
    """,
    re.MULTILINE,
)

# Skip values that are clearly placeholders
_PLACEHOLDER_VALUES = {
    "your_api_key", "your_secret", "your_token", "changeme",
    "replace_me", "xxx", "yyy", "placeholder", "example",
    "your-key-here", "insert_key_here", "<key>", "<secret>",
    "none", "null", "undefined", "false", "true",
    "<your_api_key>", "<your_token>",
}

# ── Shannon entropy ───────────────────────────────────────────────────────────
_ENTROPY_CANDIDATE = re.compile(
    r"""(?P<quote>['"`])(?P<value>[A-Za-z0-9+/=_\-]{20,})(?P=quote)"""
)

ENTROPY_THRESHOLD = 4.5   # bits per character
MIN_LENGTH_FOR_ENTROPY = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in prob.values())


class SecretsDetector(BaseDetector):
    """
    Multi-strategy secrets detection for all file types.
    """

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            # Skip comment-only lines
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "--")):
                continue

            findings.extend(self._check_known_tokens(file_path, line, line_no))
            findings.extend(self._check_keyword_proximity(file_path, line, line_no))
            findings.extend(self._check_entropy(file_path, line, line_no))

        return findings

    # ── Strategy 1: Known token formats ───────────────────────────────────────
    def _check_known_tokens(
        self, file_path: Path, line: str, line_no: int
    ) -> List[Finding]:
        results = []
        for rule_id, rule_name, severity, pattern in KNOWN_TOKEN_PATTERNS:
            if re.search(pattern, line):
                results.append(
                    Finding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity=severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            f"A {rule_name} was found hardcoded in the source. "
                            "Committing secrets to source control exposes them to anyone "
                            "with repository access and leaks them in version history."
                        ),
                        fix=(
                            "Remove the secret from the code. Store it in an environment "
                            "variable (e.g. os.environ['KEY']) or a secrets manager "
                            "(e.g. AWS Secrets Manager, Vault, .env file excluded via .gitignore)."
                        ),
                        language=file_path.suffix.lstrip("."),
                    )
                )
        return results

    # ── Strategy 2: Keyword-proximity match ───────────────────────────────────
    def _check_keyword_proximity(
        self, file_path: Path, line: str, line_no: int
    ) -> List[Finding]:
        results = []
        for match in _KEYWORD_PATTERN.finditer(line):
            value = match.group("value").lower()
            if value in _PLACEHOLDER_VALUES:
                continue
            # Skip if the value looks like a variable reference: ${VAR}, %(VAR)s
            if value.startswith(("${", "%(", "{", "<")):
                continue
            results.append(
                Finding(
                    rule_id="SEC013",
                    rule_name="Hardcoded Credential in Assignment",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        f"The variable '{match.group('key')}' appears to contain a "
                        "hardcoded credential. Hardcoded secrets are a critical security "
                        "risk and are easily leaked via version control."
                    ),
                    fix=(
                        "Replace the hardcoded value with an environment variable: "
                        "os.getenv('SECRET_NAME') in Python, or process.env.SECRET_NAME in Node.js. "
                        "Use a .env file (excluded from git via .gitignore) for local development."
                    ),
                    language=file_path.suffix.lstrip("."),
                )
            )
        return results

    # ── Strategy 3: Shannon entropy ───────────────────────────────────────────
    def _check_entropy(
        self, file_path: Path, line: str, line_no: int
    ) -> List[Finding]:
        results = []
        for match in _ENTROPY_CANDIDATE.finditer(line):
            value = match.group("value")
            if len(value) < MIN_LENGTH_FOR_ENTROPY:
                continue
            entropy = _shannon_entropy(value)
            if entropy >= ENTROPY_THRESHOLD:
                # Skip Base64 padding of template strings
                if value.lower() in _PLACEHOLDER_VALUES:
                    continue
                results.append(
                    Finding(
                        rule_id="SEC014",
                        rule_name="High-Entropy String (Possible Secret)",
                        severity="MEDIUM",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            f"A high-entropy string (entropy={entropy:.2f} bits/char) was detected. "
                            "This is a strong statistical indicator of a hardcoded secret, "
                            "API key, or cryptographic material."
                        ),
                        fix=(
                            "Verify this is not a secret. If it is, move it to an environment "
                            "variable or secrets manager. If it is a legitimate constant "
                            "(e.g., a hash or nonce), add a `# secara: ignore` comment to suppress."
                        ),
                        language=file_path.suffix.lstrip("."),
                    )
                )
        return results
