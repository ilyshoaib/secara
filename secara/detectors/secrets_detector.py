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
from secara.rules.rule_loader import get_rules_for_language

logger = logging.getLogger("secara.secrets")

# ── Known token patterns ──────────────────────────────────────────────────────
# Rules are now loaded dynamically from secara/rules/builtin/secrets.yaml


# ── Generic keyword-proximity patterns ────────────────────────────────────────
# Match: key_word = "value" or key_word=value
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
    (?P<quote>['"`]?)
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
    "<your_api_key>", "<your_token>", "your_password", "your_api_key_here",
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
            # Skip comment-only lines (but allow private key headers)
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*", "--")):
                if not stripped.startswith("-----BEGIN"):
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
        rules = [r for r in get_rules_for_language("any") if r.pattern_type == "regex"]
        for rule in rules:
            pattern = rule.pattern.get("regex", "")
            if not pattern:
                continue
            if re.search(pattern, line):
                results.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=f"{rule.description}\nCommitting secrets to source control exposes them to anyone with repository access.",
                        fix=rule.fix,
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
        
        # Heuristic: Skip enormously long lines > 500 characters (minified code / chunks)
        if len(line) > 500:
            return results

        for match in _ENTROPY_CANDIDATE.finditer(line):
            value = match.group("value")
            if len(value) < MIN_LENGTH_FOR_ENTROPY:
                continue
            
            # Heuristic: Pure hex strings max out at ~4 entropy, but if long enough they trigger false flags
            # Commonly used for MD5/SHA1/Commit IDs, not usually secrets
            if re.fullmatch(r"[a-fA-F0-9]+", value):
                continue
                
            # Heuristic: base64 image data URIs
            if "data:image/" in line or "application/" in line:
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
