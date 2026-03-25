"""
Config file analyzer — Tier 2 (JSON / YAML / .env / .ini / .toml).

Detects hardcoded secrets in configuration files by checking:
  - Key names that suggest credentials
  - Non-empty, non-placeholder string values

This analyzer defers to SecretsDetector for entropy/known-token checks.
Its role is to catch plaintext credential assignments in structured config.
"""
from __future__ import annotations

import json
import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding

logger = logging.getLogger("secara.config")

# Keys that indicate credentials
_SECRET_KEYS = re.compile(
    r"""(?ix)
    (?:^|_|\b)
    (?:password|passwd|pwd|secret|token|api[-_]?key|
       auth[-_]?key|private[-_]?key|client[-_]?secret|
       access[-_]?key|signing[-_]?key|encryption[-_]?key|
       db[-_]?pass(?:word)?|database[-_]?pass(?:word)?)
    (?:$|_|\b)
    """,
    re.IGNORECASE,
)

# Non-placeholder values (at least 6 non-whitespace chars)
_REAL_VALUE = re.compile(r"""^(?!.*(?:your|change|insert|replace|example|placeholder|<|>|\*{3,}|xxx))
    .{6,}$""", re.IGNORECASE | re.VERBOSE)

# .env / .ini style: KEY=value or KEY: value
_KV_PATTERN = re.compile(
    r"""^(?P<key>[A-Z_a-z][A-Z_a-z0-9]*)\s*[=:]\s*
        (?P<quote>['"]?)(?P<value>[^\r\n'"]+)(?P=quote)""",
    re.MULTILINE | re.VERBOSE,
)

_COMMENT_LINE = re.compile(r"^\s*[#;]")


class ConfigAnalyzer(BaseDetector):
    """Tier 2 config-file credential detector."""

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        if suffix in {".json"}:
            return self._analyze_json(file_path, content)
        elif suffix in {".yaml", ".yml"}:
            return self._analyze_yaml_kv(file_path, content)
        else:
            # .env, .ini, .cfg, .toml, .conf — treat as key-value
            return self._analyze_kv(file_path, content)

    def _analyze_kv(self, file_path: Path, content: str) -> List[Finding]:
        """Parse KEY=value or KEY: value lines."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            if _COMMENT_LINE.match(line) or not line.strip():
                continue

            m = _KV_PATTERN.match(line.strip())
            if not m:
                continue

            key = m.group("key")
            value = m.group("value").strip().strip("'\"")

            if _SECRET_KEYS.search(key) and _REAL_VALUE.match(value):
                findings.append(Finding(
                    rule_id="CFG001",
                    rule_name="Hardcoded Secret in Config File",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        f"The config key '{key}' contains a plaintext credential or secret. "
                        "Config files are frequently committed to version control, "
                        "exposing the secret to all repository viewers."
                    ),
                    fix=(
                        "Replace the hardcoded value with an environment variable reference:\n"
                        f"  {key}=${{SECRET_{key.upper()}}}\n"
                        "Ensure .env files are listed in .gitignore and never committed."
                    ),
                    language=file_path.suffix.lstrip("."),
                    confidence="MEDIUM",
                ))

        return findings

    def _analyze_json(self, file_path: Path, content: str) -> List[Finding]:
        """Parse JSON and flag secret-named keys with non-empty values."""
        findings: List[Finding] = []
        try:
            obj = json.loads(content)
        except json.JSONDecodeError:
            logger.debug("Invalid JSON in %s", file_path)
            return findings

        lines = content.splitlines()
        self._walk_json(file_path, obj, lines, findings)
        return findings

    def _walk_json(
        self,
        file_path: Path,
        obj,
        lines: list[str],
        findings: List[Finding],
        depth: int = 0,
    ) -> None:
        if depth > 10:
            return
        if isinstance(obj, dict):
            for key, val in obj.items():
                if isinstance(val, str) and _SECRET_KEYS.search(str(key)):
                    if _REAL_VALUE.match(val):
                        # Find the line number by searching the raw content
                        line_no = self._find_json_key_line(lines, key, val)
                        findings.append(Finding(
                            rule_id="CFG002",
                            rule_name="Hardcoded Secret in JSON Config",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=line_no,
                            snippet=f'"{key}": "{"*" * min(len(val), 8)}..."',
                            description=(
                                f"The JSON key '{key}' contains a plaintext credential. "
                                "JSON config files should never store live secrets."
                            ),
                            fix=(
                                "Store the secret in environment variables and reference them "
                                "at runtime: process.env.SECRET_NAME (Node.js) or os.getenv() (Python)."
                            ),
                            language="json",
                            confidence="MEDIUM",
                        ))
                elif isinstance(val, (dict, list)):
                    self._walk_json(file_path, val, lines, findings, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._walk_json(file_path, item, lines, findings, depth + 1)

    def _find_json_key_line(self, lines: list[str], key: str, value: str) -> int:
        """Find the line number of a specific JSON key."""
        pattern = re.compile(re.escape(f'"{key}"'), re.IGNORECASE)
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                return i
        return 1

    def _analyze_yaml_kv(self, file_path: Path, content: str) -> List[Finding]:
        """
        Simple line-by-line YAML parser for credential detection.
        Handles: key: value and key: "value" patterns.
        """
        findings: List[Finding] = []
        lines = content.splitlines()
        yaml_kv = re.compile(
            r"""^\s*(?P<key>[a-zA-Z_][a-zA-Z0-9_\-]*)\s*:\s*
                (?P<quote>['"]?)(?P<value>[^\r\n#'"]+)(?P=quote)""",
            re.VERBOSE,
        )

        for line_no, line in enumerate(lines, start=1):
            if _COMMENT_LINE.match(line) or not line.strip():
                continue
            m = yaml_kv.match(line)
            if not m:
                continue
            key = m.group("key")
            value = m.group("value").strip().strip("'\"")
            if _SECRET_KEYS.search(key) and _REAL_VALUE.match(value):
                findings.append(Finding(
                    rule_id="CFG003",
                    rule_name="Hardcoded Secret in YAML Config",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        f"The YAML key '{key}' contains a plaintext credential. "
                        "YAML config files committed to repos expose secrets permanently "
                        "in version history."
                    ),
                    fix=(
                        "Use environment variable interpolation supported by your framework:\n"
                        f"  {key}: ${{{{ env.SECRET_{key.upper()} }}}}\n"
                        "Or load from environment at runtime."
                    ),
                    language="yaml",
                    confidence="MEDIUM",
                ))

        return findings
