"""
JavaScript / TypeScript security analyzer — Powered by YAML Rule Engine.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding
from secara.rules.rule_loader import get_rules_for_language

logger = logging.getLogger("secara.js")


_SOURCE_PATTERN = re.compile(
    r"""(?ix)
    \b(
      req\.[A-Za-z0-9_]+|
      request\.[A-Za-z0-9_]+|
      params\.[A-Za-z0-9_]+|
      query\.[A-Za-z0-9_]+|
      body\.[A-Za-z0-9_]+|
      location\.[A-Za-z0-9_]+|
      document\.URL|
      userInput|
      getParam\s*\(
    )\b
    """
)

_IDENT_PATTERN = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_ASSIGN_PATTERN = re.compile(
    r"""(?x)
    ^\s*(?:const|let|var)?\s*
    (?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.+?)\s*;?\s*$
    """
)
_SANITIZER_PATTERN = re.compile(
    r"""(?ix)
    \b(
      encodeURIComponent|
      DOMPurify\.sanitize|
      sanitizeHtml|
      escapeHtml
    )\s*\(
    """
)

# Rules where we enforce tainted-flow evidence to reduce regex-only noise.
_FLOW_SENSITIVE_RULES = {
    "SQL101",
    "CMD101",
    "CMD102",
    "CMD103",
    "SSRF101",
    "XSS101",
    "XSS102",
    "PATH101",
}


class JSAnalyzer(BaseDetector):
    """
    Tier-2 Analyzer for JavaScript/TypeScript (.js, .ts, .jsx, .tsx) files.
    Uses a hybrid approach with YAML-loaded regex patterns.
    """

    def __init__(self) -> None:
        super().__init__()
        self.rules = get_rules_for_language("javascript")
        # Ensure we also get common rules if anyone uses 'js' as short name
        if not self.rules:
            self.rules = get_rules_for_language("js")
            
        self.compiled_rules = []
        for rule in self.rules:
            if rule.pattern_type == "regex":
                pattern_str = rule.pattern.get("regex", "")
                if pattern_str:
                    try:
                        clean = pattern_str
                        for flag_group in ("(?ix)", "(?xi)", "(?x)", "(?i)"):
                            clean = clean.replace(flag_group, "")
                        compiled = re.compile(clean.strip(), re.IGNORECASE | re.MULTILINE)
                        self.compiled_rules.append((compiled, rule))
                    except re.error as e:
                        logger.error("Failed to compile JS rule %s: %s", rule.id, e)

    def analyze(self, file_path: Path, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        language = "typescript" if file_path.suffix in (".ts", ".tsx") else "javascript"
        tainted_names = self._collect_tainted_identifiers(lines)
        sanitized_names = self._collect_sanitized_identifiers(lines)

        for compiled_pattern, rule in self.compiled_rules:
            for match in compiled_pattern.finditer(content):
                # Calculate line number
                start_pos = match.start()
                line_no = content.count("\n", 0, start_pos) + 1
                line_text = lines[line_no - 1] if 0 <= line_no - 1 < len(lines) else ""
                match_text = match.group(0)

                if rule.id in _FLOW_SENSITIVE_RULES:
                    if not self._has_tainted_flow_evidence(
                        line_text, match_text, tainted_names, sanitized_names
                    ):
                        continue
                
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=rule.description,
                        fix=rule.fix,
                        language=language,
                    )
                )

        return self._deduplicate(findings)

    @staticmethod
    def _collect_tainted_identifiers(lines: list[str]) -> set[str]:
        tainted: set[str] = set()
        for line in lines:
            m = _ASSIGN_PATTERN.match(line)
            if not m:
                continue
            lhs = m.group("lhs")
            rhs = m.group("rhs")
            if _SOURCE_PATTERN.search(rhs):
                tainted.add(lhs)
                continue
            rhs_tokens = set(_IDENT_PATTERN.findall(rhs))
            if rhs_tokens & tainted:
                tainted.add(lhs)
        return tainted

    @staticmethod
    def _collect_sanitized_identifiers(lines: list[str]) -> set[str]:
        sanitized: set[str] = set()
        for line in lines:
            m = _ASSIGN_PATTERN.match(line)
            if not m:
                continue
            lhs = m.group("lhs")
            rhs = m.group("rhs")
            if _SANITIZER_PATTERN.search(rhs):
                sanitized.add(lhs)
        return sanitized

    @staticmethod
    def _has_tainted_flow_evidence(
        line_text: str,
        match_text: str,
        tainted_names: set[str],
        sanitized_names: set[str],
    ) -> bool:
        if _SOURCE_PATTERN.search(line_text) or _SOURCE_PATTERN.search(match_text):
            return True

        tokens = set(_IDENT_PATTERN.findall(match_text)) | set(_IDENT_PATTERN.findall(line_text))
        tainted_used = tokens & tainted_names
        if not tainted_used:
            return False
        # If all tainted identifiers in use are explicitly sanitized, suppress.
        return not tainted_used.issubset(sanitized_names)

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
