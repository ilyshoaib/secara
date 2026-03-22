"""
Generic regex-based analyzer powered by the YAML Rule Engine.

Used by Java, PHP, Ruby, and any future language that uses regex rules.
Language-specific analyzers simply inherit from this and pass their language name.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding
from secara.rules.rule_loader import get_rules_for_language

logger = logging.getLogger("secara.generic")


class GenericRegexAnalyzer(BaseDetector):
    """
    Loads rules from language-specific YAML and applies them via regex.
    Shared by Java, PHP, and Ruby analyzers.
    """

    def __init__(self, language: str) -> None:
        super().__init__()
        self.language = language
        rules = get_rules_for_language(language)
        self.compiled_rules = []
        for rule in rules:
            if rule.pattern_type == "regex":
                pattern_str = rule.pattern.get("regex", "")
                if pattern_str:
                    try:
                        # Strip inline (?x) / (?ix) from pattern to avoid
                        # treating '#' as a regex comment (verbose mode).
                        # We handle case-insensitivity via re.IGNORECASE instead.
                        clean = pattern_str
                        for flag_group in ("(?ix)", "(?xi)", "(?x)", "(?i)"):
                            clean = clean.replace(flag_group, "")
                        compiled = re.compile(
                            clean.strip(),
                            re.IGNORECASE | re.MULTILINE,
                        )
                        self.compiled_rules.append((compiled, rule))
                    except re.error as e:
                        logger.error(
                            "Failed to compile %s rule %s: %s", language, rule.id, e
                        )
        logger.debug(
            "%s analyzer loaded %d rules", language, len(self.compiled_rules)
        )

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for compiled_pattern, rule in self.compiled_rules:
            for match in compiled_pattern.finditer(content):
                start_pos = match.start()
                line_no = content.count("\n", 0, start_pos) + 1
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
                        language=self.language,
                    )
                )

        return self._deduplicate(findings)

    @staticmethod
    def _deduplicate(findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings at the same file+line+rule."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_number, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
