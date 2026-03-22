import re
from pathlib import Path

from secara.detectors.base import BaseDetector
from secara.output.models import Finding
from secara.rules.rule_loader import get_rules_for_language


class GoAnalyzer(BaseDetector):
    """
    Tier-2 Analyzer for Go (.go) files.
    Uses robust regular expressions configured over a context window to detect
    Command Injection, SQL Injection, SSRF, and Path Traversal.
    """

    def __init__(self) -> None:
        self.rules = get_rules_for_language("go")
        self.compiled_rules = []
        for rule in self.rules:
            if rule.pattern_type == "regex":
                pattern_str = rule.pattern.get("regex", "")
                if pattern_str:
                    clean = pattern_str
                    for flag_group in ("(?ix)", "(?xi)", "(?x)", "(?i)"):
                        clean = clean.replace(flag_group, "")
                    compiled = re.compile(clean.strip(), re.IGNORECASE | re.MULTILINE)
                    self.compiled_rules.append((compiled, rule))

    def analyze(self, file_path: Path, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        for compiled_pattern, rule in self.compiled_rules:
            findings.extend(
                self._scan_pattern(
                    file_path,
                    content,
                    lines,
                    compiled_pattern,
                    rule.id,
                    rule.name,
                    rule.severity,
                    rule.description,
                    rule.fix,
                )
            )

        return findings

    def _scan_pattern(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        pattern: re.Pattern,
        rule_id: str,
        rule_name: str,
        severity: str,
        description: str,
        fix: str,
    ) -> list[Finding]:
        findings = []
        for match in pattern.finditer(content):
            # Calculate line number
            start_pos = match.start()
            line_no = content.count("\n", 0, start_pos) + 1
            findings.append(
                Finding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=self.get_snippet(lines, line_no),
                    description=description,
                    fix=fix,
                    language="go",
                )
            )
        return findings
