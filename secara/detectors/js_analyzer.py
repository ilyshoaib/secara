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
                        compiled = re.compile(pattern_str, re.MULTILINE | re.DOTALL)
                        self.compiled_rules.append((compiled, rule))
                    except re.error as e:
                        logger.error("Failed to compile JS rule %s: %s", rule.id, e)

    def analyze(self, file_path: Path, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()
        language = "typescript" if file_path.suffix in (".ts", ".tsx") else "javascript"

        for compiled_pattern, rule in self.compiled_rules:
            for match in compiled_pattern.finditer(content):
                # Calculate line number
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
                        language=language,
                    )
                )

        return findings
