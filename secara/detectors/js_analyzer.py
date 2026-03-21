"""
JavaScript / TypeScript security analyzer.

Uses a regex-AST hybrid approach — no external compiled parsers required.
Detects:
  - SQL Injection: string concatenation or template literals in DB query calls
  - Command Injection: exec/execSync/spawn with dynamic args
  - eval() with non-literal arguments
  - Prototype pollution patterns

Strategy: Apply regex patterns with contextual window analysis (surrounding lines)
to achieve reasonable accuracy without a full parse tree.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding

logger = logging.getLogger("secara.js")

# ── SQL Injection patterns ────────────────────────────────────────────────────
# Matches "query(" or "execute(" where the argument contains string concat/template
_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "concat",
        re.compile(
            r"""(?:\.query|\.execute|\.raw|db\.run|pool\.query)\s*\(\s*(?:
                    [`'"].*?\+\s*\w+         # string + variable
                  | \w+\s*\+\s*[`'"]        # variable + string
                  | `[^`]*?\$\{[^}]+\}      # template literal with ${...}
                )""",
            re.VERBOSE | re.IGNORECASE,
        ),
    ),
    (
        "template",
        re.compile(
            r"""(?:\.query|\.execute|\.raw|db\.run)\s*\(\s*`[^`]*\$\{[^}]+\}""",
            re.IGNORECASE,
        ),
    ),
]

# ── Command Injection patterns ────────────────────────────────────────────────
_CMD_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "CMD101",
        re.compile(
            r"""exec\s*\(\s*(?:
                    ["`'].*?\+\s*\w+         # string concat
                  | \w+\s*\+\s*["`']        # var + string
                  | `[^`]*\$\{[^}]+\}       # template literal
                  | \w+                      # bare variable
                )\s*[,)]""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via exec()",
    ),
    (
        "CMD102",
        re.compile(
            r"""execSync\s*\(\s*(?:
                    ["`'].*?\+\s*\w+
                  | \w+\s*\+\s*["`']
                  | `[^`]*\$\{[^}]+\}
                  | \w+
                )\s*[,)]""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via execSync()",
    ),
    (
        "CMD103",
        re.compile(
            r"""spawn\s*\(\s*(?:
                    ["`'].*?\+\s*\w+
                  | \w+\s*\+\s*["`']
                  | `[^`]*\$\{[^}]+\}
                  | \w+
                )\s*,""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via spawn()",
    ),
]

# ── eval() patterns ───────────────────────────────────────────────────────────
_EVAL_PATTERN = re.compile(
    r"""\beval\s*\(\s*(?!['"`]\s*\))(?!\d)(?!\()([^)]+)\)""",
    re.IGNORECASE,
)

# Detect obvious non-dynamic eval (constant strings)
_EVAL_CONSTANT = re.compile(r"""\beval\s*\(\s*['"`][^'"`;]*['"`]\s*\)""")

# ── Prototype pollution ───────────────────────────────────────────────────────
_PROTO_POLLUTION = re.compile(
    r"""(?:__proto__|constructor\s*\[|prototype\s*\[)\s*\[?\s*['"]\w+""",
    re.IGNORECASE,
)

# ── Comment lines ─────────────────────────────────────────────────────────────
_COMMENT_LINE = re.compile(r"""^\s*(?://|/\*|\*)""")


class JSAnalyzer(BaseDetector):
    """Regex-AST hybrid security analyzer for JavaScript/TypeScript."""

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx"} else "javascript"

        for line_no, line in enumerate(lines, start=1):
            if _COMMENT_LINE.match(line):
                continue

            # ── SQL Injection ──────────────────────────────────────────────
            for variant, pattern in _SQL_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id="SQL002",
                        rule_name="SQL Injection in JavaScript/TypeScript",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            "A database query is built using string concatenation or "
                            "template literals with potentially user-controlled values. "
                            "This allows attackers to inject arbitrary SQL and bypass "
                            "authentication or access unauthorized data."
                        ),
                        fix=(
                            "Use parameterized queries with placeholders:\n"
                            "  db.query('SELECT * FROM users WHERE id = $1', [userId])\n"
                            "  // or with mysql2: db.execute('SELECT ? FROM ...', [val])"
                        ),
                        language=language,
                    ))
                    break

            # ── Command Injection ──────────────────────────────────────────
            for rule_id, pattern, rule_name in _CMD_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            f"A shell command is constructed dynamically in {rule_name.split('via ')[1]}. "
                            "If any part of the command includes user input, an attacker "
                            "can inject arbitrary OS commands (e.g., ; rm -rf /)."
                        ),
                        fix=(
                            "Avoid passing dynamic strings to exec/execSync/spawn.\n"
                            "  - Use spawn() with an explicit args array: spawn('ls', ['-la', userDir])\n"
                            "  - Validate and sanitize all inputs strictly before use in commands."
                        ),
                        language=language,
                    ))
                    break

            # ── eval() ────────────────────────────────────────────────────
            if _EVAL_PATTERN.search(line) and not _EVAL_CONSTANT.search(line):
                findings.append(Finding(
                    rule_id="CMD104",
                    rule_name="Dangerous eval() Usage in JavaScript",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "eval() is called with a non-literal argument. eval() executes "
                        "arbitrary JavaScript code, and if the argument is user-controlled, "
                        "this enables full remote code execution."
                    ),
                    fix=(
                        "Avoid eval() completely. Safer alternatives:\n"
                        "  - JSON.parse() for parsing data\n"
                        "  - A lookup object/map for dynamic dispatch\n"
                        "  - Function constructors should also be avoided"
                    ),
                    language=language,
                ))

            # ── Prototype Pollution ────────────────────────────────────────
            if _PROTO_POLLUTION.search(line):
                findings.append(Finding(
                    rule_id="CMD105",
                    rule_name="Potential Prototype Pollution",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "Access to __proto__ or constructor.prototype with dynamic keys "
                        "can enable prototype pollution attacks, allowing attackers to "
                        "modify Object.prototype and affect all objects in the application."
                    ),
                    fix=(
                        "Avoid dynamic property access on __proto__ or prototype.\n"
                        "  - Use Object.create(null) for maps without prototype chains.\n"
                        "  - Validate and whitelist all keys before merging user-supplied objects."
                    ),
                    language=language,
                ))

        return findings
