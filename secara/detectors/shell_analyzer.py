"""
Shell (Bash) script analyzer — Tier 2 (regex-based).

Detects:
  - eval with variable content
  - Backtick execution with unquoted/unvalidated variables
  - Command substitution with external input ($1, $@, $*, user-supplied vars)
  - Unquoted variable expansion in dangerous commands
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding

logger = logging.getLogger("secara.shell")

# ── Patterns ──────────────────────────────────────────────────────────────────
_COMMENT_LINE = re.compile(r"^\s*#")

# eval with variable: eval $VAR, eval "$VAR", eval `cmd`
_EVAL_WITH_VAR = re.compile(
    r"""\beval\s+(?:"[^"]*\$[^"]*"|'[^']*\$[^']*'|\$\w+|`[^`]+`)""",
    re.IGNORECASE,
)

# Backtick execution with external params: `cmd $1`, `cmd $USER_INPUT`
_BACKTICK_WITH_PARAM = re.compile(r"""`[^`]*\$(?:\d+|[@*]|\w+)[^`]*`""")

# Command substitution: $(cmd $VAR) or $(curl $URL)
_CMD_SUBST_WITH_VAR = re.compile(
    r"""\$\([^)]*\$(?:\d+|[@*!]|\w+)[^)]*\)"""
)

# Common dangerous commands with unquoted variable
_DANGEROUS_UNQUOTED = re.compile(
    r"""(?:curl|wget|bash|sh|python|perl|ruby|php)\s+[^"'\s]*\$\w+""",
)

# RM with variable (high risk)
_RM_WITH_VAR = re.compile(r"""\brm\s+(?:-\w+\s+)*[^"'\n]*\$(?:\d+|[@*]|\w+)""")


class ShellAnalyzer(BaseDetector):
    """Tier 2 regex-based Bash/shell script analyzer."""

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            if _COMMENT_LINE.match(line):
                continue
            stripped = line.strip()

            # ── eval with variable ────────────────────────────────────
            if _EVAL_WITH_VAR.search(line):
                findings.append(Finding(
                    rule_id="SH001",
                    rule_name="Command Injection via eval in Shell Script",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=stripped,
                    description=(
                        "eval is used with a variable or dynamic content. "
                        "eval executes its argument as a shell command; if the content "
                        "is user-controlled, arbitrary commands can be injected."
                    ),
                    fix=(
                        "Avoid eval. Use explicit command calls with properly quoted arguments. "
                        "If dynamic behavior is needed, use arrays and indirect expansion safely."
                    ),
                    language="bash",
                ))

            # ── backtick with param ───────────────────────────────────
            elif _BACKTICK_WITH_PARAM.search(line):
                findings.append(Finding(
                    rule_id="SH002",
                    rule_name="Unsafe Command Substitution with External Input",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=stripped,
                    description=(
                        "Backtick command substitution includes user-supplied positional "
                        "parameters ($1, $@, etc.). Unvalidated external input in command "
                        "substitution allows shell command injection."
                    ),
                    fix=(
                        "Quote all variables: \"$var\" instead of $var. "
                        "Validate and sanitize function arguments before use in commands."
                    ),
                    language="bash",
                ))

            # ── command substitution with var ─────────────────────────
            elif _CMD_SUBST_WITH_VAR.search(line):
                findings.append(Finding(
                    rule_id="SH003",
                    rule_name="Command Substitution with Unvalidated Input",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=stripped,
                    description=(
                        "Command substitution $(...) contains externally-supplied variables. "
                        "Shell metacharacters in the variable value can alter command behavior."
                    ),
                    fix=(
                        "Always double-quote variable expansions: \"$(cmd \"$var\")\". "
                        "Validate input before passing to commands."
                    ),
                    language="bash",
                ))

            # ── dangerous commands with unquoted var ──────────────────
            elif _DANGEROUS_UNQUOTED.search(line):
                findings.append(Finding(
                    rule_id="SH004",
                    rule_name="Dangerous Command with Unquoted Variable",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=stripped,
                    description=(
                        "A potentially dangerous command (curl, wget, bash, sh, etc.) is "
                        "called with an unquoted variable argument. Unquoted variables undergo "
                        "word splitting and globbing, enabling injection via whitespace or wildcards."
                    ),
                    fix=(
                        "Double-quote all variable references: curl \"$URL\" instead of curl $URL. "
                        "Validate the URL/path before use."
                    ),
                    language="bash",
                ))

        return findings
