"""
Basic taint tracker for Python functions.

Scope: single-function taint analysis using Python's built-in `ast` module.
Tracks variables that receive values from known user-input sources and checks
whether those tainted variables flow into known dangerous sinks.

Sources (things that introduce untrusted data):
  - request.*, request.args, request.form, request.json  (Flask/Django/FastAPI)
  - self.request.*, self.get_argument  (Tornado)
  - input()
  - sys.argv[*]
  - os.environ.get(), os.getenv()
  - event["*"], event.get("*")  (AWS Lambda)
  - kwargs, args (when function parameters)

Sinks:
  - SQL: cursor.execute, db.execute, session.execute, connection.execute
  - CMDi: os.system, subprocess.call, subprocess.run, subprocess.Popen,
           subprocess.check_output, os.popen
  - Code exec: eval, exec, compile
"""
from __future__ import annotations

import ast
import logging
from typing import Set

logger = logging.getLogger("secara.taint")

# ── Source detector helpers ───────────────────────────────────────────────────

def _is_taint_source(node: ast.expr) -> bool:
    """Return True if *node* is a known user-input source."""
    src = ast.dump(node)

    # input() / eval() call — eval is also a sink; flag it via cmd_injection
    if isinstance(node, ast.Call):
        func = node.func
        # input()
        if isinstance(func, ast.Name) and func.id == "input":
            return True
        # os.environ.get / os.getenv
        if isinstance(func, ast.Attribute):
            if func.attr in {"get", "getenv"} and _attr_chain(func) in {
                "os.environ.get", "os.getenv", "environ.get"
            }:
                return True
        # request.get_json / request.args.get / etc.
        if isinstance(func, ast.Attribute) and func.attr in {
            "get", "get_json", "get_argument", "get_data"
        }:
            return True

    # sys.argv[*]
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute) and val.attr == "argv":
            return True

    # request.form, request.args, request.json, request.data
    if isinstance(node, ast.Attribute) and node.attr in {
        "form", "args", "json", "data", "body", "values",
        "POST", "GET", "FILES"
    }:
        return True

    # event["key"] / event.get(...)
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Name) and val.id in {"event", "environ", "params"}:
            return True

    return False


def _attr_chain(node: ast.Attribute) -> str:
    """Reconstruct a dotted attribute chain like 'os.environ.get'."""
    parts = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


# ── Sink detector helpers ─────────────────────────────────────────────────────

_SQL_SINK_ATTRS = {"execute", "executemany", "raw"}
_SQL_SINK_CHAIN_KEYWORDS = {"cursor", "execute", "query", "session", "connection", "db"}

_CMD_SINK_ATTRS = {"system", "popen", "call", "run", "Popen", "check_output",
                    "check_call", "getoutput", "getstatusoutput"}
_CMD_SINK_NAMES = {"eval", "exec", "compile"}

_CMD_MODULE_SINKS = {"os", "subprocess", "commands"}


def _is_sql_sink(call_node: ast.Call) -> bool:
    func = call_node.func
    if isinstance(func, ast.Attribute) and func.attr in _SQL_SINK_ATTRS:
        return True
    return False


def _is_cmd_sink(call_node: ast.Call) -> bool:
    func = call_node.func
    if isinstance(func, ast.Name) and func.id in _CMD_SINK_NAMES:
        return True
    if isinstance(func, ast.Attribute) and func.attr in _CMD_SINK_ATTRS:
        return True
    return False


# ── Main taint tracker ────────────────────────────────────────────────────────

class PythonTaintTracker:
    """
    Walks a single Python AST node (typically a FunctionDef) and tracks
    tainted variable names. Provides methods to check if a given AST call
    node uses tainted arguments.

    Optionally accepts a ModuleTaintGraph for interprocedural tracking.
    """

    def __init__(self, module_graph=None):
        self._tainted_names: Set[str] = set()
        self._module_graph = module_graph  # Optional[ModuleTaintGraph]

    def scan_function(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """
        Populate tainted names by walking all assignments in *func_node*.
        Also treats function parameters as potentially tainted if they look
        like request/event arguments.
        """
        # Mark function args as tainted if named suggestively
        for arg in func_node.args.args:
            if arg.arg in {"request", "req", "event", "context", "environ",
                            "params", "data", "payload"}:
                self._tainted_names.add(arg.arg)

        for node in ast.walk(func_node):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                self._handle_assignment(node)
            elif isinstance(node, ast.For):
                if isinstance(node.target, ast.Name):
                    # for x in request.args  → x is tainted
                    if _is_taint_source(node.iter):
                        self._tainted_names.add(node.target.id)

    def _handle_assignment(
        self, node: ast.Assign | ast.AnnAssign | ast.AugAssign
    ) -> None:
        # Determine LHS name(s)
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target] if node.value else []
            value = node.value
        else:  # AugAssign
            targets = [node.target]
            value = node.value

        if value is None:
            return

        rhs_tainted = self._is_tainted_expr(value) or _is_taint_source(value)

        # Interprocedural: if a function call returns tainted data, mark LHS
        if not rhs_tainted and self._module_graph and isinstance(value, ast.Call):
            func = value.func
            func_name = None
            if isinstance(func, ast.Name):
                func_name = func.id
            elif isinstance(func, ast.Attribute):
                func_name = func.attr
            if func_name and self._module_graph.does_return_tainted(func_name):
                rhs_tainted = True

        if rhs_tainted:
            for t in targets:
                if isinstance(t, ast.Name):
                    self._tainted_names.add(t.id)

    def _is_tainted_expr(self, node: ast.expr) -> bool:
        """Return True if *node* contains a reference to a tainted variable."""
        if isinstance(node, ast.Name):
            return node.id in self._tainted_names
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(
                self._is_tainted_expr(v)
                for v in ast.walk(node)
                if isinstance(v, ast.FormattedValue)
            )
        if isinstance(node, (ast.BinOp, ast.BoolOp)):
            return any(self._is_tainted_expr(child) for child in ast.walk(node)
                       if isinstance(child, ast.Name))
        if isinstance(node, ast.Call):
            return any(
                self._is_tainted_expr(arg) for arg in node.args + node.keywords
            )
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        # Walk sub-expressions generically
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr) and self._is_tainted_expr(child):
                return True
        return False

    def is_arg_tainted(self, call_node: ast.Call) -> bool:
        """Return True if any argument to *call_node* is tainted."""
        for arg in call_node.args:
            if self._is_tainted_expr(arg):
                return True
        for kw in call_node.keywords:
            if kw.value and self._is_tainted_expr(kw.value):
                return True
        return False

    @property
    def tainted_names(self) -> Set[str]:
        return frozenset(self._tainted_names)
