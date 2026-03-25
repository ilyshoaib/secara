"""
Interprocedural Taint Analysis for Python.

Extends the single-function PythonTaintTracker by building a call graph
within a module and propagating taint across function boundaries.

Algorithm:
1. Parse the module into an AST.
2. Build a map of function_name → (FunctionDef, local_taint_sources)
3. Identify "seed" functions — those that directly receive tainted input
   (Flask/Django views, FastAPI routes, etc.)
4. For each call node, if the callee returns tainted data, mark the result
   as tainted in the caller.

This is intentionally conservative (no FP explosion):
- Only tracks within the same file
- Follows 1 level of function return taint propagation
- Sanitizer-aware: if a value passes through int(), str.strip(), bleach.clean(), etc.
  it is marked clean
"""
from __future__ import annotations

import ast
import logging
from typing import Dict, List, Optional, Set, Tuple

from secara.taint.signatures import PY_SANITIZERS, PY_TAINTED_PARAM_NAMES

logger = logging.getLogger("secara.taint.interproc")

# ── Sanitizer functions — if taint flows through these, it becomes clean ───────
# Keep additional sanitizers specific to interprocedural summary logic.
_SANITIZERS: Set[str] = set(PY_SANITIZERS) | {
    "bleach_clean", "sanitize",
    "html_escape", "xml_escape",
    "re_escape",
    "b64encode",
}


def _is_sanitized_call(call: ast.Call) -> bool:
    """Return True if *call* is a known sanitizer."""
    if isinstance(call.func, ast.Name):
        return call.func.id in _SANITIZERS
    if isinstance(call.func, ast.Attribute):
        return call.func.attr in _SANITIZERS
    return False


class FunctionTaintSummary:
    """Summarizes whether a function returns tainted data and what sources it uses."""

    def __init__(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.func_name = func_node.name
        self.returns_tainted = False
        self.tainted_params: Set[str] = set()
        self._func = func_node

    def __repr__(self) -> str:
        return f"<FunctionTaintSummary {self.func_name} returns_tainted={self.returns_tainted}>"


class ModuleTaintGraph:
    """
    Builds interprocedural taint graph for a Python module.

    Usage:
        graph = ModuleTaintGraph(tree)
        graph.build()
        # Ask: does calling 'helper_func' return tainted data?
        returns_tainted = graph.does_return_tainted("helper_func")
        # Expand taint set given a call to a function we know returns tainted
        graph.expand_tainted_names(call_node, tainted_names_set)
    """

    def __init__(self, tree: ast.Module) -> None:
        self._tree = tree
        self._summaries: Dict[str, FunctionTaintSummary] = {}
        self._built = False

    def build(self) -> None:
        if self._built:
            return
        # First pass: collect all function definitions
        for node in ast.walk(self._tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                summary = FunctionTaintSummary(node)
                self._analyze_function(node, summary)
                self._summaries[node.name] = summary
        self._built = True
        logger.debug("ModuleTaintGraph built: %d functions", len(self._summaries))

    def _analyze_function(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        summary: FunctionTaintSummary,
    ) -> None:
        """Determine if this function's return value may contain tainted data."""
        tainted: Set[str] = set()

        # Params
        for arg in func.args.args:
            if arg.arg in PY_TAINTED_PARAM_NAMES:
                tainted.add(arg.arg)
                summary.tainted_params.add(arg.arg)

        # Walk assignments
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                rhs = node.value
                if self._expr_is_tainted(rhs, tainted):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            tainted.add(t.id)
            elif isinstance(node, ast.AnnAssign) and node.value:
                if self._expr_is_tainted(node.value, tainted):
                    if isinstance(node.target, ast.Name):
                        tainted.add(node.target.id)

        # Check return statements
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value:
                if self._expr_is_tainted(node.value, tainted):
                    summary.returns_tainted = True
                    break

    def _expr_is_tainted(self, node: ast.expr, tainted: Set[str]) -> bool:
        """Recursively check if an expression references tainted variables."""
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted(node.value, tainted)
        if isinstance(node, ast.Call):
            if _is_sanitized_call(node):
                return False  # sanitizer cleans the value
            # If any argument is tainted, the call result is tainted
            for arg in node.args:
                if self._expr_is_tainted(arg, tainted):
                    return True
        if isinstance(node, ast.JoinedStr):
            for child in ast.walk(node):
                if isinstance(child, ast.Name) and child.id in tainted:
                    return True
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left, tainted) or self._expr_is_tainted(node.right, tainted)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value, tainted)
        return False

    def does_return_tainted(self, func_name: str) -> bool:
        """Return True if the named function is known to return tainted data."""
        summary = self._summaries.get(func_name)
        return summary.returns_tainted if summary else False

    def expand_tainted_names(
        self,
        assign_value: ast.expr,
        tainted_names: Set[str],
        lhs_name: str,
    ) -> bool:
        """
        If *assign_value* is a call to a function that returns tainted,
        add *lhs_name* to *tainted_names* and return True.
        """
        if not isinstance(assign_value, ast.Call):
            return False
        func = assign_value.func
        func_name = None
        if isinstance(func, ast.Name):
            func_name = func.id
        elif isinstance(func, ast.Attribute):
            func_name = func.attr

        if func_name and self.does_return_tainted(func_name):
            tainted_names.add(lhs_name)
            return True
        return False
