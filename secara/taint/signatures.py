"""Shared taint source/sanitizer signatures for Python analyzers."""
from __future__ import annotations

# Known sanitizer functions that neutralize direct injection primitives.
PY_SANITIZERS = {
    "int", "float", "bool",
    "quote", "quote_plus", "escape", "literal_eval",
}

# Known entrypoint parameter names.
PY_TAINTED_PARAM_NAMES = {
    "request", "req", "event", "context", "environ",
    "params", "data", "payload", "body", "form",
}

# Attribute-based source signals.
PY_SOURCE_ATTRS = {
    "form", "args", "json", "data", "body", "values",
    "POST", "GET", "FILES",
}

# Source call attribute signals.
PY_SOURCE_CALL_ATTRS = {"get", "get_json", "get_argument", "get_data"}
