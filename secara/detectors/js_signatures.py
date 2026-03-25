"""Shared source/sanitizer signature fragments for JS/TS flow modeling."""
from __future__ import annotations

JS_SOURCE_FRAGMENTS = [
    r"req\.[A-Za-z0-9_]+",
    r"request\.[A-Za-z0-9_]+",
    r"params\.[A-Za-z0-9_]+",
    r"query\.[A-Za-z0-9_]+",
    r"body\.[A-Za-z0-9_]+",
    r"location\.[A-Za-z0-9_]+",
    r"document\.URL",
    r"userInput",
    r"getParam\s*\(",
]

JS_SANITIZER_FRAGMENTS = [
    r"encodeURIComponent",
    r"DOMPurify\.sanitize",
    r"sanitizeHtml",
    r"escapeHtml",
]
