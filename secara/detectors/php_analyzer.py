"""
PHP security analyzer — OWASP Top 10 coverage.

Detects:
  SQL Injection       — mysql_query($user_input), PDO without prepare
  Command Injection   — exec/system/shell_exec with user input, backtick operator
  LFI / RFI           — include/require with user-controlled path
  XSS                 — echo/print of unescaped $_GET, $_POST
  Path Traversal      — file_get_contents, fopen with user path
  SSRF                — curl_setopt CURLOPT_URL with user URL, file_get_contents
  Deserialization     — unserialize($_POST)
  Weak Crypto         — md5($password), sha1($password)
  Misconfiguration    — display_errors = On

Rules are loaded dynamically from secara/rules/builtin/php.yaml
"""
from __future__ import annotations

from secara.detectors.generic_analyzer import GenericRegexAnalyzer


class PHPAnalyzer(GenericRegexAnalyzer):
    """
    Tier-2 Analyzer for PHP (.php, .phtml, .php3, .php4, .php5) files.
    """

    def __init__(self) -> None:
        super().__init__("php")
