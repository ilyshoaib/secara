"""
Java / Kotlin security analyzer — OWASP Top 10 coverage.

Detects:
  SQL Injection          — PreparedStatement bypass, MyBatis ${} interpolation
  Command Injection      — Runtime.exec(), ProcessBuilder with dynamic args
  XXE                    — DocumentBuilderFactory without disabling external entities
  Insecure Deserialization — ObjectInputStream.readObject()
  SSRF                   — new URL(userInput).openConnection()
  Weak Crypto            — MD5/SHA-1, java.util.Random
  Path Traversal         — new File(request.getParameter())
  CSRF Disabled          — Spring Security csrf().disable()
  Log Injection          — logger.info(userInput)

Rules are loaded dynamically from secara/rules/builtin/java.yaml
"""
from __future__ import annotations

from secara.detectors.generic_analyzer import GenericRegexAnalyzer


class JavaAnalyzer(GenericRegexAnalyzer):
    """
    Tier-2 Analyzer for Java (.java) and Kotlin (.kt, .kts) files.
    """

    def __init__(self) -> None:
        super().__init__("java")
