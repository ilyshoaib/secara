"""
Ruby / Rails security analyzer — OWASP Top 10 coverage.

Detects:
  SQL Injection        — ActiveRecord .where("...#{params}")
  Command Injection    — system(), exec(), backtick #{} interpolation
  Mass Assignment      — Model.create(params) without .permit
  XSS                  — .html_safe on user-controlled data
  Path Traversal       — File.read(params[:path])
  SSRF                 — Net::HTTP.get(URI(params[:url]))
  Deserialization      — Marshal.load(user_data)
  Weak Crypto          — Digest::MD5.hexdigest(password)
  Dynamic Dispatch     — obj.send(params[:method])

Rules are loaded dynamically from secara/rules/builtin/ruby.yaml
"""
from __future__ import annotations

from secara.detectors.generic_analyzer import GenericRegexAnalyzer


class RubyAnalyzer(GenericRegexAnalyzer):
    """
    Tier-2 Analyzer for Ruby (.rb) and ERB (.erb) files.
    """

    def __init__(self) -> None:
        super().__init__("ruby")
