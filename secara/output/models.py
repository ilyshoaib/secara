"""
Data models for scan findings.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Finding:
    """Represents a single detected vulnerability or security issue."""

    rule_id: str
    rule_name: str
    severity: str          # HIGH | MEDIUM | LOW
    file_path: str
    line_number: int
    snippet: str           # The offending line(s) of code
    description: str       # Human-readable explanation
    fix: str               # Actionable fix suggestion
    language: str = ""
    confidence: str = "HIGH"  # HIGH | MEDIUM — reserved for future use

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)
