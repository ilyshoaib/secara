"""
Abstract base class for all detectors.
Every detector takes a file path + content and returns a list of Findings.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from secara.output.models import Finding


class BaseDetector(ABC):
    """Common interface for all language analyzers and detectors."""

    @abstractmethod
    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        """
        Analyze *content* from *file_path* and return any Findings.
        Must never raise — catch exceptions internally and log them.
        """
        ...

    @staticmethod
    def get_snippet(lines: list[str], line_number: int, context: int = 0) -> str:
        """
        Return the source line at *line_number* (1-indexed), stripped.
        *context* lines of surrounding code are NOT included here to keep
        output clean; the full line is sufficient for most findings.
        """
        idx = line_number - 1
        if 0 <= idx < len(lines):
            return lines[idx].rstrip()
        return ""
