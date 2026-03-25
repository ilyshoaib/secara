"""Stable finding fingerprint utilities for triage continuity."""
from __future__ import annotations

import hashlib

from secara.output.models import Finding


def finding_fingerprint(f: Finding) -> str:
    """
    Compute a stable fingerprint for a finding.
    Uses structural fields that should survive formatting changes.
    """
    raw = "|".join(
        [
            f.rule_id,
            f.file_path,
            str(f.line_number),
            (f.snippet or "").strip(),
            (f.language or "").strip(),
        ]
    )
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()
