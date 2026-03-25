"""Confidence calibration helpers for findings."""
from __future__ import annotations

from typing import List

from secara.output.models import Finding

_MEDIUM_CONF_RULES = {
    "SEC013",
    "CFG001", "CFG002", "CFG003",
    "CRY003", "CRY102",
    "LOG001", "RACE001", "MASS001", "TEMP001",
}

_LOW_CONF_RULES = {"SEC014"}

_TAINT_DRIVEN_RULES = {
    "SQL001",
    "CMD001", "CMD002",
    "SSRF001",
    "PATH001", "PATH002",
    "SSTI001",
    "SQL101", "CMD101", "CMD102", "CMD103", "SSRF101", "XSS101", "XSS102", "PATH101",
}


def calibrate_confidence(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        rule_id = f.rule_id.upper()

        if rule_id in _LOW_CONF_RULES:
            f.confidence = "LOW"
            continue
        if rule_id in _MEDIUM_CONF_RULES:
            f.confidence = "MEDIUM"
            continue

        if rule_id in _TAINT_DRIVEN_RULES:
            has_taint_evidence = bool(
                isinstance(f.evidence, dict)
                and f.evidence.get("taint_sources")
            )
            f.confidence = "HIGH" if has_taint_evidence else "MEDIUM"
            continue

        # Preserve existing explicit confidence where set by detectors;
        # keep high as default for deterministic patterns.
        if f.confidence not in {"HIGH", "MEDIUM", "LOW"}:
            f.confidence = "HIGH"

    return findings
