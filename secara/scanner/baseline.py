"""Baseline storage and filtering for 'new findings only' workflows."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Set

from secara.output.fingerprint import finding_fingerprint
from secara.output.models import Finding


def load_baseline_fingerprints(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict) and isinstance(raw.get("fingerprints"), list):
        return {str(x) for x in raw["fingerprints"]}
    return set()


def write_baseline(findings: Iterable[Finding], path: Path) -> None:
    fps = sorted({finding_fingerprint(f) for f in findings})
    payload = {"fingerprints": fps}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def filter_new_findings(findings: List[Finding], baseline_fps: Set[str]) -> List[Finding]:
    if not baseline_fps:
        return findings
    return [f for f in findings if finding_fingerprint(f) not in baseline_fps]
