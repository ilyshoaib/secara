"""Benchmark helpers for quality-gate style detector evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import yaml

from secara.detectors.python_analyzer import PythonAnalyzer
from secara.detectors.secrets_detector import SecretsDetector
from secara.quality.metrics import BinaryMetrics, compute_binary_metrics


@dataclass(frozen=True)
class BenchmarkCase:
    """Single labeled benchmark case."""

    name: str
    detector: str
    extension: str
    code: str
    expect_finding: bool
    expected_rule: Optional[str] = None


def load_benchmark_cases(path: Path) -> List[BenchmarkCase]:
    """Load benchmark cases from a YAML file."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw_cases = data.get("cases", [])
    cases: List[BenchmarkCase] = []
    for item in raw_cases:
        cases.append(
            BenchmarkCase(
                name=str(item["name"]),
                detector=str(item["detector"]),
                extension=str(item.get("extension", ".txt")),
                code=str(item["code"]),
                expect_finding=bool(item["expect_finding"]),
                expected_rule=item.get("expected_rule"),
            )
        )
    return cases


def _predict_case(case: BenchmarkCase) -> bool:
    if case.detector == "python":
        findings = PythonAnalyzer().analyze(Path(f"benchmark{case.extension}"), case.code)
    elif case.detector == "secrets":
        findings = SecretsDetector().analyze(Path(f"benchmark{case.extension}"), case.code)
    else:
        raise ValueError(f"Unsupported benchmark detector: {case.detector}")

    if case.expected_rule:
        return any(f.rule_id == case.expected_rule for f in findings)
    return bool(findings)


def evaluate_benchmark(cases: Iterable[BenchmarkCase]) -> BinaryMetrics:
    """Evaluate benchmark cases and return binary metrics."""
    case_list = list(cases)
    predictions = [_predict_case(c) for c in case_list]
    labels = [c.expect_finding for c in case_list]
    return compute_binary_metrics(predictions=predictions, labels=labels)
