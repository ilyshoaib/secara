"""Benchmark helpers for quality-gate style detector evaluation."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import yaml

from secara.detectors.config_analyzer import ConfigAnalyzer
from secara.detectors.js_analyzer import JSAnalyzer
from secara.detectors.python_analyzer import PythonAnalyzer
from secara.detectors.secrets_detector import SecretsDetector
from secara.output.confidence import calibrate_confidence
from secara.output.models import CONFIDENCE_ORDER, Finding
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
    findings = _predict_case_findings(case)
    if case.expected_rule:
        return any(f.rule_id == case.expected_rule for f in findings)
    return bool(findings)


def _predict_case_findings(case: BenchmarkCase) -> List[Finding]:
    target = Path(f"benchmark{case.extension}")
    if case.detector == "python":
        findings = PythonAnalyzer().analyze(target, case.code)
    elif case.detector == "javascript":
        findings = JSAnalyzer().analyze(target, case.code)
    elif case.detector == "config":
        findings = ConfigAnalyzer().analyze(target, case.code)
    elif case.detector == "secrets":
        findings = SecretsDetector().analyze(target, case.code)
    else:
        raise ValueError(f"Unsupported benchmark detector: {case.detector}")

    # Benchmark quality should reflect production scan behavior, including confidence
    # calibration.
    return calibrate_confidence(findings)


def evaluate_benchmark_confidence(cases: Iterable[BenchmarkCase]) -> Dict[str, Dict[str, float]]:
    """
    Compute confidence-bucket quality metrics from benchmark cases.

    Returns a mapping with keys HIGH/MEDIUM/LOW and per-level aggregates:
    predictions, true_positive, false_positive, precision.
    """
    levels = ("HIGH", "MEDIUM", "LOW")
    stats: Dict[str, Dict[str, float]] = {
        lvl: {"predictions": 0.0, "true_positive": 0.0, "false_positive": 0.0, "precision": 0.0}
        for lvl in levels
    }

    for case in cases:
        findings = _predict_case_findings(case)
        if case.expected_rule:
            findings = [f for f in findings if f.rule_id == case.expected_rule]
        if not findings:
            continue

        # Use strongest confidence for the case-level prediction.
        predicted = min(
            findings,
            key=lambda f: CONFIDENCE_ORDER.get(f.confidence.upper(), 99),
        )
        level = predicted.confidence.upper()
        if level not in stats:
            continue

        stats[level]["predictions"] += 1
        if case.expect_finding:
            stats[level]["true_positive"] += 1
        else:
            stats[level]["false_positive"] += 1

    for level in levels:
        tp = stats[level]["true_positive"]
        fp = stats[level]["false_positive"]
        denom = tp + fp
        stats[level]["precision"] = (tp / denom) if denom else 0.0

    return stats


def evaluate_benchmark(cases: Iterable[BenchmarkCase]) -> BinaryMetrics:
    """Evaluate benchmark cases and return binary metrics."""
    case_list = list(cases)
    predictions = [_predict_case(c) for c in case_list]
    labels = [c.expect_finding for c in case_list]
    return compute_binary_metrics(predictions=predictions, labels=labels)


def evaluate_benchmark_by_rule(cases: Iterable[BenchmarkCase]) -> Dict[str, BinaryMetrics]:
    """
    Compute per-rule metrics for cases that define expected_rule.
    """
    grouped: Dict[str, List[BenchmarkCase]] = {}
    for case in cases:
        if not case.expected_rule:
            continue
        grouped.setdefault(case.expected_rule, []).append(case)

    out: Dict[str, BinaryMetrics] = {}
    for rule, rule_cases in grouped.items():
        predictions = [_predict_case(c) for c in rule_cases]
        labels = [c.expect_finding for c in rule_cases]
        out[rule] = compute_binary_metrics(predictions=predictions, labels=labels)
    return out
