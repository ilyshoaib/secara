from pathlib import Path

from secara.quality.report import (
    build_quality_report,
    check_quality_budget,
)


def test_build_quality_report_contains_global_and_rules():
    report = build_quality_report(Path("tests/benchmark/corpus.yaml"))
    assert "global" in report
    assert "confidence" in report
    assert "rules" in report
    assert "SQL001" in report["rules"]
    assert "HIGH" in report["confidence"]


def test_check_quality_budget_flags_regression():
    baseline = {
        "global": {"precision": 1.0, "recall": 1.0, "false_positive_rate": 0.0},
        "confidence": {"HIGH": {"precision": 1.0}},
        "rules": {"SQL001": {"precision": 1.0, "recall": 1.0}},
    }
    current = {
        "global": {"precision": 0.8, "recall": 0.9, "false_positive_rate": 0.2},
        "confidence": {"HIGH": {"precision": 0.8}},
        "rules": {"SQL001": {"precision": 0.7, "recall": 0.8}},
    }
    budget = {
        "global": {"precision_drop": 0.01, "recall_drop": 0.01, "fpr_increase": 0.01},
        "per_rule": {"precision_drop": 0.01, "recall_drop": 0.01},
        "confidence": {"high_precision_drop": 0.01},
    }
    violations = check_quality_budget(current, baseline, budget)
    assert violations
    assert any("global precision" in v for v in violations)
    assert any("HIGH confidence precision" in v for v in violations)
