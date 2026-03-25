from pathlib import Path

import yaml

from secara.quality.benchmark import (
    evaluate_benchmark,
    evaluate_benchmark_by_rule,
    load_benchmark_cases,
)


def test_quality_gate_on_benchmark_corpus():
    corpus = Path(__file__).parent / "benchmark" / "corpus.yaml"
    cases = load_benchmark_cases(corpus)
    metrics = evaluate_benchmark(cases)
    per_rule = evaluate_benchmark_by_rule(cases)
    thresholds = yaml.safe_load(corpus.read_text(encoding="utf-8")).get("rule_thresholds", {})

    assert metrics.precision >= 0.95
    assert metrics.recall >= 0.95
    assert metrics.false_positive_rate <= 0.05
    for rule_id, bounds in thresholds.items():
        assert per_rule[rule_id].precision >= float(bounds.get("precision", 0.0))
        assert per_rule[rule_id].recall >= float(bounds.get("recall", 0.0))
