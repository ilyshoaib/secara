from pathlib import Path

from secara.quality.benchmark import evaluate_benchmark, load_benchmark_cases


def test_quality_gate_on_benchmark_corpus():
    corpus = Path(__file__).parent / "benchmark" / "corpus.yaml"
    cases = load_benchmark_cases(corpus)
    metrics = evaluate_benchmark(cases)

    assert metrics.precision >= 0.95
    assert metrics.recall >= 0.95
    assert metrics.false_positive_rate <= 0.05
