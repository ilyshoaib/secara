from secara.quality.metrics import compute_binary_metrics


def test_compute_binary_metrics_values():
    metrics = compute_binary_metrics(
        predictions=[True, True, False, False, True],
        labels=[True, False, False, True, True],
    )

    assert metrics.true_positive == 2
    assert metrics.false_positive == 1
    assert metrics.true_negative == 1
    assert metrics.false_negative == 1
    assert metrics.total == 5
    assert metrics.precision == 2 / 3
    assert metrics.recall == 2 / 3
    assert metrics.f1 == 2 / 3
    assert metrics.accuracy == 3 / 5
    assert metrics.false_positive_rate == 1 / 2


def test_compute_binary_metrics_length_mismatch():
    try:
        compute_binary_metrics(predictions=[True], labels=[True, False])
    except ValueError as exc:
        assert "same length" in str(exc)
    else:
        assert False, "Expected ValueError for length mismatch"
