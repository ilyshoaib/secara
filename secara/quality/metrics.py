"""Core quality metrics used to evaluate detector accuracy."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class BinaryMetrics:
    """Confusion-matrix metrics for binary classification."""

    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
        )

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r) / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.true_positive + self.true_negative) / self.total if self.total else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positive + self.true_negative
        return self.false_positive / denom if denom else 0.0


def compute_binary_metrics(
    predictions: Iterable[bool],
    labels: Iterable[bool],
) -> BinaryMetrics:
    """
    Compute confusion-matrix totals from ordered predictions and labels.

    Raises:
        ValueError: if the input iterables have different lengths.
    """
    preds = list(predictions)
    expected = list(labels)

    if len(preds) != len(expected):
        raise ValueError("predictions and labels must have the same length")

    tp = fp = tn = fn = 0
    for pred, label in zip(preds, expected):
        if pred and label:
            tp += 1
        elif pred and not label:
            fp += 1
        elif not pred and not label:
            tn += 1
        else:
            fn += 1

    return BinaryMetrics(
        true_positive=tp,
        false_positive=fp,
        true_negative=tn,
        false_negative=fn,
    )
