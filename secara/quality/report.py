"""Quality report generation and budget regression checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from secara.quality.benchmark import (
    evaluate_benchmark,
    evaluate_benchmark_by_rule,
    load_benchmark_cases,
)


def build_quality_report(corpus_path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(corpus_path.read_text(encoding="utf-8")) or {}
    thresholds = data.get("rule_thresholds", {})
    cases = load_benchmark_cases(corpus_path)
    global_metrics = evaluate_benchmark(cases)
    per_rule = evaluate_benchmark_by_rule(cases)

    report = {
        "corpus": str(corpus_path),
        "global": {
            "precision": global_metrics.precision,
            "recall": global_metrics.recall,
            "f1": global_metrics.f1,
            "false_positive_rate": global_metrics.false_positive_rate,
        },
        "rules": {},
    }

    for rule_id, metrics in per_rule.items():
        bounds = thresholds.get(rule_id, {})
        p_req = float(bounds.get("precision", 0.0))
        r_req = float(bounds.get("recall", 0.0))
        report["rules"][rule_id] = {
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "false_positive_rate": metrics.false_positive_rate,
            "thresholds": {"precision": p_req, "recall": r_req},
            "pass": metrics.precision >= p_req and metrics.recall >= r_req,
        }
    return report


def render_quality_markdown(report: Dict[str, Any]) -> str:
    g = report["global"]
    lines = [
        "# Secara Quality Report",
        "",
        f"- Corpus: `{report['corpus']}`",
        f"- Global precision: `{g['precision']:.4f}`",
        f"- Global recall: `{g['recall']:.4f}`",
        f"- Global F1: `{g['f1']:.4f}`",
        f"- Global false_positive_rate: `{g['false_positive_rate']:.4f}`",
        "",
        "| Rule | Precision | Recall | F1 | FPR | Threshold(P/R) | Pass |",
        "|---|---:|---:|---:|---:|---|---|",
    ]
    for rule_id in sorted(report["rules"]):
        r = report["rules"][rule_id]
        t = r["thresholds"]
        lines.append(
            f"| {rule_id} | {r['precision']:.4f} | {r['recall']:.4f} | "
            f"{r['f1']:.4f} | {r['false_positive_rate']:.4f} | "
            f"{t['precision']:.2f}/{t['recall']:.2f} | {'yes' if r['pass'] else 'no'} |"
        )
    return "\n".join(lines) + "\n"


def write_report_files(report: Dict[str, Any], json_path: Path, md_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    md_path.write_text(render_quality_markdown(report), encoding="utf-8")


def check_quality_budget(
    current_report: Dict[str, Any],
    baseline_report: Dict[str, Any],
    budget: Dict[str, Any],
) -> List[str]:
    violations: List[str] = []

    g_budget = budget.get("global", {})
    p_drop = float(g_budget.get("precision_drop", 0.0))
    r_drop = float(g_budget.get("recall_drop", 0.0))
    fpr_inc = float(g_budget.get("fpr_increase", 0.0))

    cur_g = current_report["global"]
    base_g = baseline_report["global"]

    if cur_g["precision"] < base_g["precision"] - p_drop:
        violations.append("global precision regressed beyond budget")
    if cur_g["recall"] < base_g["recall"] - r_drop:
        violations.append("global recall regressed beyond budget")
    if cur_g["false_positive_rate"] > base_g["false_positive_rate"] + fpr_inc:
        violations.append("global false_positive_rate regressed beyond budget")

    per_budget = budget.get("per_rule", {})
    rp_drop = float(per_budget.get("precision_drop", 0.0))
    rr_drop = float(per_budget.get("recall_drop", 0.0))

    for rule_id, cur in current_report.get("rules", {}).items():
        base = baseline_report.get("rules", {}).get(rule_id)
        if not base:
            continue
        if cur["precision"] < base["precision"] - rp_drop:
            violations.append(f"{rule_id} precision regressed beyond budget")
        if cur["recall"] < base["recall"] - rr_drop:
            violations.append(f"{rule_id} recall regressed beyond budget")

    return violations


def load_json_file(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
