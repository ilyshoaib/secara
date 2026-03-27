"""
Secara CLI — entry point.

Commands:
    secara scan <path>  [--json] [--verbose] [--severity LEVEL] [--no-cache]
"""
from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import statistics
import sys
import time
from datetime import date
from pathlib import Path
from typing import List

import click

from secara import __version__
from secara.scanner.file_scanner import collect_files, scan_files_parallel
from secara.scanner.incremental import collect_changed_files
from secara.scanner.incremental import collect_impacted_files, select_shard
from secara.scanner.baseline import (
    filter_new_findings,
    load_baseline_fingerprints,
    write_baseline as write_baseline_snapshot,
)
from secara.scanner.language_engine import get_language_info, LanguageTier
from secara.scanner.cache import FileCache
from secara.detectors.secrets_detector import SecretsDetector
from secara.detectors.python_analyzer import PythonAnalyzer
from secara.detectors.js_analyzer import JSAnalyzer
from secara.detectors.shell_analyzer import ShellAnalyzer
from secara.detectors.config_analyzer import ConfigAnalyzer
from secara.detectors.go_analyzer import GoAnalyzer
from secara.detectors.java_analyzer import JavaAnalyzer
from secara.detectors.php_analyzer import PHPAnalyzer
from secara.detectors.ruby_analyzer import RubyAnalyzer
from secara.output.models import Finding
from secara.output.confidence import calibrate_confidence
from secara.output.formatter import (
    filter_by_confidence,
    filter_findings,
    render_findings,
)
from secara.quality.history import append_history, read_history, DEFAULT_HISTORY_PATH
from secara.quality.report import (
    build_quality_report,
    check_quality_budget,
    load_json_file,
    write_report_files,
)
from secara.config import load_config

# ── IGNORE ANNOTATION ────────────────────────────────────────────────────────
IGNORE_COMMENT = "secara: ignore"   # suppresses all findings on this line
# Also supports: secara: ignore[SQL001,CMD001]  — suppress specific rules only

# ── Logging ───────────────────────────────────────────────────────────────────
def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s [%(name)s] %(message)s",
        level=level,
        stream=sys.stderr,
    )


# ── Analyzer registry ─────────────────────────────────────────────────────────
_SECRETS_DETECTOR = SecretsDetector()
_PYTHON_ANALYZER  = PythonAnalyzer()
_JS_ANALYZER      = JSAnalyzer()
_SHELL_ANALYZER   = ShellAnalyzer()
_CONFIG_ANALYZER  = ConfigAnalyzer()
_GO_ANALYZER      = GoAnalyzer()
_JAVA_ANALYZER    = JavaAnalyzer()
_PHP_ANALYZER     = PHPAnalyzer()
_RUBY_ANALYZER    = RubyAnalyzer()
_DEP_SCANNER      = None  # Lazy-loaded on first use


def _is_suppressed(
    line: str,
    rule_id: str,
    enforce_metadata: bool = False,
) -> bool:
    """Return True if the line has a valid secara ignore annotation covering rule_id."""
    if IGNORE_COMMENT not in line:
        return False
    covered = True
    m = re.search(r"secara:\s*ignore\[([^\]]+)\]", line)
    if m:
        suppressed_ids = {r.strip() for r in m.group(1).split(",")}
        covered = rule_id in suppressed_ids
    if not covered:
        return False

    reason = re.search(r"\breason\s*=\s*([^\s]+)", line)
    until = re.search(r"\buntil\s*=\s*(\d{4}-\d{2}-\d{2})", line)

    if until:
        try:
            expiry = date.fromisoformat(until.group(1))
        except ValueError:
            return False
        if date.today() > expiry:
            return False

    if enforce_metadata:
        return bool(reason and until)
    return True


def _analyze_file(
    file_path: Path,
    cache: "FileCache",
    cfg=None,
    enforce_suppression_metadata: bool = False,
) -> List[Finding]:
    """
    Run all applicable detectors on *file_path*.
    Returns an empty list on any error.
    """
    if cfg is None:
        cfg = load_config()

    # ── Path exclusion check ──────────────────────────────────────────────
    if cfg.is_path_excluded(file_path, Path.cwd()):
        return []

    try:
        st = file_path.stat()
        cached = cache.get(file_path, stat_result=st)
        if cached is not None:
            from secara.output.models import Finding as F
            return [F(**d) for d in cached] if cached else []

        raw = file_path.read_bytes()
    except OSError:
        return []

    file_hash = hashlib.sha256(raw).hexdigest()
    cached = cache.get(file_path, file_hash=file_hash, stat_result=st)
    if cached is not None:
        from secara.output.models import Finding as F
        return [F(**d) for d in cached] if cached else []

    content = raw.decode("utf-8", errors="replace")

    findings: List[Finding] = []
    tier, language = get_language_info(file_path)

    if tier is None:
        return []

    # ── Always run secrets detector ───────────────────────────────────────
    findings.extend(_SECRETS_DETECTOR.analyze(file_path, content))

    # ── Tier 1: Deep analysis ─────────────────────────────────────────────
    if tier == LanguageTier.TIER1:
        if language == "python":
            findings.extend(_PYTHON_ANALYZER.analyze(file_path, content))
        elif language in {"javascript", "typescript"}:
            findings.extend(_JS_ANALYZER.analyze(file_path, content))

    # ── Tier 2: Basic detection ───────────────────────────────────────────
    elif tier == LanguageTier.TIER2:
        if language == "bash":
            findings.extend(_SHELL_ANALYZER.analyze(file_path, content))
        elif language in {"json", "yaml"}:
            findings.extend(_CONFIG_ANALYZER.analyze(file_path, content))
        elif language == "go":
            findings.extend(_GO_ANALYZER.analyze(file_path, content))
        elif language in {"java", "kotlin"}:
            findings.extend(_JAVA_ANALYZER.analyze(file_path, content))
        elif language == "php":
            findings.extend(_PHP_ANALYZER.analyze(file_path, content))
        elif language == "ruby":
            findings.extend(_RUBY_ANALYZER.analyze(file_path, content))

    # ── Secrets-only tier ─────────────────────────────────────────────────
    elif tier == LanguageTier.SECRETS_ONLY:
        findings.extend(_CONFIG_ANALYZER.analyze(file_path, content))

    # ── Filter inline ignores + config-disabled rules ─────────────────────
    lines = content.splitlines()
    filtered = []
    for f in findings:
        # Config-level rule disable
        if cfg.is_rule_disabled(f.rule_id):
            continue
        # Inline suppression
        line_idx = f.line_number - 1
        if 0 <= line_idx < len(lines):
            if _is_suppressed(
                lines[line_idx],
                f.rule_id,
                enforce_metadata=enforce_suppression_metadata,
            ):
                continue
        filtered.append(f)

    cache.set(file_path, filtered, file_hash=file_hash, stat_result=st)
    return filtered



# ── CLI Definition ────────────────────────────────────────────────────────────
BANNER = rf"""
 ____                           
/ ___|  ___  ___ __ _ _ __ __ _ 
\___ \ / _ \/ __/ _` | '__/ _` |
 ___) |  __/ (_| (_| | | | (_| |
|____/ \___|\___\__,_|_|  \__,_|

[bold cyan]Static Code Security Scanner[/bold cyan]  v{__version__}
"""

POLICY_PRESETS = {
    "balanced": {"severity": "LOW", "min_confidence": "LOW"},
    "strict": {"severity": "MEDIUM", "min_confidence": "MEDIUM"},
}


@click.group()
@click.version_option(__version__, "--version", "-V", prog_name="secara")
def cli() -> None:
    """
    \b
    Secara — Static Code Security Scanner
    Detects real, exploitable vulnerabilities with high accuracy.
    """
    pass


@cli.command("scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--json", "use_json",
    is_flag=True, default=False,
    help="Output results as JSON (machine-readable).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True, default=False,
    help="Show full descriptions and fix details.",
)
@click.option(
    "--sarif",
    is_flag=True, default=False,
    help="Output results in SARIF format for CI/CD.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path), default=None,
    help="Write output to file (useful with --sarif or --json).",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option(
    "--min-confidence",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Minimum confidence level to report.",
)
@click.option(
    "--no-cache",
    is_flag=True, default=False,
    help="Disable file cache (re-scan everything).",
)
@click.option(
    "--workers", "-w",
    type=int, default=8, show_default=True,
    help="Number of parallel worker threads.",
)
@click.option(
    "--changed-only",
    is_flag=True,
    default=False,
    help="Scan only changed/untracked files in git.",
)
@click.option(
    "--impacted-only",
    is_flag=True,
    default=False,
    help="Scan changed files plus basic dependent files (impact graph mode).",
)
@click.option(
    "--shard-index",
    type=int,
    default=None,
    help="Shard index (0-based) for deterministic split scanning.",
)
@click.option(
    "--shard-count",
    type=int,
    default=None,
    help="Total shard count for deterministic split scanning.",
)
@click.option(
    "--baseline",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to baseline fingerprints JSON (filter out existing findings).",
)
@click.option(
    "--write-baseline",
    type=click.Path(path_type=Path),
    default=None,
    help="Write current findings as baseline fingerprints JSON.",
)
@click.option(
    "--policy",
    type=click.Choice(["balanced", "strict"], case_sensitive=False),
    default=None,
    help="Policy pack preset.",
)
@click.option(
    "--enforce-suppression-metadata",
    is_flag=True,
    default=False,
    help="Require suppression comments to include reason= and until=YYYY-MM-DD.",
)
@click.option(
    "--profile-scan",
    is_flag=True,
    default=False,
    help="Show stage timings and cache stats for scan performance profiling.",
)
def scan_command(
    path: Path,
    use_json: bool,
    verbose: bool,
    sarif: bool,
    output: Path | None,
    severity: str,
    min_confidence: str,
    no_cache: bool,
    workers: int,
    changed_only: bool,
    impacted_only: bool,
    shard_index: int | None,
    shard_count: int | None,
    baseline: Path | None,
    write_baseline: Path | None,
    policy: str | None,
    enforce_suppression_metadata: bool,
    profile_scan: bool,
) -> None:
    """
    Scan a file or directory for security vulnerabilities.

    \b
    Examples:
      secara scan ./src
      secara scan app.py --severity HIGH
      secara scan . --json > results.json
      secara scan . --verbose --no-cache
    """
    _configure_logging(verbose)

    # ── Load project config ───────────────────────────────────────────────
    cfg = load_config(path if path.is_dir() else path.parent)

    # ── Banner (non-JSON mode) ────────────────────────────────────────────
    if not use_json and not sarif:
        try:
            from rich.console import Console
            from rich.padding import Padding
            c = Console()
            c.print(BANNER, highlight=False)
        except ImportError:
            print(f"Secara v{__version__} — Static Code Security Scanner\n")

    start_time = time.perf_counter()
    cache = FileCache(enabled=not no_cache)
    stage_collect_s = 0.0
    stage_analyze_s = 0.0
    stage_render_s = 0.0
    stage_filter_s = 0.0

    # ── Collect files ─────────────────────────────────────────────────────
    t_collect_start = time.perf_counter()
    effective_policy = (policy or cfg.policy or "balanced").lower()
    policy_cfg = POLICY_PRESETS.get(effective_policy, POLICY_PRESETS["balanced"])
    severity = severity.upper()
    min_confidence = min_confidence.upper()
    if severity == "LOW":
        severity = policy_cfg["severity"]
    if min_confidence == "LOW":
        min_confidence = policy_cfg["min_confidence"]

    if changed_only and impacted_only:
        raise click.UsageError("Use either --changed-only or --impacted-only, not both.")

    if (shard_index is None) != (shard_count is None):
        raise click.UsageError("Both --shard-index and --shard-count are required together.")
    if shard_count is not None:
        if shard_count <= 0:
            raise click.UsageError("--shard-count must be > 0.")
        if shard_index < 0 or shard_index >= shard_count:
            raise click.UsageError("--shard-index must be in range [0, shard-count).")

    if impacted_only:
        git_root = path if path.is_dir() else path.parent
        files = collect_impacted_files(git_root.resolve())
        if path.is_dir():
            root_resolved = path.resolve()
            files = [f for f in files if root_resolved in (f, *f.parents)]
        else:
            files = [f for f in files if f.resolve() == path.resolve()]
    elif changed_only:
        git_root = path if path.is_dir() else path.parent
        files = collect_changed_files(git_root.resolve())
        if path.is_dir():
            root_resolved = path.resolve()
            files = [f for f in files if root_resolved in (f, *f.parents)]
        else:
            files = [f for f in files if f.resolve() == path.resolve()]
    else:
        files = collect_files(path)
    files = sorted(files, key=lambda p: str(p.resolve()))
    if shard_count is not None:
        files = select_shard(files, shard_index=shard_index, shard_count=shard_count)
    stage_collect_s = time.perf_counter() - t_collect_start
    if not use_json and not sarif and files:
        try:
            from rich.console import Console
            Console().print(
                f"[dim]Scanning [bold]{len(files)}[/bold] files "
                f"({'cached' if not no_cache else 'no cache'})…[/dim]\n"
            )
        except ImportError:
            print(f"Scanning {len(files)} files…\n")
    elif not files:
        if not use_json and not sarif:
            print("No scannable files found.")
        sys.exit(0)

    # ── Parallel scan ─────────────────────────────────────────────────────
    # CLI --workers flag overrides secara.yaml workers.
    # If both are untouched defaults (8), scale automatically with CPU count.
    if workers == 8 and cfg.workers == 8:
        effective_workers = min(32, max(4, (os.cpu_count() or 4) * 4))
    else:
        effective_workers = workers if workers != 8 else cfg.workers

    def analyze(fp: Path) -> List[Finding]:
        return _analyze_file(
            fp,
            cache,
            cfg,
            enforce_suppression_metadata=enforce_suppression_metadata,
        )

    t_analyze_start = time.perf_counter()
    all_findings = scan_files_parallel(files, analyze, max_workers=effective_workers)
    all_findings = calibrate_confidence(all_findings)
    stage_analyze_s = time.perf_counter() - t_analyze_start

    # ── Persist cache ─────────────────────────────────────────────────────
    cache.save()

    elapsed = time.perf_counter() - start_time

    # ── Filter by severity ────────────────────────────────────────────────
    t_filter_start = time.perf_counter()
    filtered = filter_findings(all_findings, severity)
    filtered = filter_by_confidence(filtered, min_confidence)

    baseline_path = baseline or (Path.cwd() / ".secara" / "baseline.json")
    if baseline:
        baseline_fps = load_baseline_fingerprints(baseline_path)
        filtered = filter_new_findings(filtered, baseline_fps)

    if write_baseline:
        write_baseline_snapshot(filtered, write_baseline)
    stage_filter_s = time.perf_counter() - t_filter_start

    # ── Render ────────────────────────────────────────────────────────────
    t_render_start = time.perf_counter()
    render_findings(
        filtered,
        use_json=use_json,
        use_sarif=sarif,
        output_file=str(output) if output else None,
        verbose=verbose,
    )
    stage_render_s = time.perf_counter() - t_render_start

    if not use_json and not sarif:
        try:
            from rich.console import Console
            Console().print(
                f"[dim]⏱  Scan completed in {elapsed:.2f}s — "
                f"{len(files)} files, {len(all_findings)} total findings "
                f"({len(filtered)} shown at {severity}+/{min_confidence}+)[/dim]\n"
            )
        except ImportError:
            print(
                f"\nScan completed in {elapsed:.2f}s — "
                f"{len(files)} files, {len(all_findings)} findings\n"
            )

    if profile_scan:
        profile = {
            "total_s": round(elapsed, 4),
            "collect_s": round(stage_collect_s, 4),
            "analyze_s": round(stage_analyze_s, 4),
            "filter_s": round(stage_filter_s, 4),
            "render_s": round(stage_render_s, 4),
            "files": len(files),
            "workers": effective_workers,
            "cache": cache.stats(),
        }
        if use_json or sarif:
            click.echo(json.dumps({"scan_profile": profile}, indent=2), err=True)
        else:
            click.echo("\nScan Profile:")
            click.echo(
                f"- total={profile['total_s']}s collect={profile['collect_s']}s "
                f"analyze={profile['analyze_s']}s filter={profile['filter_s']}s "
                f"render={profile['render_s']}s"
            )
            click.echo(
                f"- files={profile['files']} workers={profile['workers']} "
                f"cache_hits={profile['cache'].get('hits', 0)} "
                f"cache_misses={profile['cache'].get('misses', 0)}"
            )

    try:
        append_history(
            {
                "duration_s": round(elapsed, 4),
                "files_scanned": len(files),
                "findings_total": len(all_findings),
                "findings_shown": len(filtered),
                "severity": severity,
                "min_confidence": min_confidence,
                "policy": effective_policy,
                "changed_only": changed_only,
            }
        )
    except OSError:
        pass

    # ── Exit code ─────────────────────────────────────────────────────────
    sys.exit(1 if filtered else 0)


def main() -> None:
    cli()


@cli.command("metrics")
@click.option("--json", "use_json", is_flag=True, default=False, help="Output metrics history as JSON.")
@click.option("--limit", type=int, default=20, show_default=True, help="Number of recent scans to show.")
@click.option("--rules", is_flag=True, default=False, help="Show benchmark per-rule quality metrics.")
@click.option(
    "--corpus",
    type=click.Path(path_type=Path),
    default=Path("tests/benchmark/corpus.yaml"),
    show_default=True,
    help="Benchmark corpus file to evaluate when --rules is used.",
)
def metrics_command(use_json: bool, limit: int, rules: bool, corpus: Path) -> None:
    """Show historical scan metrics trends."""
    if rules:
        report = build_quality_report(corpus)
        if use_json:
            click.echo(json.dumps(report, indent=2))
            return
        click.echo("Per-Rule Quality Metrics:")
        for rule_id in sorted(report["rules"]):
            r = report["rules"][rule_id]
            click.echo(
                f"- {rule_id}: P={r['precision']:.3f} R={r['recall']:.3f} "
                f"F1={r['f1']:.3f} pass={'yes' if r['pass'] else 'no'}"
            )
        return

    rows = read_history(DEFAULT_HISTORY_PATH)
    if limit > 0:
        rows = rows[-limit:]
    if use_json:
        click.echo(json.dumps(rows, indent=2))
        return
    if not rows:
        click.echo("No scan history found.")
        return
    click.echo("Recent Scan Metrics:")
    for row in rows:
        ts = row.get("timestamp", "?")
        dur = row.get("duration_s", "?")
        files = row.get("files_scanned", "?")
        shown = row.get("findings_shown", "?")
        policy = row.get("policy", "balanced")
        click.echo(f"- {ts}  files={files} findings={shown} duration={dur}s policy={policy}")


@cli.command("benchmark")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--runs", type=int, default=5, show_default=True, help="Measured benchmark runs.")
@click.option("--warmup", type=int, default=1, show_default=True, help="Warmup runs.")
@click.option(
    "--workers", "-w",
    type=int, default=8, show_default=True,
    help="Number of parallel worker threads.",
)
@click.option(
    "--no-cache",
    is_flag=True, default=False,
    help="Disable file cache (re-scan everything).",
)
@click.option(
    "--changed-only",
    is_flag=True,
    default=False,
    help="Benchmark changed/untracked files in git only.",
)
@click.option(
    "--impacted-only",
    is_flag=True,
    default=False,
    help="Benchmark changed files plus dependents (impact graph mode).",
)
@click.option(
    "--json", "use_json",
    is_flag=True, default=False,
    help="Output benchmark summary as JSON.",
)
def benchmark_command(
    path: Path,
    runs: int,
    warmup: int,
    workers: int,
    no_cache: bool,
    changed_only: bool,
    impacted_only: bool,
    use_json: bool,
) -> None:
    """Benchmark scan throughput for CI trend tracking."""
    if runs <= 0:
        raise click.UsageError("--runs must be > 0.")
    if warmup < 0:
        raise click.UsageError("--warmup must be >= 0.")
    if changed_only and impacted_only:
        raise click.UsageError("Use either --changed-only or --impacted-only, not both.")

    cfg = load_config(path if path.is_dir() else path.parent)
    if impacted_only:
        git_root = path if path.is_dir() else path.parent
        files = collect_impacted_files(git_root.resolve())
        if path.is_dir():
            root_resolved = path.resolve()
            files = [f for f in files if root_resolved in (f, *f.parents)]
        else:
            files = [f for f in files if f.resolve() == path.resolve()]
    elif changed_only:
        git_root = path if path.is_dir() else path.parent
        files = collect_changed_files(git_root.resolve())
        if path.is_dir():
            root_resolved = path.resolve()
            files = [f for f in files if root_resolved in (f, *f.parents)]
        else:
            files = [f for f in files if f.resolve() == path.resolve()]
    else:
        files = collect_files(path)
    files = sorted(files, key=lambda p: str(p.resolve()))
    if not files:
        click.echo(json.dumps({"error": "No scannable files found."}) if use_json else "No scannable files found.")
        sys.exit(0)

    effective_workers = workers if workers != 8 else cfg.workers
    if workers == 8 and cfg.workers == 8:
        effective_workers = min(32, max(4, (os.cpu_count() or 4) * 4))

    def run_once() -> tuple[float, int]:
        cache = FileCache(enabled=not no_cache)

        def analyze(fp: Path) -> List[Finding]:
            return _analyze_file(fp, cache, cfg)

        t0 = time.perf_counter()
        findings = scan_files_parallel(files, analyze, max_workers=effective_workers)
        findings = calibrate_confidence(findings)
        cache.save()
        return (time.perf_counter() - t0), len(findings)

    for _ in range(warmup):
        run_once()

    durations: List[float] = []
    findings_count = 0
    for _ in range(runs):
        dur, findings_count = run_once()
        durations.append(dur)

    ordered = sorted(durations)
    idx95 = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * 0.95))))
    summary = {
        "files": len(files),
        "workers": effective_workers,
        "runs": runs,
        "warmup": warmup,
        "no_cache": no_cache,
        "findings_total_last_run": findings_count,
        "timings_s": {
            "avg": round(statistics.fmean(durations), 4),
            "min": round(min(durations), 4),
            "p50": round(statistics.median(durations), 4),
            "p95": round(ordered[idx95], 4),
            "max": round(max(durations), 4),
        },
    }

    if use_json:
        click.echo(json.dumps(summary, indent=2))
    else:
        click.echo("Benchmark results:")
        click.echo(
            f"- files={summary['files']} workers={summary['workers']} "
            f"runs={summary['runs']} warmup={summary['warmup']} no_cache={summary['no_cache']}"
        )
        t = summary["timings_s"]
        click.echo(
            f"- avg={t['avg']}s min={t['min']}s p50={t['p50']}s "
            f"p95={t['p95']}s max={t['max']}s"
        )


@cli.command("quality-report")
@click.option(
    "--corpus",
    type=click.Path(path_type=Path),
    default=Path("tests/benchmark/corpus.yaml"),
    show_default=True,
    help="Benchmark corpus YAML path.",
)
@click.option(
    "--json-output",
    type=click.Path(path_type=Path),
    default=Path("artifacts/quality_report.json"),
    show_default=True,
    help="Path to write JSON quality report.",
)
@click.option(
    "--md-output",
    type=click.Path(path_type=Path),
    default=Path("artifacts/quality_report.md"),
    show_default=True,
    help="Path to write markdown quality report.",
)
@click.option(
    "--enforce-budget",
    is_flag=True,
    default=False,
    help="Fail if quality regresses beyond budget limits.",
)
@click.option(
    "--baseline-file",
    type=click.Path(path_type=Path),
    default=Path(".github/quality_baseline.json"),
    show_default=True,
    help="Baseline quality report JSON for budget comparisons.",
)
@click.option(
    "--budget-file",
    type=click.Path(path_type=Path),
    default=Path(".github/quality_budget.json"),
    show_default=True,
    help="Budget policy JSON (allowed regressions).",
)
def quality_report_command(
    corpus: Path,
    json_output: Path,
    md_output: Path,
    enforce_budget: bool,
    baseline_file: Path,
    budget_file: Path,
) -> None:
    """Generate benchmark quality report artifacts and enforce regression budget."""
    report = build_quality_report(corpus)
    write_report_files(report, json_output, md_output)
    click.echo(f"Wrote quality report JSON to {json_output}")
    click.echo(f"Wrote quality report markdown to {md_output}")

    if not enforce_budget:
        return
    if not baseline_file.exists() or not budget_file.exists():
        click.echo("Budget enforcement requested but baseline/budget file is missing.", err=True)
        sys.exit(2)

    baseline = load_json_file(baseline_file)
    budget = load_json_file(budget_file)
    violations = check_quality_budget(report, baseline, budget)
    if violations:
        click.echo("Quality budget violations detected:", err=True)
        for v in violations:
            click.echo(f"- {v}", err=True)
        sys.exit(1)


@cli.command("deps")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--json", "use_json",
    is_flag=True, default=False,
    help="Output results as JSON.",
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
    default="LOW",
    show_default=True,
    help="Minimum severity level to report.",
)
def deps_command(path: Path, use_json: bool, severity: str) -> None:
    """
    Scan dependency manifests for known CVEs using the OSV.dev database.

    \b
    Scans: requirements.txt, package.json, go.mod, Gemfile.lock
    Example:
      secara deps .
      secara deps . --severity HIGH --json
    """
    from secara.sca.dependency_scanner import DependencyScanner
    scanner = DependencyScanner()

    # Find all supported dependency files
    if path.is_file():
        candidates = [path]
    else:
        candidates = []
        for p in path.rglob("*"):
            if scanner.is_dependency_file(p):
                candidates.append(p)

    if not candidates:
        click.echo("No dependency files found (requirements.txt, package.json, go.mod, Gemfile.lock).")
        sys.exit(0)

    all_findings: List[Finding] = []
    for dep_file in candidates:
        try:
            content = dep_file.read_text(encoding="utf-8", errors="replace")
            findings = scanner.analyze(dep_file, content)
            all_findings.extend(findings)
        except OSError as e:
            click.echo(f"Warning: Could not read {dep_file}: {e}", err=True)

    filtered = filter_findings(all_findings, severity)

    if use_json:
        import json as _json
        out = [{
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity,
            "file": f.file_path,
            "line": f.line_number,
            "description": f.description,
            "fix": f.fix,
        } for f in filtered]
        click.echo(_json.dumps(out, indent=2))
    else:
        try:
            from rich.console import Console
            from rich.table import Table
            c = Console()
            if not filtered:
                c.print("[green]✓ No known vulnerabilities found in dependencies.[/green]")
            else:
                c.print(f"[bold red]Found {len(filtered)} vulnerable dependenc{'y' if len(filtered)==1 else 'ies'}:[/bold red]\n")
                for f in filtered:
                    sev_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}.get(f.severity, "white")
                    c.print(f"  [{sev_color}][{f.severity}][/{sev_color}] {f.rule_name}")
                    c.print(f"    [dim]{f.file_path}:{f.line_number}[/dim]")
                    c.print(f"    {f.description}")
                    c.print(f"    [green]Fix:[/green] {f.fix}")
                    c.print()
        except ImportError:
            for f in filtered:
                print(f"[{f.severity}] {f.rule_name}\n  {f.description}\n  Fix: {f.fix}\n")

    sys.exit(1 if filtered else 0)


if __name__ == "__main__":
    main()
