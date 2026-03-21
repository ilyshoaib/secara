"""
Secara CLI — entry point.

Commands:
    secara scan <path>  [--json] [--verbose] [--severity LEVEL] [--no-cache]
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import List

import click

from secara import __version__
from secara.scanner.file_scanner import collect_files, scan_files_parallel
from secara.scanner.language_engine import get_language_info, LanguageTier
from secara.scanner.cache import FileCache
from secara.detectors.secrets_detector import SecretsDetector
from secara.detectors.python_analyzer import PythonAnalyzer
from secara.detectors.js_analyzer import JSAnalyzer
from secara.detectors.shell_analyzer import ShellAnalyzer
from secara.detectors.config_analyzer import ConfigAnalyzer
from secara.detectors.go_analyzer import GoAnalyzer
from secara.output.models import Finding
from secara.output.formatter import render_findings, filter_findings

# ── IGNORE ANNOTATION ────────────────────────────────────────────────────────
IGNORE_COMMENT = "secara: ignore"

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


def _analyze_file(file_path: Path, cache: FileCache) -> List[Finding]:
    """
    Run all applicable detectors on *file_path*.
    Returns an empty list on any error.
    """
    # ── Ignore annotation check ───────────────────────────────────────────
    # Check first line of file for file-level suppress
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Check cache
    cached = cache.get(file_path)
    if cached is not None:
        from secara.output.models import Finding as F
        return [F(**d) for d in cached] if cached else []

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

    # ── Secrets-only tier ─────────────────────────────────────────────────
    elif tier == LanguageTier.SECRETS_ONLY:
        findings.extend(_CONFIG_ANALYZER.analyze(file_path, content))

    # ── Filter inline ignores ─────────────────────────────────────────────
    lines = content.splitlines()
    filtered = []
    for f in findings:
        line_idx = f.line_number - 1
        if 0 <= line_idx < len(lines):
            if IGNORE_COMMENT in lines[line_idx]:
                continue
        filtered.append(f)

    cache.set(file_path, filtered)
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
    "--no-cache",
    is_flag=True, default=False,
    help="Disable file cache (re-scan everything).",
)
@click.option(
    "--workers", "-w",
    type=int, default=8, show_default=True,
    help="Number of parallel worker threads.",
)
def scan_command(
    path: Path,
    use_json: bool,
    verbose: bool,
    sarif: bool,
    output: Path | None,
    severity: str,
    no_cache: bool,
    workers: int,
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

    # ── Collect files ─────────────────────────────────────────────────────
    files = collect_files(path)
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
    def analyze(fp: Path) -> List[Finding]:
        return _analyze_file(fp, cache)

    all_findings = scan_files_parallel(files, analyze, max_workers=workers)

    # ── Persist cache ─────────────────────────────────────────────────────
    cache.save()

    elapsed = time.perf_counter() - start_time

    # ── Filter by severity ────────────────────────────────────────────────
    filtered = filter_findings(all_findings, severity)

    # ── Render ────────────────────────────────────────────────────────────
    render_findings(
        filtered,
        use_json=use_json,
        use_sarif=sarif,
        output_file=str(output) if output else None,
        verbose=verbose,
    )

    if not use_json and not sarif:
        try:
            from rich.console import Console
            Console().print(
                f"[dim]⏱  Scan completed in {elapsed:.2f}s — "
                f"{len(files)} files, {len(all_findings)} total findings "
                f"({len(filtered)} shown at {severity}+)[/dim]\n"
            )
        except ImportError:
            print(
                f"\nScan completed in {elapsed:.2f}s — "
                f"{len(files)} files, {len(all_findings)} findings\n"
            )

    # ── Exit code ─────────────────────────────────────────────────────────
    sys.exit(1 if filtered else 0)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
