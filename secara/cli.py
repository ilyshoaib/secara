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
_DEP_SCANNER      = None  # Lazy-loaded on first use


def _is_suppressed(line: str, rule_id: str) -> bool:
    """Return True if the line has a secara ignore annotation that covers rule_id."""
    if IGNORE_COMMENT not in line:
        return False
    # Generic suppress — no rule list
    if f"{IGNORE_COMMENT}[" not in line:
        return True
    # Rule-specific suppress: secara: ignore[SQL001,CMD002]
    import re
    m = re.search(r"secara:\s*ignore\[([^\]]+)\]", line)
    if m:
        suppressed_ids = {r.strip() for r in m.group(1).split(",")}
        return rule_id in suppressed_ids
    return True


def _analyze_file(file_path: Path, cache: "FileCache", cfg=None) -> List[Finding]:
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
            if _is_suppressed(lines[line_idx], f.rule_id):
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
    # CLI --workers flag overrides secara.yaml workers
    effective_workers = workers if workers != 8 else cfg.workers

    def analyze(fp: Path) -> List[Finding]:
        return _analyze_file(fp, cache, cfg)

    all_findings = scan_files_parallel(files, analyze, max_workers=effective_workers)

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
