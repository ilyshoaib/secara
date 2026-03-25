"""
Output formatter — renders scan findings to the terminal (rich) or JSON.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import List

from secara.output.models import Finding, SEVERITY_ORDER, CONFIDENCE_ORDER
from secara.output.fingerprint import finding_fingerprint

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.padding import Padding
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ── Severity styling ──────────────────────────────────────────────────────────
SEVERITY_STYLES: dict[str, tuple[str, str]] = {
    "HIGH":   ("bold white on red", "🔴"),
    "MEDIUM": ("bold black on yellow", "🟡"),
    "LOW":    ("bold white on blue", "🔵"),
}


def _severity_badge(severity: str) -> str:
    icon = SEVERITY_STYLES.get(severity.upper(), ("", "❓"))[1]
    return f"{icon} {severity}"


# ── Filtering ─────────────────────────────────────────────────────────────────
def filter_findings(findings: List[Finding], min_severity: str) -> List[Finding]:
    """Return only findings at or above *min_severity*."""
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 99)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity.upper(), 99) <= threshold]


def filter_by_confidence(findings: List[Finding], min_confidence: str) -> List[Finding]:
    """Return only findings at or above *min_confidence*."""
    threshold = CONFIDENCE_ORDER.get(min_confidence.upper(), 99)
    return [f for f in findings if CONFIDENCE_ORDER.get(f.confidence.upper(), 99) <= threshold]


# ── JSON output ───────────────────────────────────────────────────────────────
def output_json(findings: List[Finding], output_file: str | None = None) -> None:
    """Print findings as JSON to stdout or write to file."""
    data = []
    for f in findings:
        obj = f.to_dict()
        obj["fingerprint"] = finding_fingerprint(f)
        data.append(obj)
    out_str = json.dumps(data, indent=2)
    if output_file:
        Path(output_file).write_text(out_str, encoding="utf-8")
        print(f"JSON results written to {output_file}")
    else:
        print(out_str)


# ── Rich CLI output ───────────────────────────────────────────────────────────
def output_rich(findings: List[Finding], verbose: bool = False) -> None:
    console = Console(stderr=False)

    if not findings:
        console.print(
            "\n[bold green]✅  No security issues detected.[/bold green]\n"
        )
        return

    # Group findings by file
    from collections import defaultdict
    by_file: dict[str, List[Finding]] = defaultdict(list)
    for f in sorted(findings, key=lambda f: (f.file_path, f.line_number)):
        by_file[f.file_path].append(f)

    console.print()

    for file_path, file_findings in by_file.items():
        rel_path = _try_relative(file_path)
        console.rule(f"[bold cyan]{rel_path}[/bold cyan]", style="cyan")

        for finding in file_findings:
            sev = finding.severity.upper()
            style, icon = SEVERITY_STYLES.get(sev, ("bold", "❓"))

            # Header line
            badge = Text(f" {sev} ", style=style)
            title_text = Text()
            title_text.append(f"{icon} ")
            title_text.append(badge)
            title_text.append(f"  {finding.rule_name}", style="bold white")
            title_text.append(f"  [{finding.rule_id}]", style="dim")
            console.print(Padding(title_text, (1, 0, 0, 2)))

            # Location
            console.print(
                f"  [dim]Line {finding.line_number}[/dim]  "
                f"[bold]{rel_path}[/bold]:{finding.line_number}",
                highlight=False,
            )
            console.print(
                f"  [dim]Confidence: {finding.confidence}  Fingerprint: {finding_fingerprint(finding)[:12]}[/dim]",
                highlight=False,
            )

            # Code snippet
            if finding.snippet:
                console.print(
                    Padding(
                        Panel(
                            f"[yellow]{finding.snippet}[/yellow]",
                            expand=False,
                            border_style="dim",
                        ),
                        (0, 2),
                    )
                )

            if verbose:
                console.print(
                    Padding(
                        f"[bold]Description:[/bold] {finding.description}",
                        (0, 4),
                    )
                )
                if finding.evidence:
                    console.print(
                        Padding(
                            f"[bold magenta]Evidence:[/bold magenta] {finding.evidence}",
                            (0, 4),
                        )
                    )
                console.print(
                    Padding(
                        f"[bold green]Fix:[/bold green] {finding.fix}",
                        (0, 4),
                    )
                )
            else:
                # Always show a short description line
                short_desc = finding.description.split(".")[0] + "."
                console.print(
                    Padding(f"[dim]{short_desc}[/dim]", (0, 4))
                )
                console.print(
                    Padding(
                        f"[bold green]▶ Fix:[/bold green] {finding.fix.splitlines()[0]}",
                        (0, 4),
                    )
                )

        console.print()

    # ── Summary table ─────────────────────────────────────────────────────────
    _print_summary(console, findings)


def _print_summary(console, findings: List[Finding]) -> None:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    rule_counts: dict[str, int] = {}

    for f in findings:
        counts[f.severity.upper()] = counts.get(f.severity.upper(), 0) + 1
        rule_counts[f.rule_name] = rule_counts.get(f.rule_name, 0) + 1

    table = Table(
        title="[bold]Scan Summary[/bold]",
        box=box.ROUNDED,
        border_style="bright_blue",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Count", justify="right", width=8)

    for sev in ["HIGH", "MEDIUM", "LOW"]:
        count = counts.get(sev, 0)
        style, icon = SEVERITY_STYLES[sev]
        display = f"{icon} {sev}"
        table.add_row(display, str(count))

    table.add_section()
    table.add_row("[bold]TOTAL[/bold]", str(len(findings)))

    console.print(table)
    console.print()

    # Top rules
    if rule_counts:
        top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:5]
        console.print("[bold]Top Findings:[/bold]")
        for rule_name, count in top_rules:
            console.print(f"  • {rule_name}: [bold]{count}[/bold]")
        console.print()


def _try_relative(file_path: str) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(Path.cwd()))
    except ValueError:
        return file_path


# ── Fallback plain-text output (no rich) ─────────────────────────────────────
def output_plain(findings: List[Finding], verbose: bool = False) -> None:
    if not findings:
        print("\n✅  No security issues detected.\n")
        return

    for f in sorted(findings, key=lambda x: (x.file_path, x.line_number)):
        print(f"\n[{f.severity}] {f.rule_name} ({f.rule_id})")
        print(f"  File: {f.file_path}:{f.line_number}")
        print(f"  Code: {f.snippet}")
        print(f"  Confidence: {f.confidence}  Fingerprint: {finding_fingerprint(f)}")
        if verbose:
            print(f"  Description: {f.description}")
        print(f"  Fix: {f.fix.splitlines()[0]}")

    print(f"\n--- TOTAL: {len(findings)} findings ---\n")


def render_findings(
    findings: List[Finding],
    use_json: bool = False,
    use_sarif: bool = False,
    output_file: str | None = None,
    verbose: bool = False,
) -> None:
    """Main rendering entry point."""
    if use_sarif:
        output_sarif(findings, output_file)
    elif use_json:
        output_json(findings, output_file)
    elif RICH_AVAILABLE:
        output_rich(findings, verbose=verbose)
    else:
        output_plain(findings, verbose=verbose)


def output_sarif(findings: List[Finding], output_file: str | None = None) -> None:
    """Generate SARIF v2.1.0 JSON output and write to stdout or file."""
    # Inline import to avoid circular dependency
    from secara import __version__
    
    rules = {}
    results = []
    
    for f in findings:
        if f.rule_id not in rules:
            level = "warning"
            if f.severity.upper() == "HIGH":
                level = "error"
            elif f.severity.upper() == "LOW":
                level = "note"
                
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name,
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.description},
                "help": {"text": f.fix},
                "properties": {
                    "tags": [getattr(f, "language", "unknown"), f"confidence:{f.confidence.lower()}"],
                    "security-severity": "9.0" if level == "error" else ("6.0" if level == "warning" else "3.0"),
                    **({"evidence": f.evidence} if f.evidence else {}),
                }
            }
            
        result_level = "warning"
        if f.severity.upper() == "HIGH":
            result_level = "error"
        elif f.severity.upper() == "LOW":
            result_level = "note"

        rel_path = _try_relative(f.file_path)
        # Use forward slashes for cross-platform SARIF compliance
        rel_uri = rel_path.replace("\\", "/")
            
        results.append({
            "ruleId": f.rule_id,
            "level": result_level,
            "message": {
                "text": f.description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_uri
                        },
                        "region": {
                            "startLine": f.line_number,
                            "snippet": {
                                "text": f.snippet
                            }
                        }
                    }
                }
            ],
            "fingerprints": {
                "secaraFingerprint": finding_fingerprint(f)
            }
        })

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secara",
                        "informationUri": "https://github.com/secara",
                        "semanticVersion": __version__,
                        "rules": list(rules.values())
                    }
                },
                "results": results
            }
        ]
    }
    
    out_str = json.dumps(sarif_log, indent=2)
    if output_file:
        Path(output_file).write_text(out_str, encoding="utf-8")
        print(f"SARIF results written to {output_file}")
    else:
        print(out_str)
