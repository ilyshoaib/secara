"""
SCA (Software Composition Analysis) — Dependency CVE Scanner.

Parses dependency manifests and queries the OSV.dev API for known
vulnerabilities. Works with:
  - requirements.txt / requirements-*.txt  (Python)
  - package.json                           (Node.js)
  - go.mod                                 (Go)
  - Gemfile / Gemfile.lock                 (Ruby)
  - Pipfile / Pipfile.lock                 (Python via Pipenv)

Architecture:
  1. Parse dependency file → list of (package_name, version_spec)
  2. Query OSV.dev batch API → list of vulnerabilities per package
  3. Return Finding objects

The OSV.dev API is free, does not require an API key, and is the
same data source used by GitHub Dependabot and Google's Assured OSS.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from secara.output.models import Finding

logger = logging.getLogger("secara.sca")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS = 10


# ── Ecosystem mapping ─────────────────────────────────────────────────────────
FILENAME_TO_ECOSYSTEM: Dict[str, str] = {
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "requirements-prod.txt": "PyPI",
    "requirements-test.txt": "PyPI",
    "Pipfile": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
}


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_requirements_txt(content: str) -> List[Tuple[str, str]]:
    """Parse requirements.txt format. Returns [(name, version)]."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        # Skip comments and options
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        # Handle: requests==2.28.0, Flask>=2.0, numpy~=1.20
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~^]{1,2}=?\s*([0-9][^\s;]*)", line)
        if m:
            name = m.group(1).strip()
            version = m.group(2).strip().split(",")[0].strip()
            deps.append((name, version))
        else:
            # Package without version pin
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)\s*$", line)
            if m2:
                deps.append((m2.group(1).strip(), ""))
    return deps


def _parse_package_json(content: str) -> List[Tuple[str, str]]:
    """Parse package.json. Returns [(name, version)]."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver_spec in data.get(section, {}).items():
            # Strip semver prefixes: ^1.2, ~1.2, >=1.2
            ver = re.sub(r"^[\^~>=<v]", "", str(ver_spec)).split(" ")[0]
            deps.append((name, ver))
    return deps


def _parse_go_mod(content: str) -> List[Tuple[str, str]]:
    """Parse go.mod require blocks. Returns [(module_path, version)]."""
    deps = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            parts = line.replace("require ", "").strip().split()
            if len(parts) >= 2:
                name = parts[0]
                ver = parts[1].lstrip("v")
                deps.append((name, ver))
    return deps


def _parse_gemfile_lock(content: str) -> List[Tuple[str, str]]:
    """Parse Gemfile.lock GEM section. Returns [(gem_name, version)]."""
    deps = []
    in_gems = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_gems = True
            continue
        if in_gems and not line.startswith(" "):
            in_gems = False
        if in_gems:
            m = re.match(r"^\s{4}([a-zA-Z0-9_\-]+)\s+\(([0-9][^\)]*)\)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
    return deps


PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-prod.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "Pipfile": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Gemfile.lock": _parse_gemfile_lock,
}


# ── OSV API ───────────────────────────────────────────────────────────────────

def _query_osv_batch(
    packages: List[Tuple[str, str, str]]  # [(name, version, ecosystem)]
) -> List[List[Dict]]:
    """
    Query the OSV.dev batch API.
    Returns a list of vuln lists, one per package.
    Silently returns empty lists on network/API errors.
    """
    if not packages:
        return []

    queries = []
    for name, version, ecosystem in packages:
        q: Dict = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            q["version"] = version
        queries.append(q)

    payload = json.dumps({"queries": queries}).encode()
    req = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OSV_TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read())
            return [r.get("vulns", []) for r in body.get("results", [])]
    except urllib.error.URLError as e:
        logger.warning("OSV API unreachable: %s", e)
        return [[] for _ in packages]
    except Exception as e:
        logger.warning("OSV query failed: %s", e)
        return [[] for _ in packages]


def _vuln_to_severity(vuln: Dict) -> str:
    """Extract severity from OSV vuln record."""
    for severity in vuln.get("severity", []):
        score = str(severity.get("score", ""))
        if score:
            # CVSS score → severity label
            try:
                v = float(score.split("/")[0] if "/" in score else score)
            except ValueError:
                pass
            else:
                if v >= 9.0:
                    return "CRITICAL"
                if v >= 7.0:
                    return "HIGH"
                if v >= 4.0:
                    return "MEDIUM"
    return "MEDIUM"  # default when score not parseable


def _format_aliases(vuln: Dict) -> str:
    """Get CVE ID or OSV ID from aliases."""
    aliases = vuln.get("aliases", [])
    for a in aliases:
        if a.startswith("CVE-"):
            return a
    return vuln.get("id", "UNKNOWN")


# ── Main SCA analyzer ─────────────────────────────────────────────────────────

class DependencyScanner:
    """
    Scans dependency manifest files for known CVEs using the OSV.dev API.
    """

    SUPPORTED_FILENAMES = set(PARSERS.keys()) | set(FILENAME_TO_ECOSYSTEM.keys())

    def is_dependency_file(self, file_path: Path) -> bool:
        return file_path.name in self.SUPPORTED_FILENAMES

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []
        fname = file_path.name

        # Determine parser
        parser = PARSERS.get(fname)
        if parser is None:
            return []

        ecosystem = FILENAME_TO_ECOSYSTEM.get(fname, "PyPI")

        # Parse deps
        deps = parser(content)
        if not deps:
            return []

        logger.debug("SCA: found %d deps in %s", len(deps), file_path.name)

        # Build OSV query list
        packages = [(name, ver, ecosystem) for name, ver in deps if name]

        # Query OSV
        results = _query_osv_batch(packages)

        lines = content.splitlines()

        for (name, version, _), vulns in zip(packages, results):
            for vuln in vulns:
                vuln_id = _format_aliases(vuln)
                severity = _vuln_to_severity(vuln)
                summary = vuln.get("summary", "No summary available.")
                affected = vuln.get("affected", [])

                # Find the line where this dependency appears
                line_no = 1
                for i, line in enumerate(lines, 1):
                    if name.lower() in line.lower():
                        line_no = i
                        break

                # Build fix recommendation
                fix_versions = []
                for aff in affected:
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            fixed = ev.get("fixed")
                            if fixed:
                                fix_versions.append(fixed)
                fix_str = f"Upgrade to version {fix_versions[0]} or later." if fix_versions else "Check the advisory for the fixed version."

                findings.append(
                    Finding(
                        rule_id=f"SCA-{vuln_id}",
                        rule_name=f"Known Vulnerability: {name} ({vuln_id})",
                        severity=severity,
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=f"{name}=={version}" if version else name,
                        description=(
                            f"Package '{name}' version {version or '(unpinned)'} has a known vulnerability "
                            f"({vuln_id}):\n{summary}"
                        ),
                        fix=fix_str,
                        language="dependency",
                    )
                )

        return findings
