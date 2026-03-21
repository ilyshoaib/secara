import re
from pathlib import Path

from secara.detectors.base import BaseDetector
from secara.output.models import Finding


class GoAnalyzer(BaseDetector):
    """
    Tier-2 Analyzer for Go (.go) files.
    Uses robust regular expressions configured over a context window to detect
    Command Injection, SQL Injection, SSRF, and Path Traversal.
    """

    def __init__(self) -> None:
        # SQL Injection: db.Query("SELECT ... " + userInput) or fmt.Sprintf
        self.sqli_pattern = re.compile(
            r"""(?ix)
            (?:db\.|tx\.)(?:Query|QueryRow|Exec|Prepare|ExecContext|QueryContext)\s*\(
            .*?
            (?:fmt\.Sprintf\s*\(|(?:\w+\s*\+\s*)+|\+\s*\w+)
            """,
            re.MULTILINE | re.DOTALL,
        )

        # Command Injection: exec.Command("sh", "-c", input)
        self.cmdi_pattern = re.compile(
            r"""(?ix)
            exec\.Command(?:Context)?\s*\(\s*
            (?:["'`]sh["'`]\s*,\s*["'`]-c["'`]|["'`]bash["'`]\s*,\s*["'`]-c["'`]|["'`]cmd["'`]\s*,\s*["'`]/c["'`])
            \s*,[^)]*?(?:[a-zA-Z0-9_\-]+|\(.*?\))\s*\)
            """,
            re.MULTILINE | re.DOTALL,
        )

        # SSRF: http.Get(userInput) or client.Do(req) after dynamic URL
        self.ssrf_pattern = re.compile(
            r"""(?ix)
            http\.(?:Get|Post|Head|Do)\s*\(\s*
            (?:[a-zA-Z0-9_]+(?:\.URL|\.String\(\))?|(?:fmt\.Sprintf\s*\([^)]+\)))
            \s*\)
            """,
            re.MULTILINE | re.DOTALL,
        )

        # Path Traversal: os.Open(userInput) or os.ReadFile
        self.path_pattern = re.compile(
            r"""(?ix)
            os\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|RemoveAll)\s*\(\s*
            (?:[a-zA-Z0-9_]+(?:\.Path|\.String\(\))?|(?:filepath\.Join\s*\([^)]+\)))
            """,
            re.MULTILINE | re.DOTALL,
        )


    def analyze(self, file_path: Path, content: str) -> list[Finding]:
        findings = []
        lines = content.splitlines()

        findings.extend(
            self._scan_pattern(
                file_path,
                content,
                lines,
                self.sqli_pattern,
                "SQL005",
                "SQL Injection via String Concatenation (Go)",
                "HIGH",
                "A database query is constructed dynamically using string formatting or concatenation. Use `db.Query('SELECT * FROM users WHERE id = ?', id)` parameterized queries.",
            )
        )

        findings.extend(
            self._scan_pattern(
                file_path,
                content,
                lines,
                self.cmdi_pattern,
                "CMD005",
                "Command Injection via exec.Command (Go)",
                "HIGH",
                "exec.Command is used with 'sh -c' and dynamic input. This allows arbitrary command execution. Avoid shells where possible and pass arguments as separate array elements: `exec.Command('ls', '-la', userDir)`.",
            )
        )

        findings.extend(
            self._scan_pattern(
                file_path,
                content,
                lines,
                self.ssrf_pattern,
                "SSRF003",
                "Server-Side Request Forgery / SSRF (Go)",
                "HIGH",
                "http.Get or similar method is called with a dynamically constructed URL. Validate user-provided URLs against an allowlist and block private IP address resolution.",
            )
        )

        findings.extend(
            self._scan_pattern(
                file_path,
                content,
                lines,
                self.path_pattern,
                "PATH004",
                "Path Traversal (Go)",
                "MEDIUM",
                "File operation with dynamically constructed path. Prevent path traversal using `filepath.Clean()` and verifying the resulting path starts with an allowed base directory.",
            )
        )

        return findings

    def _scan_pattern(
        self,
        file_path: Path,
        content: str,
        lines: list[str],
        pattern: re.Pattern,
        rule_id: str,
        rule_name: str,
        severity: str,
        description: str,
    ) -> list[Finding]:
        findings = []
        for match in pattern.finditer(content):
            # Calculate line number
            start_pos = match.start()
            line_no = content.count("\n", 0, start_pos) + 1
            findings.append(
                Finding(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    severity=severity,
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=self.get_snippet(lines, line_no),
                    description=description,
                    fix="Audit the input flowing into this function and apply safe usage patterns.",
                    language="go",
                )
            )
        return findings
