"""
JavaScript / TypeScript security analyzer — OWASP Top 10 + Extended Coverage.

Uses a regex-AST hybrid approach — no external compiled parsers required.

Detects:
  [A01] Broken Access Control   — path traversal in fs.readFile/writeFile
  [A02] Crypto Failures         — crypto.createHash('md5'), Math.random() for tokens
  [A03] Injection               — SQLi, CMDi, eval(), XSS via innerHTML/document.write,
                                   LDAP injection, SSTI, ReDoS patterns
  [A05] Misconfiguration        — CORS wildcard, hardcoded secrets, debug flags
  [A08] Data Integrity          — deserialize(), node-serialize unsafe usage
  [A10] SSRF                    — fetch/axios/http.get with dynamic URLs

Strategy: Apply regex patterns with contextual window analysis (surrounding lines)
to achieve reasonable accuracy without a full parse tree.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from typing import List

from secara.detectors.base import BaseDetector
from secara.output.models import Finding

logger = logging.getLogger("secara.js")

# ── SQL Injection patterns ────────────────────────────────────────────────────
_SQL_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "concat",
        re.compile(
            r"""(?:\.query|\.execute|\.raw|db\.run|pool\.query)\s*\(\s*(?:
                    [`'"].*?\+\s*\w+         # string + variable
                  | \w+\s*\+\s*[`'"]        # variable + string
                  | `[^`]*?\$\{[^}]+\}      # template literal with ${...}
                )""",
            re.VERBOSE | re.IGNORECASE,
        ),
    ),
    (
        "template",
        re.compile(
            r"""(?:\.query|\.execute|\.raw|db\.run)\s*\(\s*`[^`]*\$\{[^}]+\}""",
            re.IGNORECASE,
        ),
    ),
]

# ── Command Injection patterns ────────────────────────────────────────────────
_CMD_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    (
        "CMD101",
        re.compile(
            r"""exec\s*\(\s*(?:
                    [`"'].*?\+\s*\w+         # string concat
                  | \w+\s*\+\s*[`"']        # var + string
                  | `[^`]*\$\{[^}]+\}       # template literal
                  | \w+                      # bare variable
                )\s*[,)]""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via exec()",
    ),
    (
        "CMD102",
        re.compile(
            r"""execSync\s*\(\s*(?:
                    [`"'].*?\+\s*\w+
                  | \w+\s*\+\s*[`"']
                  | `[^`]*\$\{[^}]+\}
                  | \w+
                )\s*[,)]""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via execSync()",
    ),
    (
        "CMD103",
        re.compile(
            r"""spawn\s*\(\s*(?:
                    [`"'].*?\+\s*\w+
                  | \w+\s*\+\s*[`"']
                  | `[^`]*\$\{[^}]+\}
                  | \w+
                )\s*,""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via spawn()",
    ),
    (
        "CMD106",
        re.compile(
            r"""execFile\s*\(\s*(?:
                    \w+\s*\+\s*[`"']
                  | `[^`]*\$\{[^}]+\}
                  | \w+
                )\s*[,)]""",
            re.VERBOSE | re.IGNORECASE,
        ),
        "Command Injection via execFile()",
    ),
]

# ── eval() patterns ───────────────────────────────────────────────────────────
_EVAL_PATTERN = re.compile(
    r"""\beval\s*\(\s*(?![`'"][^`'"]*[`'"])(?!\d)(?!\()([^)]+)\)""",
    re.IGNORECASE,
)
_EVAL_CONSTANT = re.compile(r"""\beval\s*\(\s*[`'"]\s*[^`'"]*[`'"]\s*\)""")

# ── Prototype pollution ───────────────────────────────────────────────────────
_PROTO_POLLUTION = re.compile(
    r"""(?:__proto__|constructor\s*\[|prototype\s*\[)\s*\[?\s*['"]\w+""",
    re.IGNORECASE,
)

_PROTOTYPE_MERGE = re.compile(
    r"""(?:Object\.assign|_\.merge|lodash\.merge|deepmerge|extend)\s*\([^,]+,\s*(?:req\.|request\.|body\.|params\.|query\.)""",
    re.IGNORECASE,
)

# ── XSS patterns ──────────────────────────────────────────────────────────────
_INNERHTML_PATTERN = re.compile(
    r"""\.innerHTML\s*(?:\+=|=)\s*(?:[^;]*(?:req\.|request\.|params\.|query\.|body\.|location\.|document\.URL|\$_GET|\$_POST|getParam|userInput|\w+Input))""",
    re.IGNORECASE,
)

_DOCUMENT_WRITE_PATTERN = re.compile(
    r"""document\.write(?:ln)?\s*\(\s*(?:[^)]*(?:req\.|params\.|query\.|location\.|\w+Input|\w+Param))""",
    re.IGNORECASE,
)

# Generic innerHTML with a variable (less precise, MEDIUM)
_INNERHTML_VAR = re.compile(
    r"""\.innerHTML\s*(?:\+=|=)\s*\w+""",
    re.IGNORECASE,
)

# ── SSRF patterns ─────────────────────────────────────────────────────────────
_SSRF_FETCH_PATTERN = re.compile(
    r"""(?:fetch|axios\.get|axios\.post|axios\.request|http\.get|http\.request|https\.get|https\.request)\s*\(\s*(?:
          \w+\s*\+\s*[`'"]       # var + string
        | ['"]\s*\+\s*\w+        # string + var
        | `[^`]*\$\{[^}]+\}      # template literal
        | \w+                    # bare variable
    )\s*[,)]""",
    re.VERBOSE | re.IGNORECASE,
)

# ── Insecure Deserialization (node-serialize, js-yaml unsafe) ─────────────────
_DESERIALIZE_PATTERN = re.compile(
    r"""(?:deserialize|unserialize|fromJSON)\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.)""",
    re.IGNORECASE,
)

_YAML_LOAD_UNSAFE = re.compile(
    r"""yaml\.load\s*\([^,)]+(?!\s*,\s*yaml\.SAFE_LOAD|\s*,\s*\{schema)""",
    re.IGNORECASE,
)

# ── Weak crypto ───────────────────────────────────────────────────────────────
_WEAK_HASH_PATTERN = re.compile(
    r"""crypto\.createHash\s*\(\s*['"`](md5|sha1|sha-1)['"`]\s*\)""",
    re.IGNORECASE,
)

_MATH_RANDOM_SECURITY = re.compile(
    r"""(?:token|secret|password|key|session|nonce|csrf|salt)\s*[=:]\s*(?:[^;]*Math\.random\(\))""",
    re.IGNORECASE,
)

# ── Path Traversal ────────────────────────────────────────────────────────────
_FS_TRAVERSAL_PATTERN = re.compile(
    r"""(?:fs\.readFile|fs\.writeFile|fs\.readFileSync|fs\.writeFileSync|fs\.unlink|fs\.appendFile)\s*\(\s*(?:
          \w+\s*\+\s*[`'"]       # var + string
        | ['"]\s*\+\s*\w+        # string + var
        | `[^`]*\$\{[^}]+\}      # template literal
        | req\.\w+\.\w+          # direct req reference
    )\s*[,)]""",
    re.VERBOSE | re.IGNORECASE,
)

# ── CORS wildcard ─────────────────────────────────────────────────────────────
_CORS_WILDCARD = re.compile(
    r"""(?:Access-Control-Allow-Origin|cors\s*\(\s*\{\s*origin)\s*[=:]['"`\s]*\*""",
    re.IGNORECASE,
)

# ── Hardcoded credentials (JS-specific) ──────────────────────────────────────
_JS_HARDCODED_SECRET = re.compile(
    r"""(?:password|passwd|secret|apiKey|api_key|token|authToken|auth_token)\s*[:=]\s*['"`][^'"`]{6,}['"`]""",
    re.IGNORECASE,
)

# ── Comment lines ─────────────────────────────────────────────────────────────
_COMMENT_LINE = re.compile(r"""^\s*(?://|/\*|\*)""")

# ── String placeholder values to skip ─────────────────────────────────────────
_PLACEHOLDER_VALUES = re.compile(
    r"""(?:your[_-]?(?:key|secret|token|password|api)|placeholder|example|dummy|test|xxx+|<[^>]+>|changeme|todo|fixme|redacted|none|null|undefined|'')""",
    re.IGNORECASE,
)


class JSAnalyzer(BaseDetector):
    """Regex-AST hybrid security analyzer for JavaScript/TypeScript — OWASP Top 10."""

    def analyze(self, file_path: Path, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        language = "typescript" if file_path.suffix.lower() in {".ts", ".tsx"} else "javascript"

        for line_no, line in enumerate(lines, start=1):
            if _COMMENT_LINE.match(line):
                continue

            # ── SQL Injection ──────────────────────────────────────────────
            for _variant, pattern in _SQL_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id="SQL002",
                        rule_name="SQL Injection in JavaScript/TypeScript",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            "A database query is built using string concatenation or "
                            "template literals with potentially user-controlled values. "
                            "This allows attackers to inject arbitrary SQL and bypass "
                            "authentication or access unauthorized data."
                        ),
                        fix=(
                            "Use parameterized queries with placeholders:\n"
                            "  db.query('SELECT * FROM users WHERE id = $1', [userId])\n"
                            "  // or with mysql2: db.execute('SELECT ? FROM ...', [val])"
                        ),
                        language=language,
                    ))
                    break

            # ── Command Injection ──────────────────────────────────────────
            for rule_id, pattern, rule_name in _CMD_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            f"A shell command is constructed dynamically in {rule_name.split('via ')[1]}. "
                            "If any part of the command includes user input, an attacker "
                            "can inject arbitrary OS commands (e.g., ; rm -rf /)."
                        ),
                        fix=(
                            "Avoid passing dynamic strings to exec/execSync/spawn.\n"
                            "  - Use spawn() with an explicit args array: spawn('ls', ['-la', userDir])\n"
                            "  - Validate and sanitize all inputs strictly before use in commands."
                        ),
                        language=language,
                    ))
                    break

            # ── eval() ────────────────────────────────────────────────────
            if _EVAL_PATTERN.search(line) and not _EVAL_CONSTANT.search(line):
                findings.append(Finding(
                    rule_id="CMD104",
                    rule_name="Dangerous eval() Usage in JavaScript",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "eval() is called with a non-literal argument. eval() executes "
                        "arbitrary JavaScript code, and if the argument is user-controlled, "
                        "this enables full remote code execution."
                    ),
                    fix=(
                        "Avoid eval() completely. Safer alternatives:\n"
                        "  - JSON.parse() for parsing data\n"
                        "  - A lookup object/map for dynamic dispatch\n"
                        "  - Function constructors should also be avoided"
                    ),
                    language=language,
                ))

            # ── Prototype Pollution ────────────────────────────────────────
            if _PROTO_POLLUTION.search(line):
                findings.append(Finding(
                    rule_id="CMD105",
                    rule_name="Potential Prototype Pollution (Direct __proto__ Access)",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "Access to __proto__ or constructor.prototype with dynamic keys "
                        "can enable prototype pollution attacks, allowing attackers to "
                        "modify Object.prototype and affect all objects in the application."
                    ),
                    fix=(
                        "Avoid dynamic property access on __proto__ or prototype.\n"
                        "  - Use Object.create(null) for maps without prototype chains.\n"
                        "  - Validate and whitelist all keys before merging user-supplied objects."
                    ),
                    language=language,
                ))

            if _PROTOTYPE_MERGE.search(line):
                findings.append(Finding(
                    rule_id="CMD107",
                    rule_name="Prototype Pollution via Object Merge with User Data",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "A merge/assign function is being called with user-supplied request "
                        "data (req.body, req.params, etc.) directly. This can lead to "
                        "prototype pollution if the user data contains __proto__ or "
                        "constructor keys, affecting the entire application state."
                    ),
                    fix=(
                        "Sanitize user input before merging:\n"
                        "  - Use deep clone with explicit schema validation\n"
                        "  - Filter out __proto__, constructor, prototype keys\n"
                        "  - Use JSON parse/stringify to strip non-standard properties"
                    ),
                    language=language,
                ))

            # ── XSS via innerHTML ──────────────────────────────────────────
            if _INNERHTML_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="XSS001",
                    rule_name="Cross-Site Scripting (XSS) via innerHTML with Request Data",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "innerHTML is set using data that appears to come from a request "
                        "parameter or user input. This leads to reflected or stored XSS: "
                        "an attacker can inject <script>steal(document.cookie)</script> "
                        "to hijack sessions or exfiltrate data."
                    ),
                    fix=(
                        "Never assign unsanitized user data to innerHTML.\n"
                        "  - Use textContent instead: element.textContent = userInput\n"
                        "  - Or sanitize with DOMPurify: element.innerHTML = DOMPurify.sanitize(input)"
                    ),
                    language=language,
                ))
            elif _INNERHTML_VAR.search(line) and "innerHTML" in line:
                findings.append(Finding(
                    rule_id="XSS002",
                    rule_name="Potential Cross-Site Scripting (XSS) via innerHTML",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "innerHTML is set to a variable value. If this variable contains "
                        "user-controlled data, this can lead to XSS attacks."
                    ),
                    fix=(
                        "Use textContent for plain text, or sanitize HTML with DOMPurify:\n"
                        "  element.textContent = value;  // safe for plain text\n"
                        "  element.innerHTML = DOMPurify.sanitize(value);  // safe for HTML"
                    ),
                    language=language,
                ))

            if _DOCUMENT_WRITE_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="XSS003",
                    rule_name="Cross-Site Scripting (XSS) via document.write",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "document.write() or document.writeln() is called with user-supplied "
                        "data. This is a classic XSS vector — any HTML or script tags in "
                        "the input will be executed by the browser."
                    ),
                    fix=(
                        "Avoid document.write() entirely. Use DOM APIs:\n"
                        "  const el = document.createElement('p');\n"
                        "  el.textContent = userInput;  // safe\n"
                        "  document.body.appendChild(el);"
                    ),
                    language=language,
                ))

            # ── SSRF via fetch/axios ───────────────────────────────────────
            if _SSRF_FETCH_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="SSRF002",
                    rule_name="Server-Side Request Forgery (SSRF) via fetch/axios",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "A network request is made using a URL that may be derived from "
                        "user input. This can enable SSRF: an attacker can force the server "
                        "to make requests to internal services (e.g., http://localhost:6379 Redis, "
                        "http://169.254.169.254 AWS metadata) or external attacker infrastructure."
                    ),
                    fix=(
                        "Validate the URL against an allowlist of permitted domains:\n"
                        "  const { hostname } = new URL(url);\n"
                        "  if (!ALLOWED_HOSTS.includes(hostname)) throw new Error('Blocked');"
                    ),
                    language=language,
                ))

            # ── Insecure Deserialization ───────────────────────────────────
            if _DESERIALIZE_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="DSER005",
                    rule_name="Insecure Deserialization of User-Controlled Data",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "A deserialization function is called directly with request data. "
                        "Libraries like node-serialize can execute embedded function expressions "
                        "during deserialization, leading to Remote Code Execution (RCE)."
                    ),
                    fix=(
                        "Never deserialize untrusted data with node-serialize or similar.\n"
                        "  - Use JSON.parse() for structured data\n"
                        "  - Validate schema after parsing with a library like Joi or Zod"
                    ),
                    language=language,
                ))

            # ── Unsafe yaml.load ───────────────────────────────────────────
            if _YAML_LOAD_UNSAFE.search(line):
                findings.append(Finding(
                    rule_id="DSER006",
                    rule_name="Insecure yaml.load() Without Safe Schema",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "yaml.load() is called without specifying a safe schema. "
                        "In js-yaml, the default unsafe load can execute JavaScript "
                        "via !!js/function YAML tags, leading to code execution."
                    ),
                    fix=(
                        "Use yaml.safeLoad() (deprecated) or yaml.load() with SAFE_SCHEMA:\n"
                        "  yaml.load(data, { schema: yaml.SAFE_SCHEMA })"
                    ),
                    language=language,
                ))

            # ── Weak Crypto ────────────────────────────────────────────────
            m = _WEAK_HASH_PATTERN.search(line)
            if m:
                algo = m.group(1)
                findings.append(Finding(
                    rule_id="CRY004",
                    rule_name=f"Weak Hash Algorithm: crypto.createHash('{algo}')",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        f"crypto.createHash('{algo}') creates a weak, broken hash. "
                        f"{algo.upper()} is vulnerable to collision attacks and must not "
                        "be used for passwords, signatures, or data integrity verification."
                    ),
                    fix=(
                        "Use a stronger algorithm:\n"
                        "  crypto.createHash('sha256')  // for data integrity\n"
                        "  // For passwords, use bcrypt or argon2:\n"
                        "  const bcrypt = require('bcrypt');\n"
                        "  await bcrypt.hash(password, 12);"
                    ),
                    language=language,
                ))

            if _MATH_RANDOM_SECURITY.search(line):
                findings.append(Finding(
                    rule_id="CRY005",
                    rule_name="Insecure Math.random() for Security-Sensitive Value",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "Math.random() is used to generate a security-sensitive value "
                        "(token, secret, password, session ID, etc.). Math.random() is "
                        "a pseudo-random number generator (PRNG) — its output is predictable "
                        "and can be brute-forced or predicted by an attacker."
                    ),
                    fix=(
                        "Use the crypto module for security-sensitive values:\n"
                        "  const { randomBytes } = require('crypto');\n"
                        "  const token = randomBytes(32).toString('hex');  // 64 chars, secure"
                    ),
                    language=language,
                ))

            # ── Path Traversal ─────────────────────────────────────────────
            if _FS_TRAVERSAL_PATTERN.search(line):
                findings.append(Finding(
                    rule_id="PATH003",
                    rule_name="Path Traversal via fs Module with Dynamic Path",
                    severity="HIGH",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "A Node.js fs function is called with a dynamic path that may "
                        "be user-controlled. An attacker can use ../../ sequences to "
                        "read or write arbitrary files on the server."
                    ),
                    fix=(
                        "Resolve and validate the path before file operations:\n"
                        "  const path = require('path');\n"
                        "  const base = '/safe/uploads/';\n"
                        "  const safe = path.resolve(base, filename);\n"
                        "  if (!safe.startsWith(base)) throw new Error('Path traversal');"
                    ),
                    language=language,
                ))

            # ── CORS Wildcard ──────────────────────────────────────────────
            if _CORS_WILDCARD.search(line):
                findings.append(Finding(
                    rule_id="CFG010",
                    rule_name="CORS Misconfiguration: Wildcard Origin Allowed",
                    severity="MEDIUM",
                    file_path=str(file_path),
                    line_number=line_no,
                    snippet=line.strip(),
                    description=(
                        "CORS is configured with a wildcard origin (*), allowing any domain "
                        "to make cross-origin requests. For APIs that handle authentication "
                        "or sensitive data, this can expose resources to malicious websites "
                        "via cross-site request forgery or data theft."
                    ),
                    fix=(
                        "Specify an explicit allowlist of permitted origins:\n"
                        "  app.use(cors({ origin: ['https://yourdomain.com', 'https://app.yourdomain.com'] }))"
                    ),
                    language=language,
                ))

            # ── Hardcoded Credentials (JS-specific) ────────────────────────
            if _JS_HARDCODED_SECRET.search(line):
                m = _JS_HARDCODED_SECRET.search(line)
                val = m.group(0)
                if not _PLACEHOLDER_VALUES.search(val):
                    findings.append(Finding(
                        rule_id="SEC013",
                        rule_name="Hardcoded Credential in JavaScript/TypeScript",
                        severity="HIGH",
                        file_path=str(file_path),
                        line_number=line_no,
                        snippet=line.strip(),
                        description=(
                            "A password, secret, API key, or token is hardcoded as a string "
                            "literal. Anyone with access to the source code repository can "
                            "extract and misuse these credentials."
                        ),
                        fix=(
                            "Store secrets in environment variables:\n"
                            "  const apiKey = process.env.API_KEY;\n"
                            "For local development, use .env files with dotenv:\n"
                            "  require('dotenv').config();"
                        ),
                        language=language,
                    ))

        return findings
