<div align="center">

# 🔍 Secara

### Static Code Security Scanner

**Fast. Accurate. Developer-Trusted.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

*Detect real, exploitable vulnerabilities — not style warnings.*

</div>

---

## What is Secara?

Secara is an open-source, **CLI-based static code security scanner** designed for accuracy and developer usability. It uses a hybrid of **AST-based analysis**, **regex pattern matching**, and **basic taint tracking** to detect real security vulnerabilities in your codebase — without false alarms.

It runs fully **offline**, requires **no cloud APIs**, and is built to scale across large monorepos.

---

## ✨ Features

| Feature | Details |
|--------|---------|
| 🔑 **Secrets Detection** | AWS keys, GitHub tokens, Stripe keys, private keys, high-entropy strings |
| 💉 **SQL Injection** | AST-based detection of string concat / f-string SQL in Python and JS |
| 🖥️ **Command Injection** | `os.system`, `subprocess` with `shell=True`, `exec()`, `eval()` |
| 🐍 **Python (Tier 1)** | Full AST analysis + single-function taint tracking |
| 🌐 **JavaScript / TypeScript (Tier 1)** | Regex-AST hybrid, no compiled dependencies |
| 🐹 **Go (Tier 2)** | Basic regex-based AST parsing (SQLi, CMDi, SSRF) |
| 🐚 **Bash / Shell (Tier 2)** | Eval injection, unsafe substitution patterns |
| ⚙️ **JSON / YAML / .env (Tier 2)** | Config file plaintext credential detection |
| ⚡ **Parallel Scanning** | ThreadPoolExecutor for fast multi-file processing |
| 💾 **Smart Cache** | SHA-256 file cache skips unchanged files |
| 🎨 **Beautiful Output** | Rich terminal UI, JSON mode, severity filtering |
| 🛠️ **CI/CD Ready** | Generate standard SARIF files for GitHub Actions Code Scanning |

---

## 🚀 Quick Start

### Linux / macOS — One-line install (recommended)

```bash
git clone https://github.com/ilyshoaib/secara.git
cd secara
bash install.sh
```

The installer will:
- Install secara from source
- **Create a global symlink in `/usr/local/bin`** (may prompt for `sudo` password)
- Verify the `secara` command works

You can now use `secara` from anywhere immediately:

```bash
secara scan .
```

---

### Manual install (all platforms)

```bash
git clone https://github.com/ilyshoaib/secara.git
cd secara
pip install -e .
```

**If `secara` command is not found after install** (common on Linux):

```bash
# Check where pip installed the script
python3 -c "import site; print(site.getusersitepackages())"

# Add ~/.local/bin to your PATH permanently
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/ilyshoaib/secara.git
cd secara
pip install -e .
# The secara command is available immediately — no PATH fix needed
secara scan .
```

> **PyPI release coming soon** — once published, installation will be simply `pip install secara`.

### Scan a directory

```bash
secara scan ./src
```

### Scan a single file

```bash
secara scan app.py
```

### JSON output (for CI/CD pipelines)

```bash
secara scan . --json > results.json
```

---

## 📖 Usage

```
Usage: secara scan [OPTIONS] PATH

  Scan a file or directory for security vulnerabilities.

Options:
  --json            Output results as JSON (machine-readable)
  --sarif           Output results as SARIF v2.1.0 for GitHub CI/CD integration
  -o, --output      Write output to file (useful with --sarif or --json)
  -v, --verbose     Show full descriptions and fix details
  -s, --severity    Minimum severity: HIGH | MEDIUM | LOW  [default: LOW]
  --no-cache        Disable file cache (re-scan everything)
  -w, --workers     Number of parallel worker threads  [default: 8]
  -V, --version     Show version and exit
  --help            Show this message and exit
```

### Examples

```bash
# Scan everything, show all findings
secara scan .

# Only show HIGH severity findings
secara scan . --severity HIGH

# Full details with fix suggestions
secara scan ./src --verbose

# Machine-readable JSON for CI integration
secara scan . --json | jq '.[] | select(.severity == "HIGH")'

# Generate SARIF for GitHub Code Scanning
secara scan . --sarif --output secara-results.sarif

# Force re-scan (ignore cache)
secara scan . --no-cache

# Scan with more parallel workers
secara scan /large/repo --workers 16
```

---

## 🛡️ Vulnerability Coverage (v0.2)

### 🔑 Hardcoded Secrets (35+ patterns)

| Rule ID | Vulnerability | Severity |
|---------|--------------|----------|
| SEC001 | AWS Access Key ID (`AKIA...`) | HIGH |
| SEC001B | AWS Secret Access Key | HIGH |
| SEC002 | GitHub PAT (`ghp_...`) | HIGH |
| SEC004B | GitHub Fine-Grained Token (`github_pat_...`) | HIGH |
| SEC004C | GitLab Token (`glpat-...`) | HIGH |
| SEC005 | Stripe Live Key (`sk_live_...`) | HIGH |
| SEC007B | Slack Webhook URL | HIGH |
| SEC008 | RSA/EC/OPENSSH Private Key Header | HIGH |
| SEC009 | SendGrid API Key (`SG....`) | HIGH |
| SEC010 | Google API Key (`AIza...`) | HIGH |
| SEC010B | Google OAuth Secret (`GOCSPX-...`) | HIGH |
| SEC010C | GCP Service Account Key | HIGH |
| SEC012 | Hardcoded JWT Token | HIGH |
| SEC015 | OpenAI API Key (`sk-...`) | HIGH |
| SEC016 | Anthropic API Key (`sk-ant-...`) | HIGH |
| SEC017 | Azure Storage Connection String | HIGH |
| SEC018 | npm Auth Token (`npm_...`) | HIGH |
| SEC020 | Telegram Bot Token | HIGH |
| SEC021 | Discord Bot Token | HIGH |
| SEC024 | PyPI Token (`pypi-...`) | HIGH |
| SEC025 | HuggingFace Token (`hf_...`) | HIGH |
| SEC026 | Databricks Token (`dapi...`) | HIGH |
| SEC028 | HashiCorp Vault Token (`hvs....`) | HIGH |
| SEC029 | Shopify Token (`shpat_...`) | HIGH |
| SEC031 | Database Connection String (Postgres/MySQL/MongoDB) | HIGH |
| SEC013 | Generic Hardcoded Credential (password/secret/api_key) | HIGH |
| SEC014 | High-Entropy String (Possible Secret) | MEDIUM |

### 💉 SQL Injection

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| SQL001 | SQLi via String Concat / f-string | Python AST | HIGH |
| SQL002 | SQLi via Concat / Template Literal | JavaScript | HIGH |
| SQL005 | SQLi via string construction in `db.Query` | Go | HIGH |

### 🖥️ Command Injection

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| CMD001 | `os.system()` with dynamic args | Python | HIGH |
| CMD002 | `subprocess` with `shell=True` + dynamic cmd | Python | HIGH |
| CMD003 | `eval()` / `exec()` with non-literal arg | Python | HIGH/MED |
| CMD101 | `exec()` with dynamic arg | JavaScript | HIGH |
| CMD102 | `execSync()` with dynamic arg | JavaScript | HIGH |
| CMD103 | `spawn()` with dynamic first arg | JavaScript | HIGH |
| CMD104 | `eval()` with non-literal arg | JavaScript | HIGH |
| CMD105 | Prototype Pollution (direct `__proto__` access) | JavaScript | MEDIUM |
| CMD107 | Prototype Pollution via `Object.assign(obj, req.body)` | JavaScript | HIGH |
| CMD005 | `exec.Command` with dynamic strings and `sh -c` | Go | HIGH |
| SH001 | `eval` with variable in shell script | Bash | HIGH |
| SH002 | Unsafe backtick substitution | Bash | HIGH |
| SH004 | Dangerous command with unquoted variable | Bash | HIGH |

### 🔐 Cryptographic Failures [OWASP A02]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| CRY001 | Weak hash: `hashlib.md5()` / `hashlib.sha1()` | Python | HIGH |
| CRY002 | SSL cert verification disabled: `verify=False` | Python | HIGH |
| CRY003 | Insecure PRNG: `random.random()` for secrets | Python | MEDIUM |
| CRY004 | Weak hash: `crypto.createHash('md5'/'sha1')` | JavaScript | HIGH |
| CRY005 | Insecure random: `Math.random()` for tokens/secrets | JavaScript | HIGH |

### 🌐 Server-Side Request Forgery [OWASP A10]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| SSRF001 | `requests.get/post(user_url)` — tainted URL | Python | HIGH |
| SSRF002 | `fetch/axios.get(user_url)` — tainted URL | JavaScript | HIGH |
| SSRF003 | `http.Get` with dynamic strings | Go | HIGH |

### 💣 Insecure Deserialization [OWASP A08]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| DSER001 | `pickle.loads(data)` — arbitrary code execution | Python | HIGH |
| DSER002 | `marshal.loads(data)` | Python | HIGH |
| DSER003 | `shelve.open(user_path)` — pickle-based | Python | MEDIUM |
| DSER004 | `yaml.load()` without `SafeLoader` | Python | HIGH |
| DSER005 | `node-serialize.deserialize(req.body)` | JavaScript | HIGH |
| DSER006 | `yaml.load()` without safe schema | JavaScript | HIGH |

### 📂 Path Traversal [OWASP A01]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| PATH001 | `open(user_input)` — directory traversal | Python | HIGH |
| PATH002 | Flask `send_file(user_input)` | Python | HIGH |
| PATH003 | `fs.readFile/writeFile` with dynamic path | JavaScript | HIGH |
| PATH004 | `os.Open` with dynamic path | Go | MEDIUM |

### 🎯 Injection — Extended [OWASP A03]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| SSTI001 | SSTI via `render_template_string(user_data)` | Python | HIGH |
| XSS001 | XSS via `innerHTML = req.params.x` | JavaScript | HIGH |
| XSS002 | Potential XSS via `element.innerHTML = var` | JavaScript | MEDIUM |
| XSS003 | XSS via `document.write(user_data)` | JavaScript | HIGH |

### 🔇 Security Logging Failures [OWASP A09]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| LOG001 | Sensitive variable (password/token) passed to logger | Python | MEDIUM |
| TEMP001 | Insecure Temporary File via `tempfile.mktemp()` | Python | HIGH |
| RACE001 | TOCTOU check via `os.path.exists()` before `open()` | Python | MEDIUM |
| MASS001 | Mass Assignment via `__dict__.update(user_data)` | Python | HIGH |
| MASS002 | Mass Assignment via `**kwargs` in ORM creation | Python | MEDIUM |

### ⚙️ Security Misconfiguration [OWASP A05]

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| CFG001 | Plaintext secret value in `.env`/`.ini` file | Config | HIGH |
| CFG002 | Plaintext secret in JSON config | JSON | HIGH |
| CFG003 | Plaintext secret in YAML config | YAML | HIGH |
| CFG010 | CORS wildcard `*` origin | JavaScript | MEDIUM |

---

## 🏗️ Architecture

```
secara/
├── cli.py                    # CLI entry point (Click)
├── scanner/
│   ├── file_scanner.py       # Recursive traversal + parallel execution
│   ├── language_engine.py    # Maps files to analysis tier
│   └── cache.py              # SHA-256 file cache (~/.secara/cache.json)
├── detectors/
│   ├── base.py               # Abstract detector interface
│   ├── secrets_detector.py   # Regex + Shannon entropy (all files)
│   ├── python_analyzer.py    # Python AST: SQLi, CMDi, eval/exec
│   ├── js_analyzer.py        # JavaScript/TypeScript: regex-AST hybrid
│   ├── shell_analyzer.py     # Bash: Tier 2 regex
│   └── config_analyzer.py   # JSON/YAML/.env: config secrets
├── taint/
│   └── python_taint.py       # Single-function taint tracking for Python
└── output/
    ├── models.py             # Finding dataclass
    └── formatter.py         # Rich CLI + JSON output
```

**Language Tiers:**
- **Tier 1** (Deep Analysis): Python, JavaScript, TypeScript
- **Tier 2** (Basic Detection): Bash, JSON, YAML
- **Secrets-only**: `.env`, `.ini`, `.toml`, `.cfg`

---

## ⚡ Performance

| Scenario | Performance |
|----------|------------|
| 1,000 Python files | ~2-3 seconds |
| 10,000 mixed files | ~15-25 seconds |
| Re-scan (cached) | ~0.5 seconds |
| Files > 512KB | Automatically skipped |
| Binary files | Automatically skipped |

Performance scales linearly with `--workers`. Cached results make repeat scans near-instant.

---

## 🔧 Suppressing False Positives

Add `# secara: ignore` to any line to suppress findings on that specific line:

```python
SIGNING_NONCE = "Xk9mP2wQzR4nV7tY1aL8cF0jH6"  # secara: ignore
result = eval(compile(safe_tree, "<string>", "eval"))  # secara: ignore
```

---

## 🧪 Running Tests

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=secara --cov-report=html
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas where you can help:**
- Adding new vulnerability rules
- Improving taint tracking accuracy
- Adding support for new languages (Go, Ruby, Java, PHP…)
- Improving false positive rate
- VS Code extension / GitHub Action support

---

## 🗺️ Roadmap

- [x] Go language support (Tier 2/Regex)
- [ ] Ruby / PHP support (Tier 2)
- [x] SARIF output format (GitHub Code Scanning compatible)
- [x] GitHub Actions workflow
- [ ] VS Code extension
- [ ] Interprocedural taint analysis
- [ ] Custom rule authoring (YAML)
- [x] Path traversal detection
- [x] SSRF detection
- [x] Insecure deserialization detection

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ for the security community · **Star ⭐ if you find it useful**

</div>
