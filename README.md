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
| 🐚 **Bash / Shell (Tier 2)** | Eval injection, unsafe substitution patterns |
| ⚙️ **JSON / YAML / .env (Tier 2)** | Config file plaintext credential detection |
| ⚡ **Parallel Scanning** | ThreadPoolExecutor for fast multi-file processing |
| 💾 **Smart Cache** | SHA-256 file cache skips unchanged files |
| 🎨 **Beautiful Output** | Rich terminal UI, JSON mode, severity filtering |

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
- **Automatically add `~/.local/bin` to your PATH** (in `.bashrc`, `.zshrc`, or `.profile`)
- Verify the `secara` command works

Then reload your shell and you're done:

```bash
source ~/.bashrc   # or source ~/.zshrc if using zsh
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

# Force re-scan (ignore cache)
secara scan . --no-cache

# Scan with more parallel workers
secara scan /large/repo --workers 16
```

---

## 🛡️ Vulnerability Coverage

### Hardcoded Secrets

| Rule ID | Vulnerability | Severity |
|---------|--------------|----------|
| SEC001  | AWS Access Key (`AKIA...`) | HIGH |
| SEC002  | GitHub Personal Access Token (`ghp_...`) | HIGH |
| SEC005  | Stripe Live Secret Key (`sk_live_...`) | HIGH |
| SEC007  | Slack Token (`xox...`) | HIGH |
| SEC008  | Private Key Header (RSA/EC/OPENSSH) | HIGH |
| SEC010  | Google API Key (`AIza...`) | HIGH |
| SEC012  | Hardcoded JWT Token | HIGH |
| SEC013  | Generic Hardcoded Credential Assignment | HIGH |
| SEC014  | High-Entropy String (Possible Secret) | MEDIUM |

### SQL Injection

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| SQL001  | SQLi via String Concatenation / f-string | Python AST | HIGH |
| SQL002  | SQLi via Concatenation / Template Literal | JavaScript | HIGH |

### Command Injection

| Rule ID | Vulnerability | Languages | Severity |
|---------|--------------|-----------|----------|
| CMD001  | `os.system()` with dynamic args | Python | HIGH |
| CMD002  | `subprocess` with `shell=True` + dynamic cmd | Python | HIGH |
| CMD003  | `eval()` / `exec()` with non-literal arg | Python | HIGH/MED |
| CMD101  | `exec()` with dynamic arg | JavaScript | HIGH |
| CMD102  | `execSync()` with dynamic arg | JavaScript | HIGH |
| CMD103  | `spawn()` with dynamic first arg | JavaScript | HIGH |
| CMD104  | `eval()` with non-literal argument | JavaScript | HIGH |
| CMD105  | Prototype Pollution | JavaScript | MEDIUM |
| SH001   | `eval` with variable in shell script | Bash | HIGH |
| SH002   | Unsafe backtick substitution | Bash | HIGH |
| SH003   | Command substitution with external input | Bash | MEDIUM |
| SH004   | Dangerous command with unquoted variable | Bash | HIGH |
| CFG001  | Plaintext secret in config file | .env/.ini | HIGH |
| CFG002  | Plaintext secret in JSON config | JSON | HIGH |
| CFG003  | Plaintext secret in YAML config | YAML | HIGH |

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

- [ ] Go language support (Tier 1)
- [ ] Ruby / PHP support (Tier 2)
- [ ] SARIF output format (GitHub Code Scanning compatible)
- [ ] GitHub Actions workflow
- [ ] VS Code extension
- [ ] Interprocedural taint analysis
- [ ] Custom rule authoring (YAML)
- [ ] Path traversal detection
- [ ] SSRF detection
- [ ] Insecure deserialization detection

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ for the security community · **Star ⭐ if you find it useful**

</div>
