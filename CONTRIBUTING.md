# Contributing to Secara

Thank you for your interest in contributing to Secara! Secara is an open-source, CLI-based static code security scanner designed for high accuracy and developer trust. 

We welcome contributions of all kinds: new vulnerability detection rules, language support, false-positive fixes, performance improvements, and documentation updates.

## 🚀 Getting Started

### 1. Prerequisite

You will need Python 3.8+ installed on your system.

### 2. Fork and Clone

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/secara.git
   cd secara
   ```

### 3. Install Dependencies

Install the project in "editable" mode so your changes take effect immediately, along with the development dependencies (like `pytest`):

```bash
pip install -e .
pip install pytest
```

You can verify it works by running:
```bash
secara --version
```

---

## 🏗️ Architecture Overview

Before diving in, here is a quick overview of how Secara works:

1. **`secara/cli.py`**: The CLI entry point using `click`. Parses flags and initiates the scan.
2. **`secara/scanner/file_scanner.py`**: Crawls the directory tree, respecting `.gitignore` and `secara: ignore` comments. It uses SHA-256 caching (`cache.py`) to skip unchanged files.
3. **`secara/scanner/language_engine.py`**: Determines which `Detector` classes to run based on the file extension.
4. **`secara/detectors/`**: The brains of the scanner.
   - `secrets_detector.py`: Uses regex/entropy. Runs on *all* files.
   - `python_analyzer.py`: Uses the built-in `ast` module to detect SQLi, Command Injection, SSRF, Deserialization, etc., for `.py` files.
   - `js_analyzer.py`: Uses a fast regex-AST hybrid approach for `.js`/`.ts` files.
5. **`secara/taint/python_taint.py`**: A basic taint-tracking engine that tracks variables assigned from user input (like `request.args.get()`) to security sinks.

---

## 🛠️ How to Add a New Vulnerability Rule

It is highly recommended to add tests before or during rule creation. Here is the lifecycle of adding a new rule (e.g., adding an API key pattern).

### Example: Adding a new Hardcoded Secret

1. Open `secara/detectors/secrets_detector.py`.
2. Locate the `KNOWN_TOKEN_PATTERNS` list.
3. Add your new tuple: `(RuleID, RuleName, Severity, RegexPattern)`
   ```python
   (
       "SEC032",
       "Hardcoded Example API Key",
       "HIGH",
       r"EX-[a-zA-Z0-9]{32}",
   )
   ```
4. Open `tests/test_new_secrets.py` (or the relevant test file).
5. Add a test function for your rule:
   ```python
   def test_detects_example_key():
       code = 'example_key = "EX-abcdefghijklmnopqrstuvwxyz123456"\n'
       assert "SEC032" in rule_ids(code)
   ```
6. Run the tests (see **Running Tests**).

### Example: Adding an AST-based Python Rule

1. Open `secara/detectors/python_analyzer.py`.
2. Find the appropriate method (e.g., `_check_sql_injection` or create a new one like `_check_ssrf`).
3. Add the logic to inspect the `ast.Call` node. Use `_is_dynamic_string` or the `PythonTaintTracker` to determine if an argument is user-controlled.
4. Return a `secara.output.models.Finding` object if a vulnerability is found.
5. Add intentionally vulnerable code to `tests/samples/vulnerable.py`.
6. Add asserts to `tests/test_owasp_python.py`.

---

## 🧪 Running Tests

We use `pytest` for all unit testing. Before submitting a Pull Request, ensure all tests pass.

To run a full test suite:
```bash
python -m pytest tests/ -v
```

If you only want to see errors, you can use:
```bash
python -m pytest tests/ --tb=short
```

---

## 📝 Submitting a Pull Request

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/detect-aws-tokens
   ```
2. Commit your changes with clear, descriptive commit messages.
3. Ensure your code follows PEP-8 style guidelines (standard Python formatting).
4. Make sure all tests pass (`python -m pytest tests/`).
5. Push to your fork:
   ```bash
   git push origin feature/detect-aws-tokens
   ```
6. Open a Pull Request on the main repository.

### PR Checklist
- [ ] Code is formatted and readable.
- [ ] Added a test case in the `tests/` directory.
- [ ] Appropriate Rule IDs (`SEC...`, `SQL...`, `CMD...`) are documented in the `README.md` Vulnerability Coverage table if a new rule was added.
- [ ] Code runs offline cleanly (no external API calls allowed).

🎉 Thank you for making open-source code more secure!
