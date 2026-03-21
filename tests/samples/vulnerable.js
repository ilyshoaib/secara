/**
 * INTENTIONALLY VULNERABLE JavaScript file for Secara testing.
 *
 * ⚠️  DO NOT USE IN PRODUCTION — Contains deliberate security vulnerabilities ⚠️
 * This file is used to verify that Secara correctly detects real issues.
 */

const { exec, execSync, spawn } = require("child_process");
const mysql = require("mysql2");

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 1: Hardcoded GitHub Token (SEC002 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
const GITHUB_TOKEN = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7";
const API_KEY = "AIzaSyD-9tSrke72I6e0dvos7bG55JzZVn5XvM8";

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 2: Hardcoded credential in variable
// ────────────────────────────────────────────────────────────────────────────
const api_secret = "prod_secret_key_DO_NOT_COMMIT_abc123xyz";
const database_password = "Passw0rdSQLServer2024!";

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 3: SQL Injection via string concatenation (SQL002 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
function getUserByName(req, res) {
  const username = req.body.username;
  const db = mysql.createConnection({});

  // VULNERABLE: String concatenation in SQL query
  db.query("SELECT * FROM users WHERE username = '" + username + "'", (err, results) => {
    res.json(results);
  });
}

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 4: SQL Injection via template literal (SQL002 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
async function getUserById(req, res) {
  const userId = req.params.id;

  // VULNERABLE: Template literal in SQL query
  const result = await db.query(`SELECT * FROM users WHERE id = ${userId}`);
  return result;
}

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 5: Command Injection via exec() (CMD101 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
function convertFile(req, res) {
  const filename = req.body.filename;

  // VULNERABLE: User input in exec()
  exec("convert " + filename + " output.pdf", (err, stdout) => {
    res.send(stdout);
  });
}

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 6: Command Injection via execSync() (CMD102 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
function runScript(req) {
  const scriptName = req.body.script;

  // VULNERABLE: User input in execSync with template literal
  const output = execSync(`bash scripts/${scriptName}`);
  return output.toString();
}

// ────────────────────────────────────────────────────────────────────────────
// VULNERABILITY 7: eval() with dynamic argument (CMD104 - HIGH)
// ────────────────────────────────────────────────────────────────────────────
function calculate(req, res) {
  const expression = req.query.expr;

  // VULNERABLE: eval with user input
  const result = eval(expression);
  res.json({ result });
}

// ────────────────────────────────────────────────────────────────────────────
// SAFE CODE BELOW — Expected: Zero findings
// ────────────────────────────────────────────────────────────────────────────

/**
 * ✅ SAFE: Parameterized query
 */
function safeGetUser(req, res) {
  const username = req.body.username;
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    res.json(results);
  });
}

/**
 * ✅ SAFE: spawn with explicit args array (no shell)
 */
function safeRunCommand(filename) {
  spawn("convert", [filename, "output.pdf"]);
}

/**
 * ✅ SAFE: JSON.parse instead of eval
 */
function safeParse(data) {
  return JSON.parse(data);
}
