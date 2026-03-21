/**
 * Intentionally vulnerable JavaScript/TypeScript samples for testing.
 * Covers all new OWASP detections in the expanded JS analyzer.
 * DO NOT deploy in production.
 */

const crypto = require('crypto');
const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// ── Hardcoded Secrets [SEC013, SEC015, CRY004] ───────────────────────────────
const apiKey = "sk-abcdefghijklmnopqrstuvwxyz012345678901234567";  // SEC015/SEC013
const password = "SuperSecretPass123!";                             // SEC013
const token = "ghp_A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7";            // SEC002/SEC013

// ── Weak Crypto [CRY004] ─────────────────────────────────────────────────────
function hashPassword(pwd) {
    return crypto.createHash('md5').update(pwd).digest('hex');  // VULN: CRY004
}

function legacyChecksum(data) {
    return crypto.createHash('sha1').update(data).digest('hex'); // VULN: CRY004
}

// ── Insecure Random [CRY005] ─────────────────────────────────────────────────
const secret = Math.random().toString(36).slice(2);  // VULN: CRY005
const token_gen = Math.random();                     // VULN: CRY005
const sessionToken = "user_" + Math.random();        // VULN: CRY005

// ── SQL Injection [SQL002] ───────────────────────────────────────────────────
app.get('/user', (req, res) => {
    const userId = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${userId}`, (err, rows) => {  // VULN: SQL002
        res.json(rows);
    });
});

app.post('/login', (req, res) => {
    const { username } = req.body;
    db.query("SELECT * FROM users WHERE name = '" + username + "'", callback); // VULN: SQL002
});

// ── Command Injection [CMD101, CMD102, CMD103] ────────────────────────────────
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, callback);  // VULN: CMD101
});

app.get('/scan', (req, res) => {
    const target = req.params.target;
    const result = execSync("nmap " + target);  // VULN: CMD102
    res.send(result.toString());
});

function runScript(userScript) {
    spawn(userScript, ['--run']);  // VULN: CMD103
}

// ── eval() [CMD104] ──────────────────────────────────────────────────────────
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    const result = eval(expression);  // VULN: CMD104
    res.json({ result });
});

// ── Prototype Pollution [CMD107] ─────────────────────────────────────────────
app.post('/update', (req, res) => {
    Object.assign(config, req.body);        // VULN: CMD107 — __proto__ pollution
});

// ── XSS via innerHTML [XSS001] ───────────────────────────────────────────────
function displayUserName(req) {
    const name = req.params.name;
    document.getElementById('greeting').innerHTML = req.query.name;  // VULN: XSS001
}

// ── XSS via document.write [XSS003] ──────────────────────────────────────────
function renderComment(params) {
    document.write(params.comment);  // VULN: XSS003
}

// ── SSRF via fetch [SSRF002] ──────────────────────────────────────────────────
app.get('/proxy', async (req, res) => {
    const targetUrl = req.query.url;
    const data = await fetch(targetUrl);  // VULN: SSRF002
    res.send(await data.text());
});

app.get('/webhook', async (req, res) => {
    const webhook = req.body.webhook_url;
    await axios.post(webhook, { event: 'test' });  // VULN: SSRF002
});

// ── Path Traversal [PATH003] ─────────────────────────────────────────────────
app.get('/download', (req, res) => {
    const filename = req.query.file;
    fs.readFile('/uploads/' + filename, (err, data) => {  // VULN: PATH003
        res.send(data);
    });
});

app.get('/static', (req, res) => {
    const asset = req.params.asset;
    fs.readFileSync(`/var/www/${asset}`);  // VULN: PATH003
});

// ── Insecure Deserialization [DSER005] ────────────────────────────────────────
const serialize = require('node-serialize');

app.post('/restore', (req, res) => {
    const data = serialize.deserialize(req.body.state);  // VULN: DSER005
    res.json(data);
});

// ── CORS Wildcard [CFG010] ────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));  // VULN: CFG010

// ── Prototype Pollution via Direct __proto__ [CMD105] ────────────────────────
function mergeOptions(base, override) {
    for (const key of Object.keys(override)) {
        base.__proto__[key] = override[key];  // VULN: CMD105
    }
}
