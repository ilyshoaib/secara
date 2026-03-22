"""
Tests for v0.6 — Java, PHP, and Ruby analyzers.
"""
import pytest
from pathlib import Path
from secara.detectors.java_analyzer import JavaAnalyzer
from secara.detectors.php_analyzer import PHPAnalyzer
from secara.detectors.ruby_analyzer import RubyAnalyzer


def java_ids(code: str):
    a = JavaAnalyzer()
    return {f.rule_id for f in a.analyze(Path("Test.java"), code)}


def php_ids(code: str):
    a = PHPAnalyzer()
    return {f.rule_id for f in a.analyze(Path("test.php"), code)}


def ruby_ids(code: str):
    a = RubyAnalyzer()
    return {f.rule_id for f in a.analyze(Path("test.rb"), code)}


# ─────────────────────────── JAVA TESTS ──────────────────────────────────────

class TestJavaAnalyzer:
    def test_detects_sqli_statement(self):
        code = '''
        String sql = "SELECT * FROM users WHERE id = " + userId;
        stmt.executeQuery(sql + " AND active=1");
        '''
        assert "SQL201" in java_ids(code)

    def test_safe_prepared_statement(self):
        code = '''
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ps.executeQuery();
        '''
        assert "SQL201" not in java_ids(code)

    def test_detects_xxe(self):
        code = '''
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(inputStream);
        '''
        assert "XXE201" in java_ids(code)

    def test_detects_insecure_deserialization(self):
        code = '''
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        Object obj = ois.readObject();
        '''
        assert "DSER201" in java_ids(code)

    def test_detects_weak_crypto_md5(self):
        code = '''
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        '''
        assert "CRY201" in java_ids(code)

    def test_detects_insecure_random(self):
        code = '''
        Random random = new Random();
        String token = String.valueOf(random.nextLong());
        '''
        assert "CRY202" in java_ids(code)

    def test_detects_csrf_disabled(self):
        code = '''
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated();
        '''
        assert "CONF201" in java_ids(code)

    def test_detects_cmdi_runtime_exec(self):
        code = '''
        String cmd = "ping " + userInput;
        Runtime.getRuntime().exec(cmd + " -c 4");
        '''
        assert "CMD201" in java_ids(code)


# ─────────────────────────── PHP TESTS ───────────────────────────────────────

class TestPHPAnalyzer:
    def test_detects_sqli_mysql_query(self):
        code = "<?php $result = mysql_query('SELECT * FROM users WHERE id=' . $_GET['id']); ?>"
        assert "SQL301" in php_ids(code)

    def test_detects_cmdi_exec(self):
        code = "<?php exec('ping ' . $_POST['host']); ?>"
        assert "CMD301" in php_ids(code)

    def test_detects_lfi(self):
        code = "<?php include($_GET['page'] . '.php'); ?>"
        assert "LFI301" in php_ids(code)

    def test_detects_xss_echo(self):
        code = "<?php echo $_GET['name']; ?>"
        assert "XSS301" in php_ids(code)

    def test_safe_echo_with_htmlspecialchars(self):
        code = "<?php echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8'); ?>"
        assert "XSS301" not in php_ids(code)

    def test_detects_unserialize(self):
        code = "<?php $obj = unserialize($_POST['data']); ?>"
        assert "DSER301" in php_ids(code)

    def test_detects_weak_password_hash(self):
        code = "<?php $hash = md5($password); ?>"
        assert "CRY301" in php_ids(code)

    def test_detects_path_traversal(self):
        code = "<?php $content = file_get_contents($_GET['file']); ?>"
        assert "PATH301" in php_ids(code)

    def test_detects_backtick_cmdi(self):
        code = "<?php $out = `ls {$_GET['dir']}`; ?>"
        assert "CMD302" in php_ids(code)


# ─────────────────────────── RUBY TESTS ──────────────────────────────────────

class TestRubyAnalyzer:
    def test_detects_sqli_activerecord(self):
        code = 'User.where("name = \'#{params[:name]}\'")'
        assert "SQL401" in ruby_ids(code)

    def test_safe_activerecord_hash(self):
        code = "User.where(name: params[:name])"
        assert "SQL401" not in ruby_ids(code)

    def test_detects_cmdi_backtick(self):
        code = 'output = `ls #{params[:dir]}`'
        assert "CMD401" in ruby_ids(code)

    def test_detects_html_safe_xss(self):
        code = '<%= params[:name].html_safe %>'
        assert "XSS401" in ruby_ids(code)

    def test_detects_path_traversal(self):
        code = 'content = File.read(params[:file])'
        assert "PATH401" in ruby_ids(code)

    def test_detects_marshal_load(self):
        code = 'data = Marshal.load(request.body.read)'
        assert "DSER401" in ruby_ids(code)

    def test_detects_weak_crypto(self):
        code = 'hash = Digest::MD5.hexdigest(password)'
        assert "CRY401" in ruby_ids(code)

    def test_detects_dynamic_dispatch(self):
        code = 'user.send(params[:method])'
        assert "DYN401" in ruby_ids(code)
