from pathlib import Path
from secara.detectors.java_analyzer import JavaAnalyzer
from secara.detectors.php_analyzer import PHPAnalyzer
from secara.detectors.ruby_analyzer import RubyAnalyzer

java_code = r"""
public class VulnerableController {
    public String getUser(String id) {
        String sql = "SELECT * FROM users WHERE id = " + id;
        Statement stmt = conn.createStatement();
        stmt.executeQuery(sql);
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        Random random = new Random();
        MessageDigest md = MessageDigest.getInstance("MD5");
        http.csrf().disable();
    }
}
"""

php_code = r"""
<?php
$id = $_GET["id"];
$result = mysql_query("SELECT * FROM users WHERE id=" . $id);
echo $_GET["name"];
include($_GET["page"] . ".php");
$data = unserialize($_POST["data"]);
$hash = md5($password);
?>
"""

ruby_code = """
class UsersController < ApplicationController
  def show
    @user = User.where("name = '\#{params[:name]}'").first
    render html: params[:html].html_safe
    content = File.read(params[:file])
    data = Marshal.load(request.body.read)
    Digest::MD5.hexdigest(password)
    user.send(params[:method])
  end
end
"""

j = JavaAnalyzer()
p = PHPAnalyzer()
r = RubyAnalyzer()

jf = j.analyze(Path("Vulnerable.java"), java_code)
pf = p.analyze(Path("vuln.php"), php_code)
rf = r.analyze(Path("users_controller.rb"), ruby_code)

print(f"Java: {len(jf)} findings")
for f in jf:
    print(f"  [{f.severity}] {f.rule_id}: {f.rule_name}")

print(f"\nPHP: {len(pf)} findings")
for f in pf:
    print(f"  [{f.severity}] {f.rule_id}: {f.rule_name}")

print(f"\nRuby: {len(rf)} findings")
for f in rf:
    print(f"  [{f.severity}] {f.rule_id}: {f.rule_name}")

print(f"\nTOTAL: {len(jf)+len(pf)+len(rf)} vulnerabilities detected across Java/PHP/Ruby")
