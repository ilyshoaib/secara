import os
import sys

sys.path.insert(0, os.path.abspath("c:\\Users\\Admin\\Documents\\GitHub\\secara"))
from secara.detectors.secrets_detector import KNOWN_TOKEN_PATTERNS

yaml_output = ["rules:"]
for idx, (rule_id, name, severity, pattern) in enumerate(KNOWN_TOKEN_PATTERNS):
    yaml_output.append(f"  - id: {rule_id}")
    yaml_output.append(f"    name: \"{name}\"")
    yaml_output.append(f"    severity: {severity}")
    yaml_output.append(f"    description: \"{name} detected.\"")
    yaml_output.append(f"    fix: \"Remove the hardcoded secret and use environment variables or a secure vault.\"")
    yaml_output.append(f"    languages: [\"any\"]")
    yaml_output.append(f"    pattern:")
    yaml_output.append(f"      type: \"regex\"")
    # escape backslashes for YAML string, or use literal block
    # best: single quoted or literal scalar
    escaped_pattern = pattern.replace('\\', '\\\\').replace('"', '\\"')
    yaml_output.append(f"      regex: \"{escaped_pattern}\"")

os.makedirs("c:\\Users\\Admin\\Documents\\GitHub\\secara\\secara\\rules\\builtin", exist_ok=True)
with open("c:\\Users\\Admin\\Documents\\GitHub\\secara\\secara\\rules\\builtin\\secrets.yaml", "w", encoding="utf-8") as f:
    f.write("\n".join(yaml_output))

print("Dumped rules to secrets.yaml")
