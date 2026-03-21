import os
import sys

sys.path.insert(0, os.path.abspath("c:\\Users\\Admin\\Documents\\GitHub\\secara"))
from secara.detectors.secrets_detector import SecretsDetector
from pathlib import Path

detector = SecretsDetector()
res = detector.analyze(Path("test.py"), "aws_key = 'AKIA1234567890ABCDEF'\n")
print(f"Findings: {len(res)}")
for f in res:
    print(f.rule_id, f.rule_name)
    
if any(f.rule_id == "SEC001" for f in res):
    print("SUCCESS")
else:
    print("FAILURE")
