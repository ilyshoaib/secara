import re
from secara.rules.rule_loader import get_rules_for_language

rules = get_rules_for_language("ruby")
for r in rules:
    if r.id == "SQL401":
        pat_raw = r.pattern.get("regex", "")
        print("Raw:", repr(pat_raw))
        clean = pat_raw
        for fg in ("(?ix)", "(?xi)", "(?x)", "(?i)"):
            clean = clean.replace(fg, "")
        clean = clean.strip()
        # Test directly
        code = r"""User.where("name = '#{params[:name]}'"  )"""
        print("Code:", repr(code))
        try:
            m = re.search(clean, code, re.IGNORECASE | re.MULTILINE)
            print("Match:", m)
            # Try with re.DOTALL too
            m2 = re.search(clean, code, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            print("Match with DOTALL:", m2)
        except Exception as e:
            print("Error:", e)
        
        # Now try a simpler pattern
        simple = r'\.where\s*\(["\'][^"\']*#\{'
        m3 = re.search(simple, code)
        print("Simple match:", m3)
