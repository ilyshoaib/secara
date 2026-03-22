import re
from secara.rules.rule_loader import get_rules_for_language

rules = get_rules_for_language("ruby")
for r in rules:
    if r.id == "SQL401":
        pat_raw = r.pattern.get("regex", "")
        print("Raw pattern:", repr(pat_raw))
        clean = pat_raw
        for fg in ("(?ix)", "(?xi)", "(?x)", "(?i)"):
            clean = clean.replace(fg, "")
        clean = clean.strip()
        print("Clean:", repr(clean))
        test = 'User.where("name = \'#{params[:name]}\'")'
        print("Test input:", repr(test))
        try:
            m = re.search(clean, test, re.IGNORECASE | re.MULTILINE)
            print("Match:", m)
        except Exception as e:
            print("Compile error:", e)
