import re

pattern = r"(?ix)(?:system|exec|spawn|IO\.popen)\s*\([^)]*#\{[^}]+\}|`[^`]*#\{[^}]+\}`"
test = "output = `ls #{params[:dir]}`"
m = re.search(pattern, test)
print("Match:", m)
print("Groups:", m.group(0) if m else "None")
