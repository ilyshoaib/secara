import re

# Replicate exactly what the test sends
code = 'User.where("name = \'#{params[:name]}\'")'
print("Code bytes:", [c for c in code])

# Check if # is in wrong place
print("Contains #:", '#' in code)

# simplest possible pattern
m = re.search(r'where.*#\{', code)
print("Simple where+#{ match:", m)

# Check the actual chars around #{
idx = code.index('#')
print("Char before #:", repr(code[idx-1]))
print("Char at #:", repr(code[idx]))
print("Context:", repr(code[idx-5:idx+15]))
