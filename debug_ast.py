import ast

def _attr_chain(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return parts

code = "import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n"
tree = ast.parse(code)
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func)
        print("Call:", chain)
