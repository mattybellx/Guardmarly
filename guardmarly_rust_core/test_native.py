"""Quick test for the guardmarly_rust_core native module."""
from guardmarly_rust_core import is_available, get_version, parse_code_snippet, supported_languages

print(f"Available: {is_available()}")
print(f"Version: {get_version()}")
print(f"Languages: {supported_languages()}")

result = parse_code_snippet("import os\nos.system('ls')", "python", "test.py")
print(f"Nodes: {len(result)}")
print(f"Root kind: {result[0]['kind']}")
print(f"Root text preview: {result[0]['text'][:60]}")
print(f"Children: {len(result[0]['children'])}")

# Test JavaScript parsing too
js_result = parse_code_snippet("const x = 1;", "javascript", "test.js")
print(f"\nJS Nodes: {len(js_result)}")
print(f"JS Root kind: {js_result[0]['kind']}")

print("\nAll OK!")
