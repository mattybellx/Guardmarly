"""Test all 5 languages via the native Rust core."""
import sys
sys.path.insert(0, r'C:\Users\matth\OneDrive\Desktop\guardmarly-focus')

from guardmarly_rust_core import is_available, get_version, parse_code_snippet, supported_languages

print(f"Available: {is_available()}")
print(f"Version: {get_version()}")
print(f"Languages: {supported_languages()}")
print()

tests = [
    ("python", "x = 1 + 2", "test.py"),
    ("javascript", "const y = 1;", "test.js"),
    ("java", "class Foo { int x = 1; }", "Test.java"),
    ("go", "package main\nfunc main() {}", "main.go"),
    ("csharp", "class Foo { int x = 1; }", "Test.cs"),
]

ok = 0
for lang, code, fn in tests:
    try:
        result = parse_code_snippet(code, lang, fn)
        root_kind = result[0]["kind"]
        print(f"[{lang:>10}] {fn:12s} -> root: {root_kind:15s} nodes: {len(result)} CHILDREN: {len(result[0]['children'])}")
        ok += 1
    except Exception as e:
        print(f"[{lang:>10}] {fn:12s} -> ERROR: {e}")

print(f"\n{ok}/{len(tests)} languages OK")
