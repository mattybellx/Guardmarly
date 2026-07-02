"""Debug multi-line method body extraction."""
from ansede_static.java_analyzer import _collect_methods

src = open("benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java").read()
methods = _collect_methods(src)
for m in methods:
    body_has_brace = "{" in m.body
    body_lines = m.body.count("\n") + 1
    print(f"{m.name}: start={m.start_line} body_len={len(m.body)} body_lines={body_lines} hasBrace={body_has_brace} params={m.params}")
    # Check if body looks truncated
    if len(m.body) < 200:
        print(f"  FULL BODY: {m.body}")
