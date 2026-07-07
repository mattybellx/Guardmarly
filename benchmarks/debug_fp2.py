#!/usr/bin/env python
"""Debug: why cmdi echo + xss list.remove suppression didn't reduce FPR."""
from ansede_static.java_analyzer import analyze_java
from pathlib import Path

# cmdi FP
fp = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00051.java")
src = fp.read_text()
r = analyze_java(src, filename=str(fp))
print(f"cmdi FP 00051: {len(r.findings)} findings, CWEs={ {f.cwe for f in r.findings} }")
print(f"has echo: {'echo' in src.lower()}")
for f in r.findings:
    if f.cwe == "CWE-78":
        print(f"  CWE-78: {f.title[:80]} (rule={f.rule_id})")

# xss FP
fp2 = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00147.java")
src2 = fp2.read_text()
r2 = analyze_java(src2, filename=str(fp2))
print(f"\nxss FP 00147: {len(r2.findings)} findings, CWEs={ {f.cwe for f in r2.findings} }")
print(f"has list.remove(0): {'valueslist.remove(0)' in src2.lower() or 'list.remove(0)' in src2.lower()}")
for f in r2.findings:
    if f.cwe == "CWE-79":
        print(f"  CWE-79: {f.title[:80]} (rule={f.rule_id})")

# Check: is the method in the AST path or fallback path?
print("\nAST check:")
try:
    from ansede_static.java_ast_analyzer import analyze_java_ast
    ast_r = analyze_java_ast(src.encode(), str(fp))
    print(f"  cmdi 00051 AST findings: {len(ast_r.findings)}")
    for f in ast_r.findings:
        print(f"    {f.cwe}: {f.title[:60]}")
except Exception as e:
    print(f"  AST error: {e}")
