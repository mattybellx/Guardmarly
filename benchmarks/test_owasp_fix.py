import subprocess, json, sys

test = "benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java"
r = subprocess.run(
    [sys.executable, "-m", "ansede_static.cli", test, "--format", "json", "--fail-on", "never"],
    capture_output=True, text=True
)
d = json.loads(r.stdout)
findings = [f for r2 in d.get("results", []) for f in r2.get("findings", [])]
print(f"BenchmarkTest00008 (SQLi): {len(findings)} findings")
for f in findings:
    print(f"  {f['cwe']} | {f['title'][:100]}")

# Also test path traversal
test2 = "benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"
r2 = subprocess.run(
    [sys.executable, "-m", "ansede_static.cli", test2, "--format", "json", "--fail-on", "never"],
    capture_output=True, text=True
)
d2 = json.loads(r2.stdout)
findings2 = [f for r3 in d2.get("results", []) for f in r3.get("findings", [])]
print(f"\nBenchmarkTest00001 (Path Traversal): {len(findings2)} findings")
for f in findings2:
    print(f"  {f['cwe']} | {f['title'][:100]}")
