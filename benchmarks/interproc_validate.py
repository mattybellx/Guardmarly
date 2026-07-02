"""Real-world interprocedural validation — scan with GlobalGraph IFDS."""
import sys, json, time
sys.path.insert(0, "src")

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.java_analyzer import analyze_java
from pathlib import Path

# Scan the OWASP helpers + test code as a multi-file repo
gg = GlobalGraph()
repo = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark")
files = list(repo.rglob("*.java"))
print(f"Scanning {len(files)} Java files with GlobalGraph IFDS...")

t0 = time.time()
all_findings = []
for fp in files[:100]:  # Limit for speed
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        all_findings.extend(result.findings)
    except Exception as e:
        pass

elapsed = time.time() - t0
print(f"Scanned {min(100,len(files))} files in {elapsed:.1f}s ({min(100,len(files))/elapsed:.0f} f/s)")
print(f"Total findings: {len(all_findings)}")

# Categorize
by_cwe = {}
for f in all_findings:
    cwe = getattr(f, "cwe", "?")
    by_cwe[cwe] = by_cwe.get(cwe, 0) + 1

print("\nFindings by CWE:")
for cwe, count in sorted(by_cwe.items(), key=lambda x: -x[1])[:12]:
    print(f"  {cwe}: {count}")

# Check for interprocedural findings specifically
interproc = [f for f in all_findings if getattr(f, "rule_id", "") == "JV-030"]
print(f"\nInterprocedural findings (JV-030): {len(interproc)}")
for f in interproc[:5]:
    print(f"  L{f.line}: {f.title[:120]}")

# Verify GlobalGraph state
print(f"\nGlobalGraph summaries: {len(gg.function_summaries)}")
print(f"GlobalGraph IDE facts: {sum(1 for _ in gg.ide_facts.keys())}")
