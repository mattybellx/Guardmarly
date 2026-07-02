"""IFDS scan of OWASP helpers + testcode — multi-file interprocedural.

Key difference from previous OWASP runs:
- Previous: each file scanned independently, no cross-file taint
- Now: GlobalGraph + fixpoint propagates summaries across ALL files
- Interprocedural findings (JV-030) show cross-method taint chains
"""
import sys, time, json
sys.path.insert(0, "src")

from pathlib import Path
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
from ansede_static.java_analyzer import analyze_java

gg = GlobalGraph()
repo = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark")
all_files = list(repo.rglob("*.java"))
print(f"Scanning {len(all_files)} Java files with IFDS...")

# Phase 1: Scan all files
t0 = time.time()
all_findings = []
for fp in all_files:
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        all_findings.extend(result.findings)
    except Exception:
        pass

t1 = time.time()
print(f"Phase 1: {len(all_findings)} findings, {len(gg.function_summaries)} summaries in {t1-t0:.1f}s")

# Phase 2: Fixpoint
t0 = time.time()
stats = run_interprocedural_fixpoint(gg)
print(f"Phase 2: Fixpoint {stats} in {time.time()-t0:.1f}s")

# Phase 3: Re-scan with enriched summaries
t0 = time.time()
enriched = []
for fp in all_files:
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        enriched.extend(result.findings)
    except Exception:
        pass

t2 = time.time()
print(f"Phase 3: {len(enriched)} findings (+{len(enriched)-len(all_findings)}) in {t2-t0:.1f}s")

# Show interprocedural findings
interproc = [f for f in enriched if getattr(f, "rule_id", "") == "JV-030"]
print(f"\n=== Interprocedural findings (JV-030): {len(interproc)} ===")
for f in interproc[:10]:
    print(f"  L{f.line}: {f.title[:120]}")

# CWE breakdown
by_cwe = {}
for f in enriched:
    cwe = getattr(f, "cwe", "?")
    by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
print("\nBy CWE:")
for cwe, count in sorted(by_cwe.items(), key=lambda x: -x[1])[:12]:
    print(f"  {cwe}: {count}")
