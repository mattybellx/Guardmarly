"""IFDS fixpoint validation — multi-file interprocedural taint detection."""
import sys, time, json
sys.path.insert(0, "src")

from pathlib import Path
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
from ansede_static.java_analyzer import analyze_java

gg = GlobalGraph()
repo = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark")
files = [f for f in repo.rglob("*.java") if "helpers" in str(f) or "testcode" in str(f)]
print(f"Phase 1: Scanning {len(files)} Java files with GlobalGraph IFDS...")

t0 = time.time()
all_findings = []
for fp in files[:50]:  # Limit for speed
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        all_findings.extend(result.findings)
    except Exception:
        pass

elapsed1 = time.time() - t0
print(f"Phase 1 done: {len(all_findings)} findings in {elapsed1:.1f}s")
print(f"GlobalGraph: {len(gg.function_summaries)} summaries, {sum(1 for _ in gg.ide_facts.keys())} IDE facts")

# Phase 2: Run fixpoint
print("\nPhase 2: Running interprocedural fixpoint...")
stats = run_interprocedural_fixpoint(gg)
print(f"Fixpoint: {stats}")

# Phase 3: Re-scan with enriched summaries
print("\nPhase 3: Re-scanning with enriched summaries...")
t0 = time.time()
enriched_findings = []
for fp in files[:50]:
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        enriched_findings.extend(result.findings)
    except Exception:
        pass

elapsed3 = time.time() - t0
new_findings = len(enriched_findings) - len(all_findings)
print(f"Phase 3 done: {len(enriched_findings)} findings (+{new_findings}) in {elapsed3:.1f}s")

# Show interprocedural findings
interproc = [f for f in enriched_findings if getattr(f, "rule_id", "") == "JV-030"]
print(f"\nInterprocedural findings (JV-030): {len(interproc)}")
for f in interproc[:8]:
    print(f"  L{f.line}: {f.title[:120]}")

# CWE breakdown
by_cwe = {}
for f in enriched_findings:
    cwe = getattr(f, "cwe", "?")
    by_cwe[cwe] = by_cwe.get(cwe, 0) + 1
print("\nFindings by CWE:")
for cwe, count in sorted(by_cwe.items(), key=lambda x: -x[1])[:12]:
    print(f"  {cwe}: {count}")
