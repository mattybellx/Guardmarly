"""Validate interprocedural IFDS on multi-layer Java app."""
import sys
sys.path.insert(0, "src")

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.java_analyzer import analyze_java
from pathlib import Path

gg = GlobalGraph()

# Phase 1: Scan multi-layer app
code = open("tmp/MultilayerApp.java").read()
result = analyze_java(code, filename="tmp/MultilayerApp.java", global_graph=gg)

print("=== Phase 1: Initial scan ===")
print(f"Findings: {len(result.findings)}")
for f in result.findings:
    print(f"  {f.rule_id} L{f.line}: {f.title[:120]}")

print(f"\nGlobalGraph summaries: {len(gg.function_summaries)}")
for (fp, fn), summary in gg.function_summaries.items():
    print(f"  {fn}: args_to_sink={summary.args_to_sink} return_from_source={summary.return_from_source} depends_on={summary.depends_on}")

# Phase 2: Run fixpoint
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
print("\n=== Phase 2: Interprocedural fixpoint ===")
stats = run_interprocedural_fixpoint(gg)
print(f"Stats: {stats}")

# Phase 3: Re-scan with enriched summaries
print("\n=== Phase 3: Re-scan with enriched summaries ===")
result2 = analyze_java(code, filename="tmp/MultilayerApp.java", global_graph=gg)
print(f"Findings: {len(result2.findings)} (+{len(result2.findings) - len(result.findings)})")
for f in result2.findings:
    print(f"  {f.rule_id} L{f.line}: {f.title[:120]}")

# Show interprocedural findings
interproc = [f for f in result2.findings if getattr(f, "rule_id", "") == "JV-030"]
print(f"\nInterprocedural findings: {len(interproc)}")
for f in interproc:
    print(f"  L{f.line}: {f.title}")
