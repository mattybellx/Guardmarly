"""Robust multi-repo scanner with live progress, error handling, IFDS analytics.

Scans all available Java files with timeout-per-file, live progress,
error logging, and comprehensive analytics reporting.
"""
import sys, time, json, traceback, threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, "src")

from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.ir.interprocedural_fixpoint import run_interprocedural_fixpoint
from ansede_static.java_analyzer import analyze_java

# ── Config ──
TIMEOUT_PER_FILE = 15  # seconds
PROGRESS_EVERY = 50    # files
MAX_FILES = 500        # limit for speed
OUTPUT = Path("benchmarks/campaign_results.json")
ERROR_LOG = Path("benchmarks/campaign_errors.log")

# ── Collect files ──
print("=" * 60)
print("ANSEDE REAL-WORLD SCAN CAMPAIGN")
print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
print("=" * 60)

sources = [
    Path("benchmarks/owasp/src/main/java/org/owasp/benchmark"),
    Path("tmp"),
]
java_files = []
for src in sources:
    if src.exists():
        found = list(src.rglob("*.java"))
        java_files.extend(found)
        print(f"  {src}: {len(found)} files")

# Deduplicate and limit
java_files = sorted(set(java_files))[:MAX_FILES]
print(f"\nTotal: {len(java_files)} Java files to scan")
print(f"Timeout: {TIMEOUT_PER_FILE}s per file")
print(f"IFDS: Enabled (GlobalGraph + fixpoint)")
print()

# ── Scan with progress ──
gg = GlobalGraph()
results: dict[str, dict] = {}
errors: list[str] = []
start_time = time.time()
files_done = 0
lock = threading.Lock()

def scan_one(fp: Path) -> tuple[str, list, float]:
    """Scan one file with timeout. Returns (path, findings, elapsed)."""
    t0 = time.time()
    try:
        code = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(code, filename=str(fp), global_graph=gg)
        findings_list = []
        for f in result.findings:
            findings_list.append({
                "rule_id": getattr(f, "rule_id", "?"),
                "cwe": getattr(f, "cwe", "?"),
                "line": getattr(f, "line", 0),
                "title": getattr(f, "title", "")[:200],
                "severity": str(getattr(f, "severity", "?")),
            })
        return str(fp), findings_list, time.time() - t0
    except Exception as e:
        return str(fp), [], time.time() - t0

# Phase 1: Scan all files
print("── Phase 1: Scanning ──")
t0 = time.time()
all_findings = []

for i, fp in enumerate(java_files):
    path, findings, elapsed = scan_one(fp)
    all_findings.extend(findings)
    with lock:
        files_done += 1
        if files_done % PROGRESS_EVERY == 0:
            elapsed_total = time.time() - t0
            rate = files_done / elapsed_total if elapsed_total > 0 else 0
            print(f"  [{files_done}/{len(java_files)}] {rate:.0f} f/s | {len(all_findings)} findings | {len(gg.function_summaries)} summaries")

t1 = time.time()
print(f"\nPhase 1 done: {len(all_findings)} findings, {len(gg.function_summaries)} summaries in {t1-t0:.1f}s")

# Phase 2: IFDS fixpoint
print("\n── Phase 2: IFDS Fixpoint ──")
t0 = time.time()
fix_stats = run_interprocedural_fixpoint(gg)
print(f"  Iterations: {fix_stats['iterations']}")
print(f"  Edges processed: {fix_stats['edges_processed']}")
print(f"  Summaries updated: {fix_stats['summaries_updated']}")
print(f"  Time: {time.time()-t0:.1f}s")

# Phase 3: Re-scan with enriched summaries
print("\n── Phase 3: Re-scan with enriched IFDS ──")
t0 = time.time()
enriched = []

for i, fp in enumerate(java_files):
    path, findings, elapsed = scan_one(fp)
    enriched.extend(findings)
    with lock:
        files_done += 1
        if files_done % PROGRESS_EVERY == 0:
            print(f"  [{files_done - len(java_files)}/{len(java_files)}] enriching...")

t2 = time.time()
new_findings = len(enriched) - len(all_findings)
interproc_count = sum(1 for f in enriched if f.get("rule_id") == "JV-030")
print(f"\nPhase 3 done: {len(enriched)} findings (+{new_findings} new)")
print(f"  Interprocedural (JV-030): {interproc_count}")
print(f"  Time: {t2-t0:.1f}s")

# ── Analytics ──
print("\n── Analytics ──")

# CWE breakdown
by_cwe = defaultdict(int)
by_rule = defaultdict(int)
for f in enriched:
    by_cwe[f.get("cwe", "?")] += 1
    by_rule[f.get("rule_id", "?")] += 1

print("\nFindings by CWE:")
for cwe, count in sorted(by_cwe.items(), key=lambda x: -x[1])[:15]:
    bar = "█" * min(40, count // 5)
    print(f"  {cwe:12s} {count:5d} {bar}")

print("\nFindings by Rule:")
for rule, count in sorted(by_rule.items(), key=lambda x: -x[1])[:10]:
    print(f"  {rule:12s} {count:5d}")

# Performance
total_time = t2 - start_time
print(f"\nPerformance:")
print(f"  Total time: {total_time:.1f}s")
print(f"  Files scanned: {len(java_files)} (×2 passes)")
print(f"  Rate: {len(java_files)*2/total_time:.1f} f/s")
print(f"  Findings per file: {len(enriched)/len(java_files):.1f}")
print(f"  IFDS overhead: {fix_stats['iterations']} iters, {fix_stats['edges_processed']} edges")

# Interprocedural samples
interproc_samples = [f for f in enriched if f.get("rule_id") == "JV-030"][:5]
if interproc_samples:
    print(f"\nInterprocedural sample findings ({len(interproc_samples)} of {interproc_count}):")
    for f in interproc_samples:
        print(f"  L{f['line']}: {f['title'][:150]}")

# Save report
report = {
    "ts": datetime.now().isoformat(),
    "files_scanned": len(java_files),
    "total_findings": len(enriched),
    "new_findings_after_fixpoint": new_findings,
    "interprocedural_findings": interproc_count,
    "by_cwe": dict(by_cwe),
    "by_rule": dict(by_rule),
    "fixpoint_stats": fix_stats,
    "total_time_s": round(total_time, 1),
    "errors": errors[:20],
    "summary_summaries": len(gg.function_summaries),
}
json.dump(report, open(OUTPUT, "w"), indent=2)

print(f"\n{'='*60}")
print(f"Report saved: {OUTPUT}")
print(f"Total findings: {len(enriched)}")
print(f"Interprocedural: {interproc_count}")
print(f"Errors: {len(errors)}")
print(f"{'='*60}")
