#!/usr/bin/env python3
"""Generate final campaign report from accumulated data."""
import json
from pathlib import Path

results = [
    {"name":"python-rich","lang":"python","loc":39120,"files":110,"ansede_n":79,"ansede_tp":60,"ansede_fp":19,"sg_n":20},
    {"name":"python-fastapi","lang":"python","loc":34004,"files":534,"ansede_n":202,"ansede_tp":196,"ansede_fp":6,"sg_n":32},
    {"name":"python-django","lang":"python","loc":161260,"files":913,"ansede_n":37,"ansede_tp":37,"ansede_fp":0,"sg_n":372},
    {"name":"python-flask","lang":"python","loc":9603,"files":25,"ansede_n":239,"ansede_tp":61,"ansede_fp":178,"sg_n":23},
    {"name":"python-starlette","lang":"python","loc":6658,"files":34,"ansede_n":180,"ansede_tp":27,"ansede_fp":153,"sg_n":10},
]

total_loc = sum(r["loc"] for r in results)
total_ansede = sum(r["ansede_n"] for r in results)
total_sg = sum(r["sg_n"] for r in results)
total_tp = sum(r["ansede_tp"] for r in results)
total_fp = sum(r["ansede_fp"] for r in results)
precision = round(total_tp/(total_tp+total_fp)*100,1) if (total_tp+total_fp) else 0

header = f"{'Repo':<22} {'LOC':>9} {'Ansede':>7} {'Semgrep':>8} {'Ratio':>7} {'TP':>6} {'FP':>6}"
sep = "-" * 73

print("=" * 73)
print("  ANSEDE vs SEMGREP-STYLE PATTERNS -- 5 Major Python Framework Repos")
print("=" * 73)
print(f"  Total LOC scanned: {total_loc:,}")
print(f"  Total source files: {sum(r['files'] for r in results)}")
print()
print(header)
print(sep)
for r in results:
    ratio = f"{r['ansede_n']/r['sg_n']:.1f}x" if r['sg_n'] else "N/A"
    print(f"{r['name']:<22} {r['loc']:>9,} {r['ansede_n']:>7} {r['sg_n']:>8} {ratio:>7} {r['ansede_tp']:>6} {r['ansede_fp']:>6}")
print(sep)
ratio_total = total_ansede/total_sg if total_sg else 0
print(f"{'TOTAL':<22} {total_loc:>9,} {total_ansede:>7} {total_sg:>8} {ratio_total:>6.1f}x {total_tp:>6} {total_fp:>6}")
print()
print("  KEY METRICS:")
print(f"    Ansede finds {ratio_total:.1f}x more issues than Semgrep-style patterns")
print(f"    Audit precision: {precision}% ({total_tp} TP / {total_tp+total_fp} classified)")
print(f"    Avg scan time: ~8s per repo")
print(f"    Ansede range: 37-239 findings per repo")
print(f"    Semgrep range: 10-372 matches per repo")
print()
print("  SEMGREP-STYLE PATTERNS USED (12 rules):")
print("    CWE-95 (eval/exec), CWE-78 (command injection), CWE-89 (SQLi),")
print("    CWE-79 (XSS), CWE-22 (path traversal), CWE-918 (SSRF),")
print("    CWE-601 (open redirect), CWE-502 (deserialization),")
print("    CWE-798 (hardcoded secrets), CWE-1333 (ReDoS),")
print("    CWE-611 (XXE), CWE-352 (CSRF)")
print()
print("  NOTES:")
print("    - Semgrep-style patterns are regex-only (no AST, no taint)")
print("    - Django's 372 Semgrep matches are mostly false positives on ORM code")
print("    - Ansede's higher FP on Flask/Starlette reflects aggressive heuristics")
print("    - Audit classification is automated (heuristic, not manual line-by-line)")
print("    - Full 50-repo campaign in progress; results accumulating in campaign/fast/")
print()

# Save JSON
report = {
    "ts": "2026-06-30T17:00:00Z",
    "campaign": "5 Python framework repos (50-repo campaign in progress)",
    "tools_compared": ["ansede-static v5.2.0", "Semgrep-style patterns (12 regex rules)"],
    "total_loc": total_loc,
    "total_files": sum(r["files"] for r in results),
    "ansede_total_findings": total_ansede,
    "semgrep_total_matches": total_sg,
    "ansede_audit_tp": total_tp,
    "ansede_audit_fp": total_fp,
    "ansede_precision_pct": precision,
    "ratio_ansede_vs_semgrep": round(ratio_total, 1),
    "per_repo": results,
}
out = Path("campaign/fast/results.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(report, indent=2))
print(f"  Report saved: {out}")
