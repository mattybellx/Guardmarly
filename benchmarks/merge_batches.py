"""Merge all batch scan results into aggregate before/after metrics."""
import json, glob
from collections import Counter
from pathlib import Path

base = Path(__file__).parent / "audit_results"

# Gather all raw scan files (not audited, not after_fix)
scan_files = sorted(
    f for f in base.glob("round*_java*.json")
    if "audited" not in f.name and "after_fix" not in f.name
)

total_repos = total_files = total_loc = total_findings = repos_with = repos_silent = 0
all_cwes = Counter()

print(f"Processing {len(scan_files)} batch files:\n")
for f in scan_files:
    d = json.loads(f.read_text())
    s = d["summary"]
    r = s["repos_scanned"]
    fc = s["total_findings"]
    print(f"  {f.name}: {r} repos, {s['total_files']} files, {s['total_loc']:,} LOC, {fc} findings")
    total_repos += r
    total_files += s["total_files"]
    total_loc += s["total_loc"]
    total_findings += fc
    repos_with += s["repos_with_findings"]
    repos_silent += s["repos_silent"]
    for cwe, cnt in s["by_cwe"].items():
        all_cwes[cwe] += cnt

print(f"\n{'='*60}")
print(f"AGGREGATE METRICS — BEFORE FIXES")
print(f"{'='*60}")
print(f"  Repos scanned:         {total_repos}")
print(f"  Files:                 {total_files:,}")
print(f"  LOC:                   {total_loc:,}")
print(f"  Total findings:        {total_findings}")
print(f"  Repos with findings:   {repos_with}")
print(f"  Silent repos:          {repos_silent}")
print(f"  Findings/repo:          {total_findings/total_repos:.1f}")
print(f"  Findings/1K LOC:        {total_findings/(total_loc/1000):.1f}")
print(f"\n  By CWE:")
for cwe, cnt in all_cwes.most_common():
    pct = cnt / total_findings * 100
    bar = "█" * int(pct / 2)
    print(f"    {cwe:12s}: {cnt:5d} ({pct:5.1f}%) {bar}")

# Save
merged = {
    "phase": "before_fixes",
    "total_repos": total_repos,
    "total_files": total_files,
    "total_loc": total_loc,
    "total_findings": total_findings,
    "repos_with_findings": repos_with,
    "silent_repos": repos_silent,
    "by_cwe": dict(all_cwes),
}
(base / "aggregate_before_fix.json").write_text(json.dumps(merged, indent=2))
print(f"\nSaved to {base / 'aggregate_before_fix.json'}")
