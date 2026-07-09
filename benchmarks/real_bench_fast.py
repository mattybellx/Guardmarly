"""real_bench_fast.py — Scan 31 repos with file caps for speed."""
import json, os, sys, time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files
from ansede_static import scan_file

REPOS_DIR = Path(__file__).resolve().parent.parent / "campaign" / "v2_100" / "repos"
RESULTS_FILE = Path(__file__).parent / "real_bench_31_results.json"
MAX_FILES = 50

repo_dirs = sorted(d for d in REPOS_DIR.iterdir() if d.is_dir() and not d.name.startswith('.'))
print(f"Found {len(repo_dirs)} repos, max {MAX_FILES} files each")

all_results = []
total_files = total_loc = total_findings = total_crashes = total_timeouts = 0
total_time_ms = 0
severity_counts = defaultdict(int)
cwe_counts = defaultdict(int)
repo_scores = []

for rd in repo_dirs:
    repo_name = rd.name
    print(f"  [{repo_name:25s}] ", end="", flush=True)
    
    try:
        all_files = _collect_files([rd], exclude_patterns=[])
    except Exception as e:
        print(f"ERROR: {e}")
        continue
    
    lang_files = [f for f in all_files if _detect_language(f) is not None]
    lang_files = lang_files[:MAX_FILES]
    
    loc = 0
    for f in lang_files:
        try:
            if f.stat().st_size <= 200 * 1024:
                loc += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    
    t0 = time.perf_counter()
    repo_findings = []
    crash_count = timeout_count = 0
    files_scanned = 0
    
    for fp in lang_files:
        try:
            result = scan_file(fp)
            files_scanned += 1
            for f in result.findings:
                repo_findings.append({
                    "severity": str(f.severity.value),
                    "cwe": f.cwe or "",
                    "rule_id": f.rule_id or "",
                    "confidence": f.confidence,
                })
        except Exception as e:
            if "timeout" in str(e).lower() or "timed" in str(e).lower():
                timeout_count += 1
            else:
                crash_count += 1
    
    elapsed = (time.perf_counter() - t0) * 1000
    f_count = len(repo_findings)
    
    total_files += files_scanned
    total_loc += loc
    total_findings += f_count
    total_crashes += crash_count
    total_timeouts += timeout_count
    total_time_ms += elapsed
    
    sevs = defaultdict(int)
    for f in repo_findings:
        sevs[f["severity"]] += 1
        if f["cwe"]:
            cwe_counts[f["cwe"]] += 1
    
    high_crit = sevs.get("critical", 0) + sevs.get("high", 0)
    repo_scores.append({
        "repo": repo_name, "files": files_scanned, "loc": loc,
        "findings": f_count, "critical": sevs.get("critical", 0),
        "high": sevs.get("high", 0), "medium": sevs.get("medium", 0),
        "low": sevs.get("low", 0), "crashes": crash_count,
        "timeouts": timeout_count, "time_ms": round(elapsed),
        "loc_per_sec": round(loc / (elapsed / 1000)) if elapsed > 0 else 0,
    })
    
    hc_str = f"{high_crit} H+" if high_crit > 0 else "0 H+"
    print(f"{files_scanned:3d}f/{loc:>6,}L → {f_count:4d}f ({hc_str}) {elapsed/1000:.1f}s", flush=True)

# ── Summary ──
print(f"\n{'='*70}")
print(f"  REAL-REPO BENCHMARK — {len(repo_dirs)} GitHub Repositories")
print(f"{'='*70}")
print(f"  Files scanned:  {total_files:,}")
print(f"  LOC analyzed:   {total_loc:,}")
print(f"  Findings:       {total_findings}")
print(f"  Crashes:        {total_crashes}")
print(f"  Timeouts:       {total_timeouts}")
print(f"  Scan time:      {total_time_ms/1000:.0f}s")
print(f"  LOC/sec:        {total_loc/(total_time_ms/1000):,.0f}" if total_time_ms else "")
print(f"{'='*70}")
print(f"  Severity:")
for s in ("critical", "high", "medium", "low", "info"):
    print(f"    {s:10s}: {sum(r[s] for r in repo_scores):5d}")

# Zero-crash repos
zero_crash = sum(1 for r in repo_scores if r["crashes"] == 0 and r["timeouts"] == 0)
print(f"\n  Repos with 0 crashes/timeouts: {zero_crash}/{len(repo_dirs)}")

# Top 15 CWEs
print(f"\n  Top 15 CWEs:")
for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1])[:15]:
    print(f"    {cwe:10s}: {count:5d}")

# Per-repo table
print(f"\n  Per-repo:")
for r in sorted(repo_scores, key=lambda x: -x["findings"]):
    crashes = f" {r['crashes']}crash" if r['crashes'] else ""
    tos = f" {r['timeouts']}to" if r['timeouts'] else ""
    print(f"    {r['repo']:25s} {r['files']:3d}f {r['loc']:>7,}L → {r['findings']:4d}f ({r['critical']}C/{r['high']}H/{r['medium']}M) {r['time_ms']/1000:5.1f}s{crashes}{tos}")

output = {
    "meta": {"repos": len(repo_dirs), "files": total_files, "loc": total_loc,
             "findings": total_findings, "crashes": total_crashes, "timeouts": total_timeouts,
             "time_ms": round(total_time_ms)},
    "severity": {s: sum(r[s] for r in repo_scores) for s in ("critical","high","medium","low","info")},
    "top_cwes": dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:30]),
    "repos": repo_scores,
}
with open(RESULTS_FILE, "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  → {RESULTS_FILE}")
