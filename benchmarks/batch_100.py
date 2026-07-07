"""
batch_100.py — Run 100 brand-new Java repos with retry-on-failure.
Outputs a single merged JSON with all results.
"""
import json, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = ROOT / "benchmarks" / "audit_results"
CACHE = Path(r"C:\Users\matth\AppData\Local\Temp\ansede_java_audit")
SAMPLER = ROOT / "benchmarks" / "java_blind_sample.py"

TARGET = 100
BATCH_SIZE = 10
START_SEED = 5001

def clear_cache():
    import shutil
    if CACHE.exists():
        shutil.rmtree(CACHE, ignore_errors=True)

def run_batch(seed, size):
    output = AUDIT_DIR / f"batch100_{seed}.json"
    cmd = [
        sys.executable, "-m", "benchmarks.java_blind_sample",
        "--repos", str(size),
        "--seed", str(seed),
        "--output", str(output),
    ]
    r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        return None, r.stderr[-300:]
    if not output.exists():
        return None, "Output file not created"
    return output, None

AUDIT_DIR.mkdir(parents=True, exist_ok=True)

completed = 0
batch_num = 0
all_outputs = []
failed_seeds = []

print(f"=== 100-REPO BATCH SCAN ===")
print(f"Target: {TARGET} repos in batches of {BATCH_SIZE}")
print(f"Start: {time.strftime('%H:%M:%S')}")
print()

while completed < TARGET:
    batch_num += 1
    seed = START_SEED + batch_num
    needed = min(BATCH_SIZE, TARGET - completed)

    clear_cache()

    print(f"[Batch {batch_num}] seed={seed}, target={needed} repos...", end=" ", flush=True)
    t0 = time.time()
    output, err = run_batch(seed, needed)
    elapsed = time.time() - t0

    if output is None:
        print(f"FAILED ({elapsed:.0f}s)")
        print(f"  Error: {err[:150] if err else 'unknown'}")
        failed_seeds.append(seed)
        continue

    d = json.loads(output.read_text())
    repos_in_batch = d["summary"]["repos_scanned"]
    findings = d["summary"]["total_findings"]
    completed += repos_in_batch
    all_outputs.append(output)

    print(f"DONE ({elapsed:.0f}s) — {repos_in_batch} repos, {findings} findings | Total: {completed}/{TARGET}")

    if repos_in_batch < needed:
        print(f"  ⚠️  Only got {repos_in_batch}/{needed} — GitHub API limit may be hit")

print()
print(f"=== COMPLETE: {completed} repos across {batch_num} batches ===")
print(f"  Failed batches: {len(failed_seeds)}")
print(f"  Finish: {time.strftime('%H:%M:%S')}")

# Merge all outputs
total_repos = 0
total_files = 0
total_loc = 0
total_findings = 0
all_cwes = {}
repos_with = 0
repos_silent = 0

for f in all_outputs:
    d = json.loads(f.read_text())
    s = d["summary"]
    total_repos += s.get("repos_scanned", 0)
    total_files += s.get("total_files", 0)
    total_loc += s.get("total_loc", 0)
    total_findings += s.get("total_findings", 0)
    repos_with += s.get("repos_with_findings", 0)
    repos_silent += s.get("repos_silent", 0)
    for cwe, cnt in s.get("by_cwe", {}).items():
        all_cwes[cwe] = all_cwes.get(cwe, 0) + cnt

merged = {
    "run_info": {
        "date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_repos": TARGET,
        "completed_repos": total_repos,
        "batches": batch_num,
        "failed_seeds": failed_seeds,
    },
    "summary": {
        "repos_scanned": total_repos,
        "repos_with_findings": repos_with,
        "repos_silent": repos_silent,
        "total_files": total_files,
        "total_loc": total_loc,
        "total_findings": total_findings,
        "findings_per_repo": round(total_findings / total_repos, 1) if total_repos else 0,
        "findings_per_1k_loc": round(total_findings / (total_loc / 1000), 1) if total_loc else 0,
        "by_cwe": dict(sorted(all_cwes.items(), key=lambda x: -x[1])),
        "percent_repos_silent": round(repos_silent / total_repos * 100, 1) if total_repos else 0,
        "percent_repos_with_findings": round(repos_with / total_repos * 100, 1) if total_repos else 0,
    },
}

merged_path = AUDIT_DIR / "batch100_merged.json"
merged_path.write_text(json.dumps(merged, indent=2))
print(f"\nMerged results: {merged_path}")
print(f"Total: {total_repos} repos, {total_files:,} files, {total_loc:,} LOC, {total_findings} findings")
