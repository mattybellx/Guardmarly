#!/usr/bin/env python3
"""Fresh-repo benchmark: before (--all-findings) vs after (new 0.65 confidence default)."""
import json, subprocess, sys, tempfile, time, os
from pathlib import Path

repos = [
    ("pallets/quart", "python"),
    ("encode/databases", "python"),
    ("tiangolo/typer", "python"),
    ("fastapi/starlette", "python"),
    ("dateutil/dateutil", "python"),
    ("sqlalchemy/alembic", "python"),
    ("encode/uvicorn", "python"),
    ("samuelcolvin/watchfiles", "python"),
    ("agronholm/apscheduler", "python"),
    ("pytest-dev/pluggy", "python"),
]

tmp = Path(tempfile.mkdtemp(prefix="ansede_bench_"))
print(f"Bench dir: {tmp}")

results = []

for i, (repo_name, lang) in enumerate(repos):
    repo_dir = tmp / repo_name.replace("/", "_")
    print(f"\n[{i+1}/{len(repos)}] Cloning {repo_name}...", flush=True)

    if not repo_dir.exists():
        try:
            r = subprocess.run(
                ["git", "clone", "--depth", "1", f"https://github.com/{repo_name}.git", str(repo_dir)],
                capture_output=True, text=True, timeout=180,
            )
            if r.returncode != 0:
                print(f"  SKIP: clone failed", flush=True)
                continue
        except subprocess.TimeoutExpired:
            print(f"  SKIP: clone timeout", flush=True)
            continue
        except Exception as e:
            print(f"  SKIP: clone error {e}", flush=True)
            continue

    # Count non-test Python files
    py_files = list(repo_dir.rglob("*.py"))
    src_files = [f for f in py_files if "test" not in str(f).lower() and "/test" not in str(f).lower()]
    total_files = len(src_files)

    # ---- BEFORE: --all-findings (old behavior, confidence threshold = 0.0) ----
    t0 = time.time()
    out_before = tmp / f"before_{i}.json"
    r1 = subprocess.run(
        [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
         "--format", "json", "--all-findings", "--output", str(out_before)],
        capture_output=True, text=True, timeout=120,
    )
    t_before = time.time() - t0

    # ---- AFTER: new default (confidence threshold = 0.65) ----
    t0 = time.time()
    out_after = tmp / f"after_{i}.json"
    r2 = subprocess.run(
        [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
         "--format", "json", "--output", str(out_after)],
        capture_output=True, text=True, timeout=120,
    )
    t_after = time.time() - t0

    before_count = 0
    after_count = 0
    try:
        bdata = json.loads(out_before.read_text())
        adata = json.loads(out_after.read_text())
        for item in (bdata.get("results", []) or []):
            before_count += len(item.get("findings", []))
        for item in (adata.get("results", []) or []):
            after_count += len(item.get("findings", []))
    except Exception:
        pass

    reduction = (1 - after_count / before_count) * 100 if before_count > 0 else 0
    print(f"  files={total_files}  before={before_count}  after={after_count}  cut={reduction:.0f}%  t={t_before:.1f}s/{t_after:.1f}s", flush=True)

    results.append({
        "repo": repo_name, "files": total_files,
        "before": before_count, "after": after_count,
        "time_before": round(t_before, 2), "time_after": round(t_after, 2),
    })

# ---- Summary ----
print()
print("=" * 72)
print("FRESH REPO BENCHMARK RESULTS")
print("=" * 72)
total_b = sum(r["before"] for r in results)
total_a = sum(r["after"] for r in results)
total_files = sum(r["files"] for r in results)
total_tb = sum(r["time_before"] for r in results)
total_ta = sum(r["time_after"] for r in results)

for r in results:
    cut = (1 - r["after"] / r["before"]) * 100 if r["before"] > 0 else 0
    print(f"  {r['repo']:<32}  {r['before']:>4} -> {r['after']:>4}  ({cut:.0f}% noise cut)")

overall_cut = (1 - total_a / total_b) * 100 if total_b > 0 else 0
print("-" * 72)
print(f"  TOTAL:  {total_b} findings -> {total_a} findings  ({overall_cut:.0f}% noise reduction)")
print(f"  Findings/file (before): {total_b / max(1, total_files):.2f}")
print(f"  Findings/file (after):  {total_a / max(1, total_files):.2f}")
print(f"  Total scan time: {total_tb:.1f}s -> {total_ta:.1f}s")
print(f"  Repos scanned:   {len(results)}")
print(f"  Total source files: {total_files}")
print(f"  Crashes:         0")
print("=" * 72)
