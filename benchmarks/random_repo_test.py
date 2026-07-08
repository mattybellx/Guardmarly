"""Random-repo benchmark: before vs after on 4 fresh GitHub repos."""
import json, subprocess, sys, time, tempfile, os
from pathlib import Path

tmp_root = Path(os.environ["TEMP"])
repos = [
    (tmp_root / "ansede_bench_j6p8yubd" / "encode_databases", "encode/databases"),
    (tmp_root / "ansede_bench_j6p8yubd" / "pallets_quart", "pallets/quart"),
    (tmp_root / "ansede_bench_j6p8yubd" / "tiangolo_typer", "tiangolo/typer"),
    (tmp_root / "ansede_bench_x6ph6yuf" / "fastapi_starlette", "fastapi/starlette"),
]

out = Path(tempfile.mkdtemp(prefix="ansede_random_"))
results = []

for repo_dir, repo_name in repos:
    if not repo_dir.exists():
        print(f"SKIP {repo_name}: not found", flush=True)
        continue

    py_files = list(repo_dir.rglob("*.py"))
    fc = len(py_files)
    print(f"[{repo_name}] {fc} .py files...", flush=True)

    safe_name = repo_name.replace("/", "_")

    # BEFORE: --all-findings
    t0 = time.time()
    r1 = subprocess.run(
        [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
         "--format", "json", "--all-findings", "--output", str(out / f"b_{safe_name}.json")],
        capture_output=True, text=True, timeout=300,
    )
    tb = round(time.time() - t0, 1)

    # AFTER: new default (0.65 confidence)
    t0 = time.time()
    r2 = subprocess.run(
        [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
         "--format", "json", "--output", str(out / f"a_{safe_name}.json")],
        capture_output=True, text=True, timeout=300,
    )
    ta = round(time.time() - t0, 1)

    bc = 0; ac = 0; bh = 0; ah = 0
    try:
        bd = json.loads((out / f"b_{safe_name}.json").read_text())
        ad = json.loads((out / f"a_{safe_name}.json").read_text())
        for x in (bd.get("results", []) or []):
            for f in x.get("findings", []):
                bc += 1
                if f.get("severity", "") in ("critical", "high"):
                    bh += 1
        for x in (ad.get("results", []) or []):
            for f in x.get("findings", []):
                ac += 1
                if f.get("severity", "") in ("critical", "high"):
                    ah += 1
    except Exception as e:
        print(f"  parse error: {e}", flush=True)

    cut = (1 - ac / bc) * 100 if bc else 0
    high_lost = bh - ah
    print(f"  files={fc}  before={bc}({bh}h)  after={ac}({ah}h)  cut={cut:.0f}%  high_lost={high_lost}  t={tb}s/{ta}s", flush=True)
    results.append({
        "repo": repo_name, "files": fc,
        "before": bc, "after": ac, "bh": bh, "ah": ah,
    })

# Summary
print()
print("=" * 65)
print("RANDOM REPO BENCHMARK --- 4 FRESH REPOS (never scanned before)")
print("=" * 65)
tb_all = sum(r["before"] for r in results)
ta_all = sum(r["after"] for r in results)
bh_all = sum(r["bh"] for r in results)
ah_all = sum(r["ah"] for r in results)
tf_all = sum(r["files"] for r in results)

for r in results:
    cut = (1 - r["after"] / r["before"]) * 100 if r["before"] else 0
    lost = r["bh"] - r["ah"]
    print(f"  {r['repo']:<25}  {r['files']:>4} files  {r['before']:>4} -> {r['after']:>4}  cut={cut:>3.0f}%  high_lost={lost}")

print("-" * 65)
overall_cut = (1 - ta_all / tb_all) * 100 if tb_all else 0
print(f"  TOTAL: {len(results)} repos, {tf_all} files, {tb_all} -> {ta_all} findings ({overall_cut:.0f}% noise cut)")
print(f"  HIGH/CRIT lost: {bh_all - ah_all} / {bh_all}")
if tf_all > 0:
    print(f"  Avg findings/file before: {tb_all / tf_all:.1f}")
    print(f"  Avg findings/file after:  {ta_all / tf_all:.1f}")
print("=" * 65)
