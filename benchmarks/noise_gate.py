#!/usr/bin/env python3
"""CI noise gate: ensure confidence threshold never suppresses HIGH/CRITICAL findings.

Usage: python benchmarks/noise_gate.py /path/to/repo1 /path/to/repo2 [repo3...]
Exit 0 if 0 HIGH/CRIT findings are lost. Exit 1 if any are suppressed.
"""
import json, subprocess, sys, tempfile, os
from pathlib import Path


def run_gate(repo_paths: list[str]) -> tuple[bool, str]:
    out = Path(tempfile.mkdtemp(prefix="ansede_gate_"))
    results: list[dict] = []

    for i, raw_path in enumerate(repo_paths):
        repo_dir = Path(raw_path)
        if not repo_dir.is_dir():
            return False, f"Directory not found: {repo_dir}"

        py_files = list(repo_dir.rglob("*.py"))
        fc = len(py_files)
        repo_name = repo_dir.name
        print(f"[{i+1}/{len(repo_paths)}] {repo_name}: {fc} .py files...", flush=True)

        # BEFORE: --all-findings (no confidence filter)
        r1 = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json", "--all-findings",
             "--output", str(out / f"before_{i}.json")],
            capture_output=True, text=True, timeout=300,
        )

        # AFTER: new default (0.65 confidence)
        r2 = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(repo_dir),
             "--format", "json",
             "--output", str(out / f"after_{i}.json")],
            capture_output=True, text=True, timeout=300,
        )

        bc = 0; ac = 0; bh = 0; ah = 0
        try:
            bd = json.loads((out / f"before_{i}.json").read_text())
            ad = json.loads((out / f"after_{i}.json").read_text())
            for item in (bd.get("results", []) or []):
                for f in item.get("findings", []):
                    bc += 1
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        bh += 1
            for item in (ad.get("results", []) or []):
                for f in item.get("findings", []):
                    ac += 1
                    if str(f.get("severity", "")).lower() in ("critical", "high"):
                        ah += 1
        except Exception as e:
            print(f"  Parse error: {e}", flush=True)
            continue

        cut = (1 - ac / bc) * 100 if bc else 0
        lost = bh - ah
        status = "PASS" if lost == 0 else "FAIL"
        print(f"  {status}: before={bc}({bh}h)  after={ac}({ah}h)  cut={cut:.0f}%  high_lost={lost}", flush=True)
        results.append({"repo": repo_name, "fc": fc, "bc": bc, "ac": ac, "bh": bh, "ah": ah, "lost": lost})

    total_lost = sum(r["lost"] for r in results)
    total_bh = sum(r["bh"] for r in results)

    if total_lost == 0:
        msg = f"NOISE GATE PASSED: 0/{total_bh} HIGH/CRIT findings suppressed across {len(results)} repos"
        return True, msg
    else:
        msg = f"NOISE GATE FAILED: {total_lost}/{total_bh} HIGH/CRIT findings were suppressed!\n"
        for r in results:
            if r["lost"] > 0:
                msg += f"  {r['repo']}: lost {r['lost']} high/crit findings\n"
        return False, msg


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python benchmarks/noise_gate.py /path/to/repo1 /path/to/repo2 ...")
        sys.exit(2)

    ok, message = run_gate(sys.argv[1:])
    print()
    print("=" * 60)
    print(message)
    print("=" * 60)
    sys.exit(0 if ok else 1)
