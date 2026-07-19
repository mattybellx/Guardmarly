#!/usr/bin/env python3
"""
perf_check.py — Guardmarly performance regression checker.

Runs a quick scan on samples/ and reports throughput (LOC/s).
Compares against committed baseline in results/benchmarks/perf_baseline.json.
Fails if throughput drops below 80% of baseline.

Usage:
    python scripts/perf_check.py              # check against baseline
    python scripts/perf_check.py --baseline   # write new baseline
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE_PATH = ROOT / "results" / "benchmarks" / "perf_baseline.json"
SAMPLES_DIR = ROOT / "samples"
MIN_THROUGHPUT_RATIO = 0.80  # Must be >= 80% of baseline


def count_loc(directory: Path, extensions: set[str]) -> int:
    """Count lines of code in scannable files."""
    loc = 0
    for ext in extensions:
        for f in directory.rglob(f"*{ext}"):
            if f.is_file():
                try:
                    loc += sum(1 for _ in open(f, errors="replace"))
                except OSError:
                    pass
    return loc


def run_scan(directory: Path) -> tuple[int, float]:
    """Run guardmarly scan and return (LOC, seconds)."""
    import subprocess

    # Count LOC first
    exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".cs", ".go", ".php", ".rb"}
    loc = count_loc(directory, exts)

    if loc == 0:
        return 0, 0.0

    # Time the scan
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, "-m", "guardmarly.cli", str(directory), "--format", "json", "--all-findings"],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(ROOT),
    )
    elapsed = time.perf_counter() - start

    if result.returncode not in (0, 1):
        print(f"ERROR: Scan failed with exit code {result.returncode}", file=sys.stderr)
        print(result.stderr[:500], file=sys.stderr)
        return loc, elapsed

    return loc, elapsed


def load_baseline() -> dict | None:
    """Load the committed performance baseline."""
    if not BASELINE_PATH.exists():
        return None
    try:
        return json.loads(BASELINE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def save_baseline(loc: int, elapsed: float, throughput: float) -> None:
    """Write a new performance baseline."""
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    baseline = {
        "version": "baseline",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "loc": loc,
        "time_s": round(elapsed, 2),
        "throughput_loc_per_s": round(throughput, 1),
        "note": "Baseline measured on samples/ directory",
    }
    BASELINE_PATH.write_text(json.dumps(baseline, indent=2))
    print(f"Baseline written to {BASELINE_PATH}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Guardmarly performance regression checker")
    parser.add_argument("--baseline", action="store_true", help="Write new baseline instead of checking")
    args = parser.parse_args()

    if not SAMPLES_DIR.exists():
        print(f"ERROR: samples/ directory not found at {SAMPLES_DIR}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {SAMPLES_DIR}...")
    loc, elapsed = run_scan(SAMPLES_DIR)

    if loc == 0:
        print("ERROR: No scannable files found", file=sys.stderr)
        sys.exit(1)

    throughput = loc / elapsed if elapsed > 0 else 0

    print(f"  Files scanned: {SAMPLES_DIR}")
    print(f"  LOC: {loc:,}")
    print(f"  Time: {elapsed:.2f}s")
    print(f"  Throughput: {throughput:,.0f} LOC/s")

    if args.baseline:
        save_baseline(loc, elapsed, throughput)
        return

    baseline = load_baseline()
    if baseline is None:
        print("No baseline found. Run with --baseline to create one.")
        print("Proceeding without comparison.")
        return

    baseline_tput = baseline.get("throughput_loc_per_s", 0)
    if baseline_tput == 0:
        print("Baseline has zero throughput — skipping comparison.")
        return

    ratio = throughput / baseline_tput
    threshold = baseline_tput * MIN_THROUGHPUT_RATIO

    print(f"\n  Baseline throughput: {baseline_tput:,.0f} LOC/s")
    print(f"  Current throughput:  {throughput:,.0f} LOC/s")
    print(f"  Ratio: {ratio:.1%}")
    print(f"  Minimum allowed:     {threshold:,.0f} LOC/s ({MIN_THROUGHPUT_RATIO:.0%})")

    if throughput >= threshold:
        print(f"\n✅ PASS — Throughput {ratio:.1%} of baseline (≥ {MIN_THROUGHPUT_RATIO:.0%})")
    else:
        print(f"\n❌ FAIL — Throughput {ratio:.1%} of baseline (< {MIN_THROUGHPUT_RATIO:.0%})")
        sys.exit(1)


if __name__ == "__main__":
    main()
