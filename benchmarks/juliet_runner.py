"""
Juliet Test Suite Runner for Ansede

Download Juliet from NIST SAMATE:
  https://samate.nist.gov/SARD/downloads/test-suites/

Usage:
  1. Download juliet-test-suite-for-java-v1-3.zip
  2. Extract to benchmarks/juliet/
  3. Run: python benchmarks/juliet_runner.py

Computes per-CWE precision, recall, and F1 against labeled ground truth.
Juliet files are labeled: filename contains "good" or "bad" and the CWE number.
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
SRC = BENCH_DIR.parent / "src"
sys.path.insert(0, str(SRC))


def parse_juliet_label(filename: str) -> tuple[str, bool] | None:
    """
    Parse Juliet filename label.
    Example: CWE89_SQL_Injection__connect_tcp_executeBatch_01_bad.java
    Returns: (cwe, is_vulnerable) or None
    """
    # Match CWE number
    cwe_match = re.search(r'CWE(\d+)', filename, re.IGNORECASE)
    if not cwe_match:
        return None
    cwe = f"CWE-{cwe_match.group(1)}"

    # Match good vs bad
    is_bad = '_bad.' in filename.lower() or '_bad_' in filename.lower()
    is_good = '_good.' in filename.lower() or '_good_' in filename.lower()

    if not is_bad and not is_good:
        return None

    return cwe, is_bad


def run_juliet_benchmark(juliet_dir: str) -> dict:
    """Run Ansede against Juliet test suite and compute per-CWE metrics."""
    from ansede_static import scan_code

    juliet_path = Path(juliet_dir)
    if not juliet_path.exists():
        print(f"ERROR: Juliet directory not found: {juliet_dir}")
        print("Download from: https://samate.nist.gov/SARD/downloads/test-suites/")
        return {}

    # Collect all Java files
    java_files = list(juliet_path.rglob("*.java"))
    if not java_files:
        print("No Java files found. Also check for C/C++ files if needed.")
        return {}

    print(f"Found {len(java_files)} Juliet test files")

    # Per-CWE tracking
    per_cwe: dict[str, dict] = defaultdict(lambda: {
        "total_bad": 0, "detected_bad": 0,  # TP for bad files
        "total_good": 0, "clean_good": 0,     # TN for good files
        "fp_on_good": 0,                       # FP on good files
    })

    start = time.perf_counter()
    for i, fpath in enumerate(java_files):
        if i % 500 == 0:
            print(f"  Progress: {i}/{len(java_files)}")

        label = parse_juliet_label(fpath.name)
        if label is None:
            continue

        cwe, is_bad = label

        try:
            code = fpath.read_text(encoding="utf-8", errors="replace")
            result = scan_code(code, "java", str(fpath))
            findings = result.findings if hasattr(result, "findings") else []
        except Exception:
            continue

        if is_bad:
            per_cwe[cwe]["total_bad"] += 1
            # TP if any finding with matching CWE
            if any(f.cwe == cwe for f in findings):
                per_cwe[cwe]["detected_bad"] += 1
        else:
            per_cwe[cwe]["total_good"] += 1
            has_finding = any(f.cwe == cwe for f in findings)
            if not has_finding:
                per_cwe[cwe]["clean_good"] += 1
            else:
                per_cwe[cwe]["fp_on_good"] += 1

    elapsed = time.perf_counter() - start
    print(f"Completed in {elapsed:.1f}s")

    # Compute metrics
    results = {}
    for cwe, stats in sorted(per_cwe.items()):
        tp = stats["detected_bad"]
        fn = stats["total_bad"] - tp
        fp = stats["fp_on_good"]
        tn = stats["clean_good"]

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        results[cwe] = {
            "recall": round(recall * 100, 1),
            "precision": round(precision * 100, 1),
            "f1": round(f1, 2),
            "total_bad": stats["total_bad"],
            "total_good": stats["total_good"],
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("juliet_dir", nargs="?", default="benchmarks/juliet")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    results = run_juliet_benchmark(args.juliet_dir)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\nJULIET TEST SUITE RESULTS")
        print("=" * 60)
        print(f"{'CWE':<12} {'Precision':>10} {'Recall':>10} {'F1':>8} {'Bad':>6} {'Good':>6}")
        print("-" * 60)
        for cwe, m in sorted(results.items()):
            print(f"{cwe:<12} {m['precision']:>9.1f}% {m['recall']:>9.1f}% {m['f1']:>7.2f} {m['total_bad']:>5} {m['total_good']:>5}")
