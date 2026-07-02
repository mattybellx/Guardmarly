"""OWASP Benchmark v1.2 head-to-head: ansede vs semgrep.

Downloads the benchmark if needed, runs both tools on all 2,740 test cases,
compares against known ground truth, and generates a scorecard.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
import time
from pathlib import Path
from collections import defaultdict

OWASP_DIR = Path(__file__).resolve().parent / "owasp"
TESTCODE_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
EXPECTED_CSV = OWASP_DIR / "expectedresults-1.2.csv"


def load_expected() -> dict[str, dict]:
    """Parse expectedresults-1.2.csv into {test_name: {category, is_vuln, cwe}}."""
    expected = {}
    with open(EXPECTED_CSV, encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            name = row[0].strip()
            expected[name] = {
                "category": row[1].strip(),
                "is_vuln": row[2].strip().lower() == "true",
                "cwe": f"CWE-{row[3].strip()}",
            }
    return expected


def find_test_files() -> dict[str, Path]:
    """Map test names to their Java source files."""
    if not TESTCODE_DIR.exists():
        print(f"ERROR: Test code directory not found: {TESTCODE_DIR}")
        return {}
    return {p.stem: p for p in TESTCODE_DIR.glob("*.java")}


def run_ansede(filepath: Path) -> list[str]:
    """Run ansede on a single file, return list of CWE IDs found."""
    try:
        r = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(filepath),
             "--format", "json", "--fail-on", "never", "--timeout-per-file", "5"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        return []

    cwes = set()
    for entry in data.get("results", []):
        for f in entry.get("findings", []):
            cwe = (f.get("cwe", "") or "").upper()
            if cwe.startswith("CWE-"):
                cwes.add(cwe)
    return sorted(cwes)


def run_semgrep(filepath: Path) -> list[str]:
    """Run semgrep on a single file, return list of CWE-like categories found."""
    try:
        r = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--quiet", "--json", str(filepath)],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception:
        return []

    cwes = set()
    for result in data.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        if isinstance(cwe_list, str):
            cwe_list = [cwe_list]
        for c in cwe_list:
            cwe_str = str(c).upper()
            if cwe_str.startswith("CWE-"):
                cwes.add(cwe_str)
        # Also check rule ID for mapping
        rule_id = result.get("check_id", "")
        category = result.get("extra", {}).get("metadata", {}).get("owasp", "")
        if category:
            cwes.add(f"OWASP-{category}")
    return sorted(cwes)


# ── CWE-to-category mapping for OWASP Benchmark ─────────────────────────────
# Maps the OWASP Benchmark categories to the CWE numbers they test for
CATEGORY_CWE_MAP: dict[str, str] = {
    "cmdi": "CWE-78",
    "crypto": "CWE-327",
    "hash": "CWE-328",
    "sqli": "CWE-89",
    "ldapi": "CWE-90",
    "xpathi": "CWE-643",
    "pathtraver": "CWE-22",
    "xss": "CWE-79",
    "trustbound": "CWE-501",
    "securecookie": "CWE-614",
    "weakrand": "CWE-330",
}


def is_detection_correct(expected_cwe: str, found_cwes: list[str], category: str) -> bool:
    """Check if the tool correctly detected (or didn't detect) the vulnerability."""
    target_cwe = CATEGORY_CWE_MAP.get(category, expected_cwe)
    return target_cwe in found_cwes


def run_benchmark(max_cases: int | None = None):
    """Run the full benchmark comparison."""
    print("=" * 65)
    print("OWASP Benchmark v1.2 — Ansede vs Semgrep")
    print("=" * 65)

    expected = load_expected()
    test_files = find_test_files()
    print(f"Loaded {len(expected)} expected results, {len(test_files)} test files")

    # Only test cases with source files
    cases = sorted(set(expected) & set(test_files))
    print(f"Testable cases: {len(cases)}")
    if max_cases:
        cases = cases[:max_cases]
        print(f"Sampling first {max_cases} cases for quick run")

    results = {
        "ansede": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0},
        "semgrep": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0},
    }
    per_case = []

    for i, case_name in enumerate(cases):
        info = expected[case_name]
        is_vuln = info["is_vuln"]
        expected_cwe = info["cwe"]
        category = info["category"]
        filepath = test_files[case_name]

        if (i + 1) % 250 == 0:
            print(f"  Progress: {i+1}/{len(cases)}...")

        # Run ansede
        ansede_cwes = run_ansede(filepath)
        ansede_correct = is_detection_correct(expected_cwe, ansede_cwes, category)

        if is_vuln:
            if ansede_cwes:  # Found something
                if ansede_correct:
                    results["ansede"]["tp"] += 1
                else:
                    results["ansede"]["fp"] += 1  # Wrong CWE found
            else:
                results["ansede"]["fn"] += 1
        else:
            if ansede_cwes:
                results["ansede"]["fp"] += 1
            else:
                results["ansede"]["tn"] += 1

        # Run semgrep
        semgrep_cwes = run_semgrep(filepath)
        semgrep_correct = is_detection_correct(expected_cwe, semgrep_cwes, category)

        if is_vuln:
            if semgrep_cwes:
                if semgrep_correct:
                    results["semgrep"]["tp"] += 1
                else:
                    results["semgrep"]["fp"] += 1
            else:
                results["semgrep"]["fn"] += 1
        else:
            if semgrep_cwes:
                results["semgrep"]["fp"] += 1
            else:
                results["semgrep"]["tn"] += 1

        per_case.append({
            "case": case_name,
            "category": category,
            "expected_vuln": is_vuln,
            "expected_cwe": expected_cwe,
            "ansede_cwes": ansede_cwes,
            "ansede_correct": ansede_correct,
            "semgrep_cwes": semgrep_cwes,
            "semgrep_correct": semgrep_correct,
        })

    # ── Compute metrics ─────────────────────────────────────────────────────
    for tool in ("ansede", "semgrep"):
        r = results[tool]
        total = r["tp"] + r["fp"] + r["tn"] + r["fn"]
        r["total"] = total
        r["recall"] = round(r["tp"] / (r["tp"] + r["fn"]) * 100, 1) if (r["tp"] + r["fn"]) else 0
        r["precision"] = round(r["tp"] / (r["tp"] + r["fp"]) * 100, 1) if (r["tp"] + r["fp"]) else 0
        r["f1"] = round(2 * r["tp"] / (2 * r["tp"] + r["fp"] + r["fn"]) * 100, 1) if (2 * r["tp"] + r["fp"] + r["fn"]) else 0
        r["accuracy"] = round((r["tp"] + r["tn"]) / total * 100, 1) if total else 0
        r["tpr"] = round(r["tp"] / (r["tp"] + r["fn"]) * 100, 1) if (r["tp"] + r["fn"]) else 0  # same as recall
        fpr_denom = r["fp"] + r["tn"]
        r["fpr"] = round(r["fp"] / fpr_denom * 100, 1) if fpr_denom else 0
        # Youden index = TPR - FPR
        r["youden"] = round(r["tpr"] / 100 - r["fpr"] / 100, 3)

    # ── Print Results ───────────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("RESULTS")
    print("=" * 65)
    print(f"{'Metric':<20} {'Ansede':>12} {'Semgrep':>12}")
    print("-" * 45)
    for metric, label in [
        ("recall", "Recall (TPR) %"),
        ("precision", "Precision %"),
        ("f1", "F1 Score %"),
        ("accuracy", "Accuracy %"),
        ("fpr", "FPR %"),
        ("youden", "Youden Index"),
        ("tp", "True Positives"),
        ("fp", "False Positives"),
        ("tn", "True Negatives"),
        ("fn", "False Negatives"),
        ("total", "Total Cases"),
    ]:
        a_val = results["ansede"].get(metric, 0)
        s_val = results["semgrep"].get(metric, 0)
        if isinstance(a_val, float):
            print(f"{label:<20} {a_val:>11.1f} {s_val:>11.1f}")
        else:
            print(f"{label:<20} {a_val:>11} {s_val:>11}")

    # ── Category breakdown ──────────────────────────────────────────────────
    print()
    print("=" * 65)
    print("BY CATEGORY")
    print("=" * 65)
    cat_results = defaultdict(lambda: {"ansede_tp": 0, "ansede_fn": 0, "semgrep_tp": 0, "semgrep_fn": 0, "total": 0})
    for case in per_case:
        cat = case["category"]
        cat_results[cat]["total"] += 1
        if case["expected_vuln"]:
            if case["ansede_correct"]:
                cat_results[cat]["ansede_tp"] += 1
            else:
                cat_results[cat]["ansede_fn"] += 1
            if case["semgrep_correct"]:
                cat_results[cat]["semgrep_tp"] += 1
            else:
                cat_results[cat]["semgrep_fn"] += 1

    print(f"{'Category':<18} {'Cases':>6} {'Ansede TPR':>11} {'Semgrep TPR':>11}")
    print("-" * 50)
    for cat in sorted(cat_results):
        cr = cat_results[cat]
        denom = cr["ansede_tp"] + cr["ansede_fn"]
        a_tpr = round(cr["ansede_tp"] / denom * 100, 1) if denom else 0
        s_denom = cr["semgrep_tp"] + cr["semgrep_fn"]
        s_tpr = round(cr["semgrep_tp"] / s_denom * 100, 1) if s_denom else 0
        print(f"{cat:<18} {cr['total']:>6} {a_tpr:>10.1f}% {s_tpr:>10.1f}%")

    # ── Save ────────────────────────────────────────────────────────────────
    from datetime import datetime, timezone

    scorecard = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "benchmark": "OWASP Benchmark v1.2",
        "total_cases": len(cases),
        "results": {k: {kk: vv for kk, vv in v.items()} for k, v in results.items()},
        "category_breakdown": {
            cat: {k: v for k, v in cr.items()}
            for cat, cr in cat_results.items()
        },
    }
    out_path = Path(__file__).resolve().parent / "owasp_scorecard.json"
    out_path.write_text(json.dumps(scorecard, indent=2))
    print(f"\nSaved: {out_path}")
    return scorecard


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=None, help="Only run N test cases (for quick testing)")
    parser.add_argument("--ansede-only", action="store_true")
    parser.add_argument("--semgrep-only", action="store_true")
    args = parser.parse_args()

    if not EXPECTED_CSV.exists():
        print("ERROR: OWASP Benchmark not found. Clone it first:")
        print("  git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git benchmarks/owasp")
        sys.exit(1)

    scorecard = run_benchmark(max_cases=args.sample)
