"""T3: score Guardmarly against OWASP Benchmark's own ground truth.

This is the evaluation that makes a recall claim survive review. The labels come
from the benchmark (`expectedresults-1.2.csv`), not from this repository, and the
scanner runs with default settings -- no per-corpus tuning.

Scoring follows the benchmark's convention:

* a test case counts as **flagged** when the scanner reports at least one finding
  in that case's file whose CWE matches the case's category;
* **TPR** = flagged vulnerable cases / all vulnerable cases;
* **FPR** = flagged safe cases / all safe cases.

Both are reported. A recall number without its false-positive rate is not a
result, and this script refuses to print one without the other.

Usage:
    python benchmarks/score_owasp_benchmark.py
    python benchmarks/score_owasp_benchmark.py --scan-only
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
CORPUS = REPO / ".corpora" / "owasp-benchmark-java"
GROUND_TRUTH = CORPUS / "expectedresults-1.2.csv"
SOURCE_ROOT = CORPUS / "src" / "main" / "java"
RESULTS = REPO / "benchmarks" / "results"
SCAN_JSON = RESULTS / "_owasp_scan.json"

_CWE_DIGITS = re.compile(r"(\d{2,4})")
_TEST_NAME = re.compile(r"(BenchmarkTest\d+)")


def load_ground_truth() -> dict[str, dict[str, object]]:
    """Read the benchmark's labels. Comment lines start with '#'."""
    if not GROUND_TRUTH.exists():
        raise SystemExit(
            f"ground truth not found: {GROUND_TRUTH}\n"
            "Run: python scripts/fetch_corpora.py --corpus owasp-benchmark-java"
        )
    cases: dict[str, dict[str, object]] = {}
    for line in GROUND_TRUTH.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            continue
        name, category, real, cwe = parts[0], parts[1], parts[2], parts[3]
        match = _TEST_NAME.search(name)
        if not match:
            continue
        cases[match.group(1)] = {
            "category": category,
            "vulnerable": real.lower() == "true",
            "cwe": (int(m.group(1)) if (m := _CWE_DIGITS.search(cwe)) else None),
        }
    return cases


def run_scan() -> dict[str, set[int]]:
    """Scan the corpus and return {test name: set of reported CWE numbers}."""
    RESULTS.mkdir(parents=True, exist_ok=True)
    argv = [
        sys.executable, "-m", "guardmarly.cli", str(SOURCE_ROOT),
        "--format", "json", "--output", str(SCAN_JSON),
        "--fail-on", "never", "--no-colour", "--workers", "8",
    ]
    print(f"[owasp] scanning {SOURCE_ROOT} ...", flush=True)
    started = time.perf_counter()
    proc = subprocess.run(
        argv, cwd=str(REPO), capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=7200, stdin=subprocess.DEVNULL,
    )
    elapsed = time.perf_counter() - started
    print(f"[owasp] scan finished in {elapsed:.1f}s (exit {proc.returncode})", flush=True)
    if not SCAN_JSON.exists():
        raise SystemExit(f"scan wrote no report\nstdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}")

    report = json.loads(SCAN_JSON.read_text(encoding="utf-8"))
    flagged: dict[str, set[int]] = {}
    for result in report.get("results", []):
        path = str(result.get("file") or "")
        match = _TEST_NAME.search(path)
        if not match:
            continue
        bucket = flagged.setdefault(match.group(1), set())
        for finding in result.get("findings", []):
            # Only security findings participate in the score.
            value = str(finding.get("cwe") or "")
            if finding.get("category") not in (None, "security"):
                continue
            digits = _CWE_DIGITS.search(value)
            if digits:
                bucket.add(int(digits.group(1)))
    return flagged


def score(cases: dict[str, dict[str, object]], flagged: dict[str, set[int]]) -> dict[str, object]:
    vulnerable = {n: c for n, c in cases.items() if c["vulnerable"]}
    safe = {n: c for n, c in cases.items() if not c["vulnerable"]}

    def hit(name: str, case: dict[str, object]) -> bool:
        reported = flagged.get(name)
        if not reported:
            return False
        return case["cwe"] in reported  # category match, not just "any finding"

    tp = [n for n, c in vulnerable.items() if hit(n, c)]
    fp = [n for n, c in safe.items() if hit(n, c)]

    tpr = len(tp) / len(vulnerable) if vulnerable else 0.0
    fpr = len(fp) / len(safe) if safe else 0.0

    by_category: dict[str, dict[str, int]] = {}
    for name, case in cases.items():
        row = by_category.setdefault(str(case["category"]), {"total": 0, "flagged": 0, "vulnerable": 0})
        row["total"] += 1
        if case["vulnerable"]:
            row["vulnerable"] += 1
        if hit(name, case):
            row["flagged"] += 1

    return {
        "cases": len(cases),
        "vulnerable": len(vulnerable),
        "safe": len(safe),
        "true_positives": len(tp),
        "false_positives": len(fp),
        "tpr": tpr,
        "fpr": fpr,
        "score": tpr - fpr,
        "by_category": by_category,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-only", action="store_true")
    args = parser.parse_args()

    cases = load_ground_truth()
    print(f"[owasp] ground truth: {len(cases)} labelled cases")
    if not cases:
        raise SystemExit("no usable ground-truth rows")

    flagged = run_scan()
    if args.scan_only:
        print(f"[owasp] flagged {len(flagged)} test-case files")
        return 0

    result = score(cases, flagged)
    (RESULTS / "_owasp_score.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    print()
    print("OWASP Benchmark v1.2 (independent labels, default settings)")
    print(f"  cases            : {result['cases']}")
    print(f"  vulnerable / safe: {result['vulnerable']} / {result['safe']}")
    print(f"  TPR (recall)     : {result['tpr'] * 100:.1f}%  ({result['true_positives']} flagged)")
    print(f"  FPR              : {result['fpr'] * 100:.1f}%  ({result['false_positives']} flagged)")
    print(f"  Youden score     : {result['score']:+.3f}")
    print()
    print("  by category:")
    for category, row in sorted(result["by_category"].items()):
        rate = row["flagged"] / row["total"] * 100 if row["total"] else 0.0
        print(f"    {category:<12} {row['flagged']:>4}/{row['total']:<4} {rate:5.1f}%  (vulnerable {row['vulnerable']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
