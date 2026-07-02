"""Fast OWASP Benchmark — inline scanning, no subprocess per file."""
import csv, json, sys, time
from pathlib import Path
from collections import defaultdict

OWASP_DIR = Path(__file__).resolve().parent / "owasp"
TESTCODE_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
EXPECTED_CSV = OWASP_DIR / "expectedresults-1.2.csv"

# Load expected results
expected = {}
with open(EXPECTED_CSV, encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        expected[row[0].strip()] = {
            "category": row[1].strip(),
            "is_vuln": row[2].strip().lower() == "true",
            "cwe": f"CWE-{row[3].strip()}",
        }

CATEGORY_CWE = {"cmdi": "CWE-78", "crypto": "CWE-327", "hash": "CWE-328",
                "sqli": "CWE-89", "ldapi": "CWE-90", "xpathi": "CWE-643",
                "pathtraver": "CWE-22", "xss": "CWE-79", "trustbound": "CWE-501",
                "securecookie": "CWE-614", "weakrand": "CWE-330"}

# Find test files
test_files = {p.stem: p for p in TESTCODE_DIR.glob("*.java")}
cases = sorted(set(expected) & set(test_files))
print(f"Loaded {len(cases)} testable cases")

# Run inline
from ansede_static.java_analyzer import analyze_java
from ansede_static._types import AnalysisResult

results = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "errors": 0}
cat_results = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})

t0 = time.perf_counter()
for i, case_name in enumerate(cases):
    info = expected[case_name]
    target_cwe = CATEGORY_CWE.get(info["category"], info["cwe"])
    filepath = test_files[case_name]

    if (i + 1) % 500 == 0:
        elapsed = time.perf_counter() - t0
        rate = (i + 1) / elapsed
        print(f"  {i+1}/{len(cases)} ({rate:.0f} files/s)...")

    try:
        src = filepath.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(src, filename=str(filepath))
        found_cwes = {f.cwe for f in result.findings if f.cwe}
    except Exception:
        results["errors"] += 1
        continue

    detected = target_cwe in found_cwes
    cat_results[info["category"]]["total"] += 1

    if info["is_vuln"]:
        if detected:
            results["tp"] += 1
            cat_results[info["category"]]["tp"] += 1
        else:
            results["fn"] += 1
            cat_results[info["category"]]["fn"] += 1
    else:
        if found_cwes:
            results["fp"] += 1
        else:
            results["tn"] += 1

elapsed = time.perf_counter() - t0
total = results["tp"] + results["fp"] + results["tn"] + results["fn"]
tpr = results["tp"] / (results["tp"] + results["fn"]) * 100 if (results["tp"] + results["fn"]) else 0
fpr = results["fp"] / (results["fp"] + results["tn"]) * 100 if (results["fp"] + results["tn"]) else 0
precision = results["tp"] / (results["tp"] + results["fp"]) * 100 if (results["tp"] + results["fp"]) else 0

print(f"\n{'='*60}")
print(f"OWASP Benchmark v1.2 — Ansede (inline)")
print(f"{'='*60}")
print(f"Cases: {total}  Time: {elapsed:.1f}s  Rate: {total/elapsed:.0f} files/s")
print(f"TP: {results['tp']}  FP: {results['fp']}  TN: {results['tn']}  FN: {results['fn']}")
print(f"Recall (TPR): {tpr:.1f}%  FPR: {fpr:.1f}%  Precision: {precision:.1f}%")
print(f"Youden: {tpr/100 - fpr/100:.3f}")

print(f"\n{'Category':<18} {'Cases':>6} {'TPR':>8}")
print("-" * 35)
for cat in sorted(cat_results):
    cr = cat_results[cat]
    denom = cr["tp"] + cr["fn"]
    tpr_cat = cr["tp"] / denom * 100 if denom else 0
    print(f"{cat:<18} {cr['total']:>6} {tpr_cat:>7.1f}%")

# Save scorecard
from datetime import datetime, timezone
scorecard = {
    "ts": datetime.now(timezone.utc).isoformat(),
    "benchmark": "OWASP Benchmark v1.2",
    "tool": "ansede-static",
    "total_cases": total,
    "elapsed_s": round(elapsed, 1),
    "rate_files_per_s": round(total / elapsed, 0),
    "tp": results["tp"], "fp": results["fp"], "tn": results["tn"], "fn": results["fn"],
    "recall_pct": round(tpr, 1), "fpr_pct": round(fpr, 1), "precision_pct": round(precision, 1),
    "youden": round(tpr / 100 - fpr / 100, 3),
    "category_breakdown": {cat: dict(cr) for cat, cr in cat_results.items()},
}
out_path = Path(__file__).resolve().parent / "owasp_scorecard.json"
out_path.write_text(json.dumps(scorecard, indent=2))
print(f"\nSaved: {out_path}")
