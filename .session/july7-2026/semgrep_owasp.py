#!/usr/bin/env python
"""Semgrep on OWASP Benchmark v1.2 — head-to-head with Ansede."""
import subprocess, csv, json, time, sys
from pathlib import Path

OWASP_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "owasp"
SEMGREP = r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\semgrep.exe"

# Run Semgrep on entire OWASP testcode
testcode = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
print(f"Running Semgrep on {testcode}...")
t0 = time.perf_counter()

r = subprocess.run(
    [SEMGREP, "scan", "--config=auto", "--quiet", "--json", str(testcode)],
    capture_output=True, text=True, timeout=600,
)
elapsed = time.perf_counter() - t0
print(f"Semgrep completed in {elapsed:.0f}s")

if r.returncode != 0:
    print(f"Semgrep error: {r.stderr[:500]}")
    sys.exit(1)

data = json.loads(r.stdout) if r.stdout.strip() else {"results": []}
results = data.get("results", [])
print(f"Semgrep raw findings: {len(results)}")

# Load expected results
expected_csv = OWASP_DIR / "expectedresults-1.2.csv"
expected = {}
with open(expected_csv, encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        expected[row[0].strip()] = {
            "category": row[1].strip(),
            "is_vuln": row[2].strip().lower() == "true",
            "cwe": f"CWE-{row[3].strip()}",
        }

CATEGORY_CWE = {
    "cmdi": "CWE-78", "crypto": "CWE-327", "hash": "CWE-328",
    "sqli": "CWE-89", "ldapi": "CWE-90", "xpathi": "CWE-643",
    "pathtraver": "CWE-22", "xss": "CWE-79", "trustbound": "CWE-501",
    "securecookie": "CWE-614", "weakrand": "CWE-330",
}

# Map findings to test cases
finding_by_case = {}
for r in results:
    path = r.get("path", "")
    case_name = Path(path).stem
    if case_name not in finding_by_case:
        finding_by_case[case_name] = []
    finding_by_case[case_name].append(r)

# Score
stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
for case_name, info in expected.items():
    target_cwe = CATEGORY_CWE.get(info["category"], info["cwe"])
    semgrep_findings = finding_by_case.get(case_name, [])
    detected = len(semgrep_findings) > 0
    
    if info["is_vuln"]:
        if detected:
            stats["tp"] += 1
        else:
            stats["fn"] += 1
    else:
        if detected:
            stats["fp"] += 1
        else:
            stats["tn"] += 1

total = stats["tp"] + stats["fp"] + stats["tn"] + stats["fn"]
tpr = stats["tp"] / (stats["tp"] + stats["fn"]) * 100 if (stats["tp"] + stats["fn"]) else 0
fpr = stats["fp"] / (stats["fp"] + stats["tn"]) * 100 if (stats["fp"] + stats["tn"]) else 0
precision = stats["tp"] / (stats["tp"] + stats["fp"]) * 100 if (stats["tp"] + stats["fp"]) else 0
youden = tpr / 100 - fpr / 100

print(f"\nSemgrep OWASP Benchmark v1.2")
print(f"TP: {stats['tp']}  FP: {stats['fp']}  TN: {stats['tn']}  FN: {stats['fn']}")
print(f"Recall: {tpr:.1f}%  FPR: {fpr:.1f}%  Precision: {precision:.1f}%  Youden: {youden:.3f}")
