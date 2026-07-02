"""OWASP Benchmark v1.2 — Ansede vs Semgrep (batch scan)."""
import csv, json, subprocess, sys, time
from pathlib import Path
from collections import defaultdict

OWASP_DIR = Path(__file__).resolve().parent / "owasp"
TESTCODE_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
EXPECTED_CSV = OWASP_DIR / "expectedresults-1.2.csv"

expected = {}
with open(EXPECTED_CSV, encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4: continue
        expected[row[0].strip()] = {"category": row[1].strip(), "is_vuln": row[2].strip().lower() == "true", "cwe": f"CWE-{row[3].strip()}"}

CATEGORY_CWE = {"cmdi":"CWE-78","crypto":"CWE-327","hash":"CWE-328","sqli":"CWE-89","ldapi":"CWE-90","xpathi":"CWE-643","pathtraver":"CWE-22","xss":"CWE-79","trustbound":"CWE-501","securecookie":"CWE-614","weakrand":"CWE-330"}

test_files = {p.stem: p for p in TESTCODE_DIR.glob("*.java")}
cases = sorted(set(expected) & set(test_files))
print(f"Loaded {len(cases)} testable cases")

# ── Semgrep batch scan ──────────────────────────────────────────────
print("Running Semgrep batch scan...")
t0 = time.perf_counter()
try:
    r = subprocess.run(["semgrep", "scan", "--config", "p/java", "--quiet", "--json", str(TESTCODE_DIR)], capture_output=True, text=True, timeout=120)
    sg_data = json.loads(r.stdout) if r.stdout.strip() else {}
    sg_elapsed = time.perf_counter() - t0
except Exception as e:
    print(f"Semgrep failed: {e}"); sg_data = {}; sg_elapsed = 0

sg_findings: dict[str, set[str]] = defaultdict(set)
for result in sg_data.get("results", []):
    stem = Path(result.get("path", "")).stem
    meta = result.get("extra", {}).get("metadata", {})
    cwe_list = meta.get("cwe", [])
    if isinstance(cwe_list, str): cwe_list = [cwe_list]
    for c in cwe_list:
        cwe_str = str(c).upper().split(":")[0].strip()  # Strip description
        if cwe_str.startswith("CWE-"): sg_findings[stem].add(cwe_str)
print(f"Semgrep: {len(sg_findings)} files with findings in {sg_elapsed:.1f}s")

# ── Ansede inline ────────────────────────────────────────────────────
from ansede_static.java_analyzer import analyze_java

results = {"ansede": {"tp":0,"fp":0,"tn":0,"fn":0}, "semgrep": {"tp":0,"fp":0,"tn":0,"fn":0}}
cat_results = defaultdict(lambda: {"a_tp":0,"a_fn":0,"s_tp":0,"s_fn":0,"total":0})

t1 = time.perf_counter()
for i, case_name in enumerate(cases):
    info = expected[case_name]; target_cwe = CATEGORY_CWE.get(info["category"], info["cwe"]); fp = test_files[case_name]
    if (i+1) % 500 == 0: print(f"  Ansede: {i+1}/{len(cases)}...")
    cat_results[info["category"]]["total"] += 1

    try:
        src = fp.read_text(encoding="utf-8", errors="replace")
        a_cwes = {f.cwe for f in analyze_java(src, filename=str(fp)).findings if f.cwe}
    except: a_cwes = set()

    if info["is_vuln"]:
        if target_cwe in a_cwes: results["ansede"]["tp"] += 1; cat_results[info["category"]]["a_tp"] += 1
        else: results["ansede"]["fn"] += 1; cat_results[info["category"]]["a_fn"] += 1
    else:
        if a_cwes: results["ansede"]["fp"] += 1
        else: results["ansede"]["tn"] += 1

    s_cwes = sg_findings.get(case_name, set())
    if info["is_vuln"]:
        if target_cwe in s_cwes: results["semgrep"]["tp"] += 1; cat_results[info["category"]]["s_tp"] += 1
        else: results["semgrep"]["fn"] += 1; cat_results[info["category"]]["s_fn"] += 1
    else:
        if s_cwes: results["semgrep"]["fp"] += 1
        else: results["semgrep"]["tn"] += 1

ansede_elapsed = time.perf_counter() - t1

def compute(r):
    r["total"] = r["tp"]+r["fp"]+r["tn"]+r["fn"]
    r["recall"] = round(r["tp"]/(r["tp"]+r["fn"])*100,1) if (r["tp"]+r["fn"]) else 0
    r["precision"] = round(r["tp"]/(r["tp"]+r["fp"])*100,1) if (r["tp"]+r["fp"]) else 0
    r["fpr"] = round(r["fp"]/(r["fp"]+r["tn"])*100,1) if (r["fp"]+r["tn"]) else 0
    r["youden"] = round(r["recall"]/100 - r["fpr"]/100, 3)
    return r
results["ansede"] = compute(results["ansede"])
results["semgrep"] = compute(results["semgrep"])

print(f"\n{'='*65}")
print(f"OWASP Benchmark v1.2 — Ansede vs Semgrep ({len(cases)} cases)")
print(f"{'='*65}")
print(f"Ansede: {ansede_elapsed:.1f}s  Semgrep: {sg_elapsed:.1f}s")
print(f"{'Metric':<20} {'Ansede':>12} {'Semgrep':>12}")
print("-"*45)
for key,label in [("recall","Recall %"),("precision","Precision %"),("fpr","FPR %"),("youden","Youden"),("tp","TP"),("fp","FP"),("tn","TN"),("fn","FN")]:
    a=results["ansede"].get(key,0); s=results["semgrep"].get(key,0)
    print(f"{label:<20} {a:>11.1f}" if isinstance(a,float) else f"{label:<20} {a:>11}", end="")
    print(f" {s:>11.1f}" if isinstance(s,float) else f" {s:>11}")

print(f"\n{'Category':<18} {'Cases':>6} {'Ansede':>10} {'Semgrep':>10} {'Win'}")
print("-"*52)
for cat in sorted(cat_results):
    cr=cat_results[cat]; ad=cr["a_tp"]+cr["a_fn"]; sd=cr["s_tp"]+cr["s_fn"]
    at=round(cr["a_tp"]/ad*100,1) if ad else 0; st=round(cr["s_tp"]/sd*100,1) if sd else 0
    w="A" if at>st else ("S" if st>at else "=")
    print(f"{cat:<18} {cr['total']:>6} {at:>9.1f}% {st:>9.1f}%  {w}")

aw=sum(1 for c in cat_results if (cat_results[c]["a_tp"]+cat_results[c]["a_fn"])>0 and cat_results[c]["a_tp"]>cat_results[c]["s_tp"])
sw=sum(1 for c in cat_results if (cat_results[c]["s_tp"]+cat_results[c]["s_fn"])>0 and cat_results[c]["s_tp"]>cat_results[c]["a_tp"])
tc=sum(1 for c in cat_results if (cat_results[c]["a_tp"]+cat_results[c]["a_fn"])>0)
print(f"\nCategory wins: Ansede {aw}/{tc}  Semgrep {sw}/{tc}")

from datetime import datetime, timezone
out={"ts":datetime.now(timezone.utc).isoformat(),"benchmark":"OWASP Benchmark v1.2","cases":len(cases),"ansede":results["ansede"],"semgrep":results["semgrep"]}
out_path=Path(__file__).resolve().parent/"owasp_head_to_head.json"
out_path.write_text(json.dumps(out,indent=2))
print(f"Saved: {out_path}")
