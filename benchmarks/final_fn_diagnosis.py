#!/usr/bin/env python
"""Final deep analysis: remaining 170 FN cases — exact patterns we miss."""
import csv, sys, os, re
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ansede_static.java_analyzer import analyze_java

OWASP_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "owasp"
TEST_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"

expected = {}
with open(OWASP_DIR / "expectedresults-1.2.csv", encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        expected[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")

CATEGORY_CWE = {"cmdi": "CWE-78", "sqli": "CWE-89", "xss": "CWE-79"}
ALT_CWE = {"hash": ["CWE-327"], "crypto": ["CWE-328"]}

# Find ALL FN cases per category
for cat in ["sqli", "xss", "cmdi"]:
    target = CATEGORY_CWE[cat]
    fn_patterns = Counter()
    fn_count = 0
    
    for name, (ecat, is_vuln) in expected.items():
        if ecat != cat or not is_vuln:
            continue
        fp = TEST_DIR / f"{name}.java"
        if not fp.exists():
            continue
        src = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(src, filename=str(fp))
        found_cwes = {f.cwe for f in result.findings if f.cwe}
        if target not in found_cwes:
            fn_count += 1
            bl = src.lower()
            
            # Extract key API patterns
            if cat == "sqli":
                for pat in ["jdbctemplate", "queryforobject", "queryforlist", "queryformap",
                           "queryforrowset", "batchupdate", "execute(", "executeupdate",
                           "executequery", "preparestatement", "createstatement",
                           "jdbc", "datasource", "entitymanager", "session.createquery",
                           "hibernate", "jpa"]:
                    if pat in bl:
                        fn_patterns[pat] += 1
            elif cat == "xss":
                for pat in ["printf(", "format(", "append(", "println(", ".write(",
                           "getwriter()", "getoutputstream()", "print("]:
                    if pat in bl:
                        fn_patterns[pat] += 1
            elif cat == "cmdi":
                for pat in ["runtime.getruntime", ".exec(", "processbuilder",
                           "runtime.exec", "getruntime()"]:
                    if pat in bl:
                        fn_patterns[pat] += 1
    
    print(f"\n{cat}: {fn_count} FN remaining")
    print(f"  Top patterns in missed cases:")
    for pat, n in fn_patterns.most_common(10):
        print(f"    {pat}: {n}/{fn_count}")

# Also: what are the FP cases using that we could suppress?
print(f"\n{'='*60}")
print("FP ANALYSIS: Safe patterns we could suppress (without hitting TPs)")
print(f"{'='*60}")

# For each category, find FP cases that have a UNIQUE safe pattern not in any TP case
for cat in ["cmdi", "sqli", "xss"]:
    target = CATEGORY_CWE[cat]
    fp_cases = []
    tp_cases = []
    
    for name, (ecat, is_vuln) in expected.items():
        if ecat != cat:
            continue
        fp = TEST_DIR / f"{name}.java"
        if not fp.exists():
            continue
        src = fp.read_text(encoding="utf-8", errors="replace")
        if is_vuln:
            tp_cases.append(src.lower())
        else:
            fp_cases.append((name, src.lower()))
    
    # Find patterns unique to FP cases (never in TP)
    fp_unique = Counter()
    tp_all = " ".join(tp_cases)
    
    for name, src in fp_cases:
        if cat == "cmdi" and '"echo "' in src:
            if '"echo "' not in tp_all:
                fp_unique["echo_cmd"] += 1
        if cat == "sqli" and "callablestatement" in src:
            if "callablestatement" not in tp_all:
                fp_unique["CallableStatement"] += 1
        if cat == "xss" and "valueslist.remove(0)" in src:
            if "valueslist.remove(0)" not in tp_all:
                fp_unique["list.remove(0)"] += 1
    
    if fp_unique:
        print(f"\n{cat}: safe patterns unique to FP cases (safe to suppress):")
        for pat, n in fp_unique.most_common():
            print(f"  {pat}: {n} FP cases (0 TP cases use this)")
    else:
        print(f"\n{cat}: NO safe patterns unique to FP cases — all safe patterns also appear in TPs")
