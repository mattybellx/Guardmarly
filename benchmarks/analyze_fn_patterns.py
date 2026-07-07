#!/usr/bin/env python
"""Identify FN patterns — which OWASP TP cases are we still missing?"""
import csv, sys, os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ansede_static.java_analyzer import analyze_java

OWASP_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "owasp"
TEST_DIR = OWASP_DIR / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"

# Load expected results
expected = {}
with open(OWASP_DIR / "expectedresults-1.2.csv", encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        expected[row[0].strip()] = {
            "category": row[1].strip(),
            "is_vuln": row[2].strip().lower() == "true",
            "cwe": f"CWE-{row[3].strip()}",
        }

CATEGORY_CWE = {
    "hash": "CWE-328", "sqli": "CWE-89", "xss": "CWE-79",
    "cmdi": "CWE-78", "crypto": "CWE-327", "weakrand": "CWE-330",
    "pathtraver": "CWE-22", "trustbound": "CWE-501",
    "securecookie": "CWE-614", "ldapi": "CWE-90", "xpathi": "CWE-643",
}

# Find FN cases: is_vuln=True but NOT detected
fn_by_cat = {}
for name, info in expected.items():
    if not info["is_vuln"]:
        continue
    cat = info["category"]
    if cat not in fn_by_cat:
        fn_by_cat[cat] = []
    
    fp = TEST_DIR / f"{name}.java"
    if not fp.exists():
        continue
    
    src = fp.read_text(encoding="utf-8", errors="replace")
    result = analyze_java(src, filename=str(fp))
    found_cwes = {f.cwe for f in result.findings if f.cwe}
    target_cwe = CATEGORY_CWE.get(cat, info["cwe"])
    
    if target_cwe not in found_cwes:
        fn_by_cat[cat].append((name, src))

# Sample 3 FN cases per category and show distinguishing patterns
for cat in ["hash", "sqli", "xss", "cmdi"]:
    cases = fn_by_cat.get(cat, [])
    print(f"\n{'='*60}")
    print(f"CATEGORY: {cat} — {len(cases)} FN cases remaining")
    print(f"{'='*60}")
    
    for name, src in cases[:3]:
        bl = src.lower()
        patterns = []
        if "messagedigest" in bl: patterns.append("MessageDigest")
        if "getproperty" in bl: patterns.append("getProperty")
        if "preparedstatement" in bl: patterns.append("PreparedStatement")
        if "createstatement" in bl: patterns.append("createStatement")
        if "executequery" in bl: patterns.append("executeQuery")
        if "executeupdate" in bl: patterns.append("executeUpdate")
        if "string.format" in bl: patterns.append("String.format")
        if "stringbuilder" in bl: patterns.append("StringBuilder")
        if "+" in src: patterns.append("string_concat")
        if "runtime.exec" in bl or "processbuilder" in bl: patterns.append("exec/ProcessBuilder")
        if "getwriter" in bl or "getoutputstream" in bl: patterns.append("response.write")
        if "encodeforhtml" in bl or "esapi" in bl: patterns.append("ESAPI_encoder")
        if "print" in bl: patterns.append("print")
        
        print(f"  {name}: patterns={patterns}")
        
        # Show the key vulnerability line
        lines = src.splitlines()
        for i, line in enumerate(lines):
            ls = line.lower()
            if cat == "hash" and "messagedigest" in ls:
                print(f"    L{i+1}: {line.strip()}")
            elif cat == "sqli" and ("execute" in ls or "statement" in ls):
                print(f"    L{i+1}: {line.strip()}")
            elif cat == "xss" and ("writer" in ls or "print" in ls or "output" in ls):
                print(f"    L{i+1}: {line.strip()}")
            elif cat == "cmdi" and ("exec" in ls or "processbuilder" in ls or "runtime" in ls):
                print(f"    L{i+1}: {line.strip()}")

# Also analyze FP cases
print(f"\n{'='*60}")
print("FP ANALYSIS: Which safe patterns do OWASP FP cases use?")
print(f"{'='*60}")

# Find FP cases that we DO flag (should suppress)
fp_detected = {}
for name, info in expected.items():
    if info["is_vuln"]:
        continue
    cat = info["category"]
    fp = TEST_DIR / f"{name}.java"
    if not fp.exists():
        continue
    
    src = fp.read_text(encoding="utf-8", errors="replace")
    result = analyze_java(src, filename=str(fp))
    found_cwes = {f.cwe for f in result.findings if f.cwe}
    target_cwe = CATEGORY_CWE.get(cat, info["cwe"])
    
    if target_cwe in found_cwes:
        if cat not in fp_detected:
            fp_detected[cat] = []
        fp_detected[cat].append((name, src))

for cat in sorted(fp_detected):
    cases = fp_detected[cat]
    print(f"\n{cat}: {len(cases)} FP cases we wrongly flag")
    for name, src in cases[:2]:
        bl = src.lower()
        # Check for known safe patterns
        safes = []
        if "securerandom" in bl: safes.append("SecureRandom")
        if "aes/gcm" in bl: safes.append("AES/GCM")
        if "callablestatement" in bl: safes.append("CallableStatement")
        if "preparedstatement" in bl: safes.append("PreparedStatement")
        if "getcanonicalpath" in bl: safes.append("getCanonicalPath")
        if '"echo "' in bl: safes.append('echo_cmd')
        if "encodeforhtml" in bl or "esapi.encoder" in bl: safes.append("ESAPI")
        if "setsecure(true)" in bl: safes.append("setSecure")
        if "normalize" in bl: safes.append("normalize")
        if "remove(0)" in bl: safes.append("list.remove(0)")
        if "stringutils" in bl and "replace" in bl: safes.append("StringUtils.replace")
        
        print(f"  {name}: safe_patterns={safes}")
        
        # Print key safe line
        lines = src.splitlines()
        for i, line in enumerate(lines):
            ls = line.lower()
            if any(s in ls for s in ["securerandom", "aes/gcm", "callablestatement",
                                       "preparedstatement", "getcanonicalpath",
                                       'echo "', "encodeforhtml", "setsecure(true)",
                                       "normalize(", ".remove(0)"]):
                print(f"    L{i+1}: {line.strip()}")
                if len(safes) >= 3:
                    break
