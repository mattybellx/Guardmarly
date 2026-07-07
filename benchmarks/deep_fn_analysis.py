#!/usr/bin/env python
"""Analyze remaining FN cases for cmdi, sqli, xss — show exact code."""
import csv, sys, os
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

CATEGORY_CWE = {"cmdi": "CWE-78", "sqli": "CWE-89", "xss": "CWE-79", "crypto": "CWE-327", "hash": "CWE-328"}

for cat in ["cmdi", "sqli", "xss"]:
    target = CATEGORY_CWE[cat]
    fn_cases = []
    for name, (ecat, is_vuln) in expected.items():
        if ecat != cat or not is_vuln:
            continue
        fp = TEST_DIR / f"{name}.java"
        if not fp.exists():
            continue
        src = fp.read_text(encoding="utf-8", errors="replace")
        result = analyze_java(src, filename=str(fp))
        found_cwes = {f.cwe for f in result.findings if f.cwe}
        alt_cwes = ["CWE-327"] if cat == "hash" else []
        detected = target in found_cwes or any(a in found_cwes for a in alt_cwes)
        if not detected:
            fn_cases.append((name, src))
    
    print(f"\n{'='*60}")
    print(f"CATEGORY: {cat} — {len(fn_cases)} FN remaining")
    print(f"{'='*60}")
    for name, src in fn_cases[:2]:
        lines = src.splitlines()
        bl = src.lower()
        
        # Show key lines for this category
        if cat == "cmdi":
            for i, line in enumerate(lines):
                ls = line.lower()
                if any(kw in ls for kw in ["runtime", "exec(", "processbuilder", "getenv"]):
                    print(f"  {name} L{i+1}: {line.strip()}")
        elif cat == "sqli":
            for i, line in enumerate(lines):
                ls = line.lower()
                if any(kw in ls for kw in ["statement", "execute", "sql", "jdbc", "query", "string"]):
                    if not ls.strip().startswith("//"):
                        print(f"  {name} L{i+1}: {line.strip()}")
        elif cat == "xss":
            for i, line in enumerate(lines):
                ls = line.lower()
                if any(kw in ls for kw in ["writer", "output", "print", "format", "response.get", "flush"]):
                    print(f"  {name} L{i+1}: {line.strip()}")
        print()
