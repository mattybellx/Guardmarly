#!/usr/bin/env python
"""Debug: why is hash (CWE-328) TPR only 2.3% on OWASP?"""
from ansede_static.java_analyzer import analyze_java
from pathlib import Path
import csv

# Load expected results
expected = {}
with open("benchmarks/owasp/expectedresults-1.2.csv", encoding="utf-8") as fh:
    for row in csv.reader(fh):
        if not row or row[0].startswith("#") or len(row) < 4:
            continue
        expected[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")

# Find hash TP cases (is_vuln=True in hash category)
test_dir = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode")
hash_tp = [n for n, (cat, vuln) in expected.items() if cat == "hash" and vuln]

# Test first 5 hash TP cases
for name in hash_tp[:5]:
    fp = test_dir / f"{name}.java"
    if not fp.exists():
        print(f"{name}: NOT FOUND")
        continue
    src = fp.read_text()
    r = analyze_java(src, filename=str(fp))
    found_cwes = {f.cwe for f in r.findings if f.cwe}
    bl = src.lower()
    has_md5 = "md5" in bl
    has_sha1 = "sha-1" in bl or "sha1" in bl
    has_message_digest = "messagedigest" in bl
    print(f"Hash TP {name}: CWEs={found_cwes}, md5={has_md5}, sha1={has_sha1}, msgDigest={has_message_digest}")
    if "CWE-328" not in found_cwes:
        # Print first 30 lines to see why
        for i, line in enumerate(src.splitlines()[:40], 1):
            print(f"  {i}: {line}")
        break
