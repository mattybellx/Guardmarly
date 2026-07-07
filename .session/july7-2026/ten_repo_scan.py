#!/usr/bin/env python
"""Scan 10 new random repos for definitive noise metrics."""
import subprocess, tempfile, os, sys, time, re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from ansede_static import scan_file

repos = [
    ("https://github.com/apache/logging-log4j2.git", "log4j2"),
    ("https://github.com/apache/commons-lang.git", "commons-lang"),
    ("https://github.com/apache/commons-net.git", "commons-net"),
    ("https://github.com/apache/commons-csv.git", "commons-csv"),
    ("https://github.com/apache/commons-email.git", "commons-email"),
    ("https://github.com/apache/commons-validator.git", "commons-validator"),
    ("https://github.com/apache/commons-math.git", "commons-math"),
    ("https://github.com/apache/commons-fileupload.git", "commons-fileupload"),
    ("https://github.com/apache/commons-dbcp.git", "commons-dbcp"),
    ("https://github.com/apache/commons-jexl.git", "commons-jexl"),
]

total_f = 0
total_find = 0
all_rates = []
all_pfs = []

for url, name in repos:
    tmp = tempfile.mkdtemp()
    subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, tmp], timeout=120)
    jfs = []
    for root, dirs, files in os.walk(tmp):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "target", ".venv")]
        for f in files:
            if f.endswith(".java") and "test" not in root.lower() and "Test" not in f:
                jfs.append(os.path.join(root, f))

    scanned = 0
    findings = 0
    cwes = {}
    start = time.time()
    for jf in jfs[:200]:
        try:
            r = scan_file(jf)
            for f in r.findings:
                if f.cwe:
                    cwes[f.cwe] = cwes.get(f.cwe, 0) + 1
            findings += len(r.findings)
            scanned += 1
        except Exception:
            pass

    t = time.time() - start
    rate = scanned / t if t > 0 else 0
    pf = findings / max(scanned, 1)
    print(f"{name}: {scanned}f {findings}findings {pf:.2f}/file {rate:.1f}f/s")
    total_f += scanned
    total_find += findings
    all_rates.append(rate)
    all_pfs.append(pf)

    subprocess.run(
        ["cmd", "/c", "rmdir", "/s", "/q", tmp], shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

avg_pf = total_find / max(total_f, 1)
avg_rate = sum(all_rates) / len(all_rates) if all_rates else 0
print(f"\n=== 10 NEW REPOS: {total_f} files, {total_find} findings, {avg_pf:.2f}/file, {avg_rate:.0f}f/s ===")

# Combine with prior 8
print(f"\n=== COMBINED (18 repos) ===")
print(f"Prior 8: 1301 files, 125 findings, 0.10/file")
print(f"New 10: {total_f} files, {total_find} findings, {avg_pf:.2f}/file")
print(f"ALL 18: {1301+total_f} files, {125+total_find} findings, {(125+total_find)/(1301+total_f):.2f}/file")
