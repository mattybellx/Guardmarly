#!/usr/bin/env python
"""Semgrep head-to-head on 2 repos."""
import subprocess, tempfile, json

semgrep = r"C:\Users\matth\OneDrive\Desktop\X\.venv\Scripts\semgrep.exe"
repos = [
    ("https://github.com/apache/commons-collections.git", "commons-collections"),
    ("https://github.com/google/gson.git", "gson"),
    ("https://github.com/apache/commons-io.git", "commons-io"),
]

for url, name in repos:
    tmp = tempfile.mkdtemp()
    subprocess.run(["git", "clone", "--depth", "1", "--quiet", url, tmp], timeout=120)
    try:
        r = subprocess.run(
            [semgrep, "scan", "--config=auto", "--quiet", "--json", tmp],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(r.stdout) if r.stdout.strip() else {"results": []}
        print(f"Semgrep {name}: {len(data.get('results', []))} findings")
    except Exception as e:
        print(f"Semgrep {name}: ERROR {e}")
    subprocess.run(
        ["cmd", "/c", "rmdir", "/s", "/q", tmp], shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
