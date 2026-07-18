"""Batch scan multiple repos and collect honest metrics."""
import subprocess
import json
import os
import sys
from pathlib import Path

PYTHON = r"c:\Users\matth\OneDrive\Desktop\ansede-static-focus\.venv\Scripts\python.exe"
BASE = Path(os.environ["TEMP"]) / "ansede-scan-test"

TARGETS = {
    "requests": BASE / "requests" / "src",
    "flask": BASE / "flask" / "src" / "flask",
    "fastapi": BASE / "fastapi" / "fastapi",
    "click": BASE / "click" / "src" / "click",
}

results = {}
for name, path in TARGETS.items():
    if not path.exists():
        print(f"Skipping {name} — not found at {path}")
        continue
    outfile = BASE / f"ansede_{name}.json"
    
    # Count lines first
    loc = 0
    for f in path.rglob("*.py"):
        try:
            loc += len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            pass
    
    print(f"\n{'='*60}")
    print(f"Scanning {name} ({loc:,} LOC)...")
    sys.stdout.flush()
    
    cmd = [PYTHON, "-m", "ansede_static.cli", str(path), 
           "--format", "json", "--fail-on", "never", 
           "--output", str(outfile), "--no-triage"]
    subprocess.run(cmd, capture_output=True)
    
    try:
        data = json.loads(outfile.read_text())
        findings = sum(len(r.get("findings", [])) for r in data.get("results", []))
        files = len(data.get("results", []))
        
        # Count by severity
        sevs = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        cwes = {}
        for r in data.get("results", []):
            for f in r.get("findings", []):
                sev = f.get("severity", "info").lower()
                sevs[sev] = sevs.get(sev, 0) + 1
                cwe = f.get("cwe", "unknown")
                cwes[cwe] = cwes.get(cwe, 0) + 1
        
        findings_per_1kloc = (findings / loc * 1000) if loc > 0 else 0
        
        print(f"  {findings} findings across {files} files ({findings_per_1kloc:.1f}/1k LOC)")
        print(f"  Severity: {sevs}")
        if cwes:
            top_cwes = sorted(cwes.items(), key=lambda x: -x[1])[:5]
            print(f"  Top CWEs: {top_cwes}")
        
        results[name] = {
            "loc": loc, "files": files, "findings": findings,
            "per_1kloc": round(findings_per_1kloc, 1),
            "severity": sevs, "top_cwes": top_cwes[:3],
        }
    except Exception as e:
        print(f"  Error: {e}")

# Summary
print(f"\n{'='*60}")
print("SUMMARY")
print(f"{'='*60}")
total_loc = sum(r["loc"] for r in results.values())
total_findings = sum(r["findings"] for r in results.values())
total_files = sum(r["files"] for r in results.values())
print(f"Repos scanned: {len(results)}")
print(f"Total LOC: {total_loc:,}")
print(f"Total files: {total_files}")
print(f"Total findings: {total_findings}")
print(f"Overall rate: {total_findings/total_loc*1000:.1f} findings per 1,000 LOC")
print()

# Per-repo breakdown
for name, stats in results.items():
    print(f"  {name}: {stats['findings']} findings / {stats['loc']:,} LOC = {stats['per_1kloc']}/1k LOC")
    print(f"          severity: {stats['severity']}")
