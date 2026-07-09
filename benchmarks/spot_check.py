"""spot_check.py — Audit actual findings from real repos for accuracy."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files
from ansede_static import scan_file

CHECKS = [
    ("js-axios", "campaign/v2_100/repos/js-axios", "javascript", 15),
    ("js-hono", "campaign/v2_100/repos/js-hono", "javascript", 15),
    ("js-react", "campaign/v2_100/repos/js-react", "javascript", 10),
    ("py-django", "campaign/v2_100/repos/py-django", "python", 10),
    ("py-fastapi", "campaign/v2_100/repos/py-fastapi", "python", 15),
    ("py-flask", "campaign/v2_100/repos/py-flask", "python", 10),
    ("py-httpx", "campaign/v2_100/repos/py-httpx", "python", 10),
]

BASE = Path(__file__).resolve().parent.parent

for name, repo_rel, lang, max_files in CHECKS:
    rd = BASE / repo_rel
    if not rd.exists():
        print(f"\n  {name}: SKIP (not found)")
        continue
    
    all_files = _collect_files([rd], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang][:max_files]
    
    print(f"\n{'='*65}")
    print(f"  {name} ({len(lang_files)} files)")
    print(f"{'='*65}")
    
    findings = []
    for fp in lang_files:
        try:
            r = scan_file(fp)
            for f in r.findings:
                findings.append((fp.name, f))
        except Exception as e:
            print(f"  CRASH: {fp.name}: {e}")
    
    crit_high = [(fn, f) for fn, f in findings if str(f.severity.value) in ("critical", "high")]
    medium = [(fn, f) for fn, f in findings if str(f.severity.value) == "medium"]
    low = [(fn, f) for fn, f in findings if str(f.severity.value) == "low"]
    
    if crit_high:
        print(f"  HIGH/CRITICAL ({len(crit_high)}):")
        for fn, f in crit_high[:10]:
            cwe = f.cwe or "?"
            conf = f.confidence if f.confidence else 0
            trace = "trace" if f.trace and len(f.trace) > 0 else "no-trace"
            print(f"    [{f.severity.value.upper():8s}] {cwe:9s} [{f.analysis_kind or '?':20s}] conf={conf:.0%} {trace:8s} {fn}:{f.line} {f.title[:70]}")
    
    if medium:
        print(f"  MEDIUM ({len(medium)}):")
        for fn, f in medium[:5]:
            cwe = f.cwe or "?"
            print(f"    [MEDIUM]   {cwe:9s} [{f.analysis_kind or '?':20s}] {fn}:{f.line} {f.title[:70]}")
    
    if low:
        print(f"  LOW ({len(low)}):")
        for fn, f in low[:3]:
            cwe = f.cwe or "?"
            print(f"    [LOW]      {cwe:9s} [{f.analysis_kind or '?':20s}] {fn}:{f.line} {f.title[:70]}")
    
    if not findings:
        print(f"  CLEAN - 0 findings")
    
    print(f"  Total: {len(findings)} ({len(crit_high)} H+, {len(medium)} M, {len(low)} L)")
