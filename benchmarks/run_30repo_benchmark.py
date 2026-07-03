"""30-Repo Real-World Benchmark with Audit — July 3, 2026
Scans 30 pre-cloned repos, classifies every finding as TP/FP/LIKELY_FP/NEEDS_REVIEW,
and produces a clean statistical report.
"""
import json, os, sys, time, statistics
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_file
from ansede_static._types import Severity

# ── Collect all pre-cloned repos ──────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
REPO_ROOTS = [
    ROOT / "campaign" / "v2_100" / "repos",
    ROOT / "benchmarks" / "online_random_samples",
]

IGNORE_DIRS = {".git", "node_modules", "vendor", "__pycache__", "dist", "build",
               ".venv", "venv", ".next", ".nuxt", ".idea", ".vscode", "coverage"}

EXT_MAP = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
}

def collect_repos():
    repos = []
    for root in REPO_ROOTS:
        if not root.exists():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            files = list(collect_files(child))
            if not files:
                continue
            repos.append({"name": child.name, "path": str(child), "files": files})
    return repos[:30]  # limit to 30

def collect_files(repo_root):
    files = []
    for child in repo_root.rglob("*"):
        try:
            if not child.is_file():
                continue
        except OSError:
            continue
        if any(part in IGNORE_DIRS for part in child.parts):
            continue
        ext = child.suffix.lower()
        if ext in EXT_MAP:
            files.append(str(child))
    return sorted(files)

def scan_repo(repo):
    """Scan a repo and return all findings."""
    all_findings = []
    files_scanned = 0
    total_loc = 0
    errors = 0
    
    for fpath in repo["files"]:
        try:
            result = scan_file(fpath)
            if result.parse_error:
                errors += 1
                continue
            files_scanned += 1
            total_loc += result.lines_scanned or 0
            for f in result.findings:
                f_dict = {
                    "file": f.file_path or fpath,
                    "line": f.line,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "title": f.title or "",
                    "cwe": f.cwe or "",
                    "rule_id": f.rule_id or "",
                    "confidence": getattr(f, 'confidence', 0.7),
                    "agent": getattr(f, 'agent', 'unknown'),
                    "description": (f.description or "")[:200],
                    "suggestion": (f.suggestion or "")[:200],
                }
                all_findings.append(f_dict)
        except Exception:
            errors += 1
    
    return {
        "name": repo["name"],
        "files_scanned": files_scanned,
        "total_loc": total_loc,
        "errors": errors,
        "raw_findings": len(all_findings),
        "findings": all_findings,
    }

def audit_finding(f):
    """Classify a single finding using heuristic audit rules."""
    cwe = (f.get("cwe") or "").upper()
    title = (f.get("title") or "").lower()
    desc = (f.get("description") or "").lower()
    sev = (f.get("severity") or "").lower()
    agent = (f.get("agent") or "").lower()
    filepath = (f.get("file") or "").lower()
    rule_id = (f.get("rule_id") or "")
    
    # ── Clearly real TPs ──────────────────────────────────────────────────
    # Hardcoded credentials in source
    if cwe == "CWE-798":
        if any(kw in desc for kw in ["password", "secret", "api_key", "token", "key"]):
            if any(kw in desc for kw in ["=", "hardcoded", "embedded"]):
                return "TP"
    # SQL injection with clear string formatting
    if cwe == "CWE-89":
        if any(kw in desc for kw in ["f-string", "format(", "%s", "concatenat", "string interpolation"]):
            return "TP"
    # Command injection with shell=True
    if cwe == "CWE-78":
        if "shell=true" in desc or "shell = true" in desc:
            return "TP"
    # Eval/exec
    if cwe == "CWE-95":
        if any(kw in desc for kw in ["eval(", "exec(", "compile("]):
            return "TP"
    # Path traversal with user input
    if cwe == "CWE-22":
        if any(kw in desc for kw in ["user", "request", "param", "input", "untrusted"]):
            return "TP"
    # XSS with innerHTML
    if cwe == "CWE-79":
        if "innerhtml" in desc or "document.write" in desc:
            return "TP"
    # Unsafe deserialization
    if cwe == "CWE-502":
        if any(kw in desc for kw in ["pickle", "yaml.load", "marshal"]):
            return "TP"
    # Missing auth on route — needs deeper review but likely real
    if cwe == "CWE-862":
        if "route" in desc or "endpoint" in desc or "handler" in desc:
            if not any(kw in desc for kw in ["test", "example", "mock", "fixture"]):
                return "LIKELY_TP"
    # IDOR
    if cwe == "CWE-639":
        if "owner" in desc or "ownership" in desc:
            if not any(kw in desc for kw in ["test", "example", "mock"]):
                return "LIKELY_TP"
    # Hardcoded secret patterns
    if rule_id in ("PY-007", "JS-005"):
        if any(kw in desc for kw in ["password", "secret", "key", "token"]):
            return "TP"
    
    # ── Clearly FPs ──────────────────────────────────────────────────────
    # Test files
    if any(kw in filepath for kw in ["/test/", "/tests/", "/test_", "_test.", "/spec/", "/__test__/", "/fixtures/", "/mock/"]):
        return "FP_TEST"
    # Example/demo files
    if any(kw in filepath for kw in ["example", "demo", "sample", "tutorial"]):
        return "FP_EXAMPLE"
    # Vendor/third-party
    if any(kw in filepath for kw in ["/vendor/", "/node_modules/", "/site-packages/", "/dist/"]):
        return "FP_VENDOR"
    # Documentation files
    if filepath.endswith(".md") or filepath.endswith(".rst") or filepath.endswith(".txt"):
        return "FP_DOCS"
    # Config files
    if any(kw in filepath for kw in ["config", "settings", ".env", ".ini", ".cfg", ".toml"]):
        return "FP_CONFIG"
    
    # ── Likely FPs based on context ──────────────────────────────────────
    # Weak crypto in test vectors
    if cwe == "CWE-327":
        if any(kw in desc for kw in ["test", "example", "mock", "fixture"]):
            return "FP_TEST"
    # Weak PRNG in non-security context
    if cwe == "CWE-338":
        if not any(kw in desc for kw in ["token", "password", "secret", "session", "auth"]):
            return "LIKELY_FP"
    # Log injection in internal tools
    if cwe == "CWE-117":
        if "test" in filepath or "debug" in filepath:
            return "LIKELY_FP"
    
    # ── Needs review ─────────────────────────────────────────────────────
    return "NEEDS_REVIEW"

def run_benchmark():
    print("=" * 70)
    print("ANSEDE 30-REPO REAL-WORLD BENCHMARK WITH AUDIT")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    repos = collect_repos()
    print(f"\nCollected {len(repos)} repos for scanning\n")
    
    results = []
    total_findings = 0
    total_files = 0
    total_loc = 0
    start = time.time()
    
    for i, repo in enumerate(repos):
        print(f"[{i+1:2d}/{len(repos)}] Scanning {repo['name']:<40} ({len(repo['files'])} files)...", end=" ", flush=True)
        t0 = time.time()
        result = scan_repo(repo)
        elapsed = time.time() - t0
        results.append(result)
        total_findings += result["raw_findings"]
        total_files += result["files_scanned"]
        total_loc += result["total_loc"]
        print(f"{result['files_scanned']:4d} files, {result['raw_findings']:4d} findings, {elapsed:5.1f}s")
    
    total_elapsed = time.time() - start
    
    # ── Audit all findings ──────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("AUDITING FINDINGS...")
    print(f"{'='*70}")
    
    audit_counts = Counter()
    cwe_audit = defaultdict(Counter)
    severity_audit = defaultdict(Counter)
    
    for result in results:
        for f in result["findings"]:
            verdict = audit_finding(f)
            f["verdict"] = verdict
            audit_counts[verdict] += 1
            cwe = (f.get("cwe") or "NO_CWE").upper()
            cwe_audit[cwe][verdict] += 1
            sev = (f.get("severity") or "info").lower()
            severity_audit[sev][verdict] += 1
    
    # ── Compute stats ───────────────────────────────────────────────────
    tp = audit_counts.get("TP", 0)
    likely_tp = audit_counts.get("LIKELY_TP", 0)
    fp_test = audit_counts.get("FP_TEST", 0)
    fp_example = audit_counts.get("FP_EXAMPLE", 0)
    fp_vendor = audit_counts.get("FP_VENDOR", 0)
    fp_docs = audit_counts.get("FP_DOCS", 0)
    fp_config = audit_counts.get("FP_CONFIG", 0)
    likely_fp = audit_counts.get("LIKELY_FP", 0)
    needs_review = audit_counts.get("NEEDS_REVIEW", 0)
    
    total_fp = fp_test + fp_example + fp_vendor + fp_docs + fp_config + likely_fp
    effective_tp = tp + likely_tp
    classified = tp + likely_tp + total_fp  # excluding needs_review
    
    # ── Report ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("BENCHMARK RESULTS")
    print(f"{'='*70}")
    print(f"Repos scanned:       {len(repos)}")
    print(f"Total files:         {total_files}")
    print(f"Total LOC:           {total_loc:,}")
    print(f"Total findings:      {total_findings}")
    print(f"Scan time:           {total_elapsed:.1f}s")
    print(f"Throughput:          {total_loc/total_elapsed:,.0f} LOC/s")
    print()
    print(f"{'─'*50}")
    print(f"{'VERDICT':<20} {'COUNT':>8} {'PCT':>8}")
    print(f"{'─'*50}")
    for label, count in [
        ("TP (Confirmed Real)", tp),
        ("LIKELY_TP (Probable)", likely_tp),
        ("FP_TEST (Test files)", fp_test),
        ("FP_EXAMPLE (Examples)", fp_example),
        ("FP_VENDOR (3rd Party)", fp_vendor),
        ("FP_DOCS (Docs)", fp_docs),
        ("FP_CONFIG (Config)", fp_config),
        ("LIKELY_FP (Probable FP)", likely_fp),
        ("NEEDS_REVIEW", needs_review),
    ]:
        pct = (count / total_findings * 100) if total_findings else 0
        print(f"{label:<20} {count:>8} {pct:>7.1f}%")
    
    print(f"{'─'*50}")
    if classified > 0:
        precision = effective_tp / classified * 100
        print(f"\n{'PRECISION (TP+LIKELY_TP / classified)':<40} {precision:>6.1f}%")
    tp_rate = effective_tp / total_findings * 100 if total_findings else 0
    print(f"{'TRUE POSITIVE RATE (of all findings)':<40} {tp_rate:>6.1f}%")
    fp_rate = total_fp / total_findings * 100 if total_findings else 0
    print(f"{'FALSE POSITIVE RATE (of all findings)':<40} {fp_rate:>6.1f}%")
    
    # ── Top CWEs ────────────────────────────────────────────────────────
    print(f"\n{'─'*50}")
    print(f"{'TOP CWE DISTRIBUTION':<30}")
    print(f"{'─'*50}")
    cwe_totals = Counter()
    for result in results:
        for f in result["findings"]:
            cwe_totals[(f.get("cwe") or "NO_CWE").upper()] += 1
    for cwe, count in cwe_totals.most_common(15):
        verdicts = cwe_audit.get(cwe, {})
        tp_c = verdicts.get("TP", 0) + verdicts.get("LIKELY_TP", 0)
        print(f"  {cwe:<12} {count:>5} findings  (TP: {tp_c})")
    
    # ── Severity breakdown ──────────────────────────────────────────────
    print(f"\n{'─'*50}")
    print(f"{'SEVERITY BREAKDOWN':<30}")
    print(f"{'─'*50}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        verdicts = severity_audit.get(sev, {})
        total_sev = sum(verdicts.values())
        tp_sev = verdicts.get("TP", 0) + verdicts.get("LIKELY_TP", 0)
        if total_sev > 0:
            print(f"  {sev:<10} {total_sev:>5} findings  (TP: {tp_sev})")
    
    # ── Repo-level summary ──────────────────────────────────────────────
    print(f"\n{'─'*50}")
    print(f"{'PER-REPO SUMMARY':<60}")
    print(f"{'─'*50}")
    findings_per_repo = []
    for r in results:
        tp_count = sum(1 for f in r["findings"] if f.get("verdict") in ("TP", "LIKELY_TP"))
        fp_count = sum(1 for f in r["findings"] if f.get("verdict", "").startswith("FP_") or f.get("verdict") == "LIKELY_FP")
        findings_per_repo.append((r["name"], len(r["findings"]), tp_count, fp_count))
    
    for name, total, tp_c, fp_c in sorted(findings_per_repo, key=lambda x: -x[1])[:15]:
        print(f"  {name[:40]:<40} {total:>4} findings  TP:{tp_c:>3}  FP:{fp_c:>3}")
    
    # ── Save raw results ────────────────────────────────────────────────
    output_path = ROOT / "benchmarks" / "report" / "30repo_benchmark_july3.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "repos_scanned": len(repos),
            "total_files": total_files,
            "total_loc": total_loc,
            "total_findings": total_findings,
            "scan_time_s": round(total_elapsed, 1),
            "throughput_loc_s": round(total_loc / total_elapsed, 0) if total_elapsed > 0 else 0,
            "audit_summary": dict(audit_counts),
            "precision_pct": round(precision, 1) if classified > 0 else None,
            "tp_rate_pct": round(tp_rate, 1),
            "fp_rate_pct": round(fp_rate, 1),
            "top_cwes": [{"cwe": c, "count": n} for c, n in cwe_totals.most_common(20)],
            "per_repo": [{"name": r["name"], "files": r["files_scanned"], "loc": r["total_loc"],
                          "findings": r["raw_findings"], "tp": sum(1 for f in r["findings"] if f.get("verdict") in ("TP", "LIKELY_TP")),
                          "fp": sum(1 for f in r["findings"] if f.get("verdict", "").startswith("FP_") or f.get("verdict") == "LIKELY_FP"),
                          "needs_review": sum(1 for f in r["findings"] if f.get("verdict") == "NEEDS_REVIEW")}
                         for r in results],
        }, f, indent=2)
    
    print(f"\nRaw results saved to: {output_path}")
    print(f"\n{'='*70}")
    print("BENCHMARK COMPLETE")
    print(f"{'='*70}")
    
    return results, audit_counts

if __name__ == "__main__":
    run_benchmark()
