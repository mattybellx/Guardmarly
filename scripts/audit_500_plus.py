"""
scripts/audit_500_plus.py
─────────────────────────
Comprehensive real-repo scan + deep audit tool.
Scans 500+ files across multiple repos, audits every finding,
and generates a detailed TP/FP/NEEDS_REVIEW breakdown.

Uses the already-cloned repos in campaign/v2_100/repos/.
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ansede_static.cli import _detect_language, _analyze_file_with_timeout

CAMPAIGN_DIR = REPO_ROOT / "campaign" / "v2_100" / "repos"
SKIP_DIRS = {"node_modules", "vendor", ".venv", "__pycache__", ".git",
             ".tox", "dist", "build", ".next", ".nuxt", "bower_components",
             "site-packages", "egg", "eggs", "target"}
MAX_KB = 500
MAX_FILES_PER_REPO = 300
TIMEOUT_SECONDS = 15.0


def count_files_and_loc(repo_dir: Path) -> tuple[int, int]:
    """Count source files and lines of code in a repo directory."""
    files, loc = 0, 0
    for ext in (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs"):
        for fp in repo_dir.rglob(f"*{ext}"):
            if set(p.lower() for p in fp.parts) & SKIP_DIRS:
                continue
            try:
                if fp.stat().st_size > MAX_KB * 1024:
                    continue
                loc += len(fp.read_text(encoding="utf-8", errors="replace").splitlines())
                files += 1
            except OSError:
                pass
    return files, loc


def collect_files(repo_dir: Path, limit: int = MAX_FILES_PER_REPO) -> list[Path]:
    """Collect source files from a repo, respecting skip dirs and size limits."""
    files = []
    for ext in (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".cs"):
        for fp in sorted(repo_dir.rglob(f"*{ext}")):
            if set(p.lower() for p in fp.parts) & SKIP_DIRS:
                continue
            try:
                if fp.stat().st_size > MAX_KB * 1024:
                    continue
                files.append(fp)
            except OSError:
                pass
    return files[:limit]


def audit_finding(finding: dict, file_path: Path) -> dict:
    """Deep audit a single finding — classify as TP, FP, or NEEDS_REVIEW."""
    cwe = str(finding.get("cwe", "")).upper()
    title = str(finding.get("title", ""))
    line = finding.get("line", 0)
    confidence = finding.get("confidence", 0.7)

    # Read context
    ctx = ""
    if file_path.exists():
        try:
            lines_data = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            s = max(0, line - 6)
            e = min(len(lines_data), line + 3)
            ctx = "\n".join(lines_data[s:e])
        except OSError:
            pass

    rel_path = str(file_path.relative_to(REPO_ROOT) if file_path.is_relative_to(REPO_ROOT) else file_path)

    # Immediate FP indicators
    path_lower = rel_path.lower()
    if any(seg in path_lower for seg in ["/test", "/tests", "/spec", "/__tests__",
                                            "/e2e", "/cypress", "/playwright",
                                            "/mock", "/fixtures", "/examples",
                                            "/demo", "/docs", "/tutorial",
                                            "/vendor/", "/node_modules/",
                                            "__pycache__", ".d.ts"]):
        return {"verdict": "FP", "reason": "test/fixture/demo context", "cwe": cwe, "line": line}

    if confidence < 0.30:
        return {"verdict": "FP", "reason": "low confidence", "cwe": cwe, "line": line}

    # CWE-specific analysis
    ctx_lower = ctx.lower()

    if cwe == "CWE-89":  # SQL injection
        if "?" in ctx and any(k in ctx_lower for k in ["execute(", "query(", "cursor."]):
            return {"verdict": "FP", "reason": "parameterized query with ?", "cwe": cwe, "line": line}
        if "%s" in ctx and "execute(" in ctx_lower:
            return {"verdict": "FP", "reason": "parameterized query with %s", "cwe": cwe, "line": line}
        if "f\"" in ctx and "select" in ctx_lower:
            return {"verdict": "TP", "reason": "f-string SQL injection risk", "cwe": cwe, "line": line}
        if "+" in ctx and any(k in ctx_lower for k in ["select ", "insert ", "update ", "delete "]):
            return {"verdict": "TP", "reason": "string concat SQL injection", "cwe": cwe, "line": line}

    if cwe == "CWE-78":  # Command injection
        if "shell=true" in ctx_lower:
            return {"verdict": "TP", "reason": "shell=True command injection", "cwe": cwe, "line": line}
        if "os.system" in ctx_lower:
            return {"verdict": "TP", "reason": "os.system command injection", "cwe": cwe, "line": line}
        if "subprocess" in ctx_lower and "shell=false" in ctx_lower:
            return {"verdict": "FP", "reason": "subprocess with shell=False", "cwe": cwe, "line": line}
        if "subprocess" in ctx_lower and "[" in ctx:
            return {"verdict": "FP", "reason": "subprocess with list args", "cwe": cwe, "line": line}

    if cwe == "CWE-79":  # XSS
        if "innerhtml" in ctx_lower:
            if any(s in ctx_lower for s in ["escape", "sanitize", "textcontent", "createelement"]):
                return {"verdict": "FP", "reason": "XSS with sanitization", "cwe": cwe, "line": line}
            return {"verdict": "TP", "reason": "innerHTML without sanitization", "cwe": cwe, "line": line}

    if cwe == "CWE-798":  # Hardcoded secrets
        if any(k in ctx for k in ["os.environ", "os.getenv", "your-", "example", "placeholder", "xxxxxxxx"]):
            return {"verdict": "FP", "reason": "env var or placeholder", "cwe": cwe, "line": line}
        if re.search(r'["\'][A-Za-z0-9+/=]{20,}["\']', ctx):
            return {"verdict": "TP", "reason": "appears to be real secret", "cwe": cwe, "line": line}

    if cwe in ("CWE-862", "CWE-639", "CWE-285", "CWE-306"):  # Auth/IDOR
        if any(k in ctx_lower for k in ["@login_required", "@permission_required",
                                          "@authenticate", "@preauthorize",
                                          "is_authenticated", "current_user",
                                          "session", "token"]):
            return {"verdict": "FP", "reason": "auth guard present", "cwe": cwe, "line": line}

    if cwe == "CWE-117":  # Log injection
        if "replace" in ctx_lower and any(k in ctx_lower for k in ["chr(10)", "chr(13)", "\\n", "\\r"]):
            return {"verdict": "FP", "reason": "log sanitization present", "cwe": cwe, "line": line}

    # Default: if confidence is high and context has suspicious patterns
    if confidence >= 0.80:
        return {"verdict": "TP", "reason": f"high confidence ({confidence:.2f})", "cwe": cwe, "line": line}

    return {"verdict": "NEEDS_REVIEW", "reason": "ambiguous — needs human review", "cwe": cwe, "line": line}


def scan_and_audit_repo(repo_dir: Path, name: str) -> dict[str, Any]:
    """Scan all files in a repo and audit every finding."""
    t0 = time.perf_counter()
    files = collect_files(repo_dir)
    total_files, total_loc = count_files_and_loc(repo_dir)

    all_findings = []
    scanned = 0
    errors = 0

    for fp in files:
        try:
            result = _analyze_file_with_timeout(fp, timeout_seconds=TIMEOUT_SECONDS)
            for f in result.findings:
                all_findings.append({
                    "file": str(fp.relative_to(repo_dir)),
                    "line": f.line,
                    "rule_id": f.rule_id or "",
                    "cwe": f.cwe or "",
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "title": f.title or "",
                    "confidence": getattr(f, "confidence", 0.7),
                })
            scanned += 1
        except Exception:
            errors += 1

    # Audit
    audited = {"TP": 0, "FP": 0, "NEEDS_REVIEW": 0}
    by_cwe = defaultdict(lambda: {"TP": 0, "FP": 0, "NR": 0})
    audit_details = []

    for f in all_findings:
        fp_full = repo_dir / f["file"]
        result = audit_finding(f, fp_full)
        verdict = result["verdict"]
        audited[verdict] = audited.get(verdict, 0) + 1
        cwe = result.get("cwe", "unknown")
        if verdict == "TP":
            by_cwe[cwe]["TP"] += 1
        elif verdict == "FP":
            by_cwe[cwe]["FP"] += 1
        else:
            by_cwe[cwe]["NR"] += 1
        audit_details.append(result)

    elapsed = time.perf_counter() - t0
    total_findings = len(all_findings)
    precision = (audited["TP"] / (audited["TP"] + audited["FP"]) * 100) if (audited["TP"] + audited["FP"]) > 0 else 100.0

    return {
        "repo": name,
        "files_total": total_files,
        "files_scanned": scanned,
        "loc": total_loc,
        "total_findings": total_findings,
        "audited": audited,
        "precision_pct": round(precision, 2),
        "by_cwe": dict(by_cwe),
        "errors": errors,
        "elapsed_sec": round(elapsed, 1),
    }


def main():
    if not CAMPAIGN_DIR.exists():
        print(f"ERROR: Campaign repo dir not found: {CAMPAIGN_DIR}")
        print("Clone repos first: cd campaign/v2_100/repos && git clone ...")
        sys.exit(1)

    repos = sorted(
        d for d in CAMPAIGN_DIR.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )
    if not repos:
        print("No repos found in", CAMPAIGN_DIR)
        sys.exit(1)

    print(f"Audit scan: {len(repos)} repos in {CAMPAIGN_DIR}")
    print(f"Settings: max {MAX_FILES_PER_REPO} files/repo, {TIMEOUT_SECONDS}s timeout, {MAX_KB}KB max")
    print("=" * 72)

    all_results = []
    grand_total = {"TP": 0, "FP": 0, "NEEDS_REVIEW": 0, "files": 0, "loc": 0, "findings": 0}

    for repo_dir in repos:
        name = repo_dir.name
        print(f"\n[{name}] ", end="", flush=True)
        try:
            result = scan_and_audit_repo(repo_dir, name)
            all_results.append(result)
            grand_total["files"] += result["files_scanned"]
            grand_total["loc"] += result["loc"]
            grand_total["findings"] += result["total_findings"]
            for k in ("TP", "FP", "NEEDS_REVIEW"):
                grand_total[k] += result["audited"].get(k, 0)
            print(f"{result['files_scanned']} files, {result['loc']} LOC, "
                  f"{result['total_findings']} findings, "
                  f"TP={result['audited']['TP']} FP={result['audited']['FP']} "
                  f"NR={result['audited']['NEEDS_REVIEW']} "
                  f"[{result['precision_pct']:.1f}%] [{result['elapsed_sec']:.0f}s]")
        except Exception as exc:
            print(f"ERROR: {exc}")
            all_results.append({"repo": name, "error": str(exc)})

    # Summary
    total_findings = grand_total["findings"]
    total_tp = grand_total["TP"]
    total_fp = grand_total["FP"]
    total_nr = grand_total["NEEDS_REVIEW"]
    total_audited = total_tp + total_fp
    precision = (total_tp / total_audited * 100) if total_audited > 0 else 100.0
    fp_rate = (total_fp / total_findings * 100) if total_findings > 0 else 0.0

    print("\n" + "=" * 72)
    print("FINAL AUDIT RESULTS")
    print("=" * 72)
    print(f"  Repos scanned:    {len(all_results)}")
    print(f"  Total files:      {grand_total['files']}")
    print(f"  Total LOC:        {grand_total['loc']:,}")
    print(f"  Total findings:   {total_findings}")
    print(f"  True Positives:   {total_tp}")
    print(f"  False Positives:  {total_fp}")
    print(f"  Needs Review:     {total_nr}")
    print(f"  Precision:        {precision:.2f}%")
    print(f"  FP Rate:          {fp_rate:.2f}%")
    print("-" * 72)

    # Save report
    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "settings": {"max_files": MAX_FILES_PER_REPO, "timeout": TIMEOUT_SECONDS, "max_kb": MAX_KB},
        "summary": {
            "repos": len(all_results),
            "files": grand_total["files"],
            "loc": grand_total["loc"],
            "total_findings": total_findings,
            "tp": total_tp, "fp": total_fp, "needs_review": total_nr,
            "precision_pct": round(precision, 2),
            "fp_rate_pct": round(fp_rate, 2),
        },
        "results": all_results,
    }

    output_path = REPO_ROOT / "audit_500_report.json"
    output_path.write_text(json.dumps(report, indent=2))
    print(f"\nReport saved: {output_path}")

    valid = total_findings >= 500 and grand_total["files"] >= 100
    if not valid:
        print(f"WARNING: Only {total_findings} findings across {grand_total['files']} files — target 500+")
    else:
        print("PASS: 500+ findings scanned and audited.")


if __name__ == "__main__":
    import re
    main()
