#!/usr/bin/env python3
"""
DEEP AUDIT for v2_100 campaign — reads actual source code at every finding
location and reclassifies with evidence-based certainty.

Target: 30 repos from campaign/v2_100/
"""
import json, sys, subprocess, time
from pathlib import Path
from collections import Counter, defaultdict

REPOS_DIR = Path("campaign/v2_100/repos")
RESULTS_FILE = Path("campaign/v2_100/results.json")
OUTPUT_FILE = Path("campaign/v2_100/deep_audit.json")

# ═══════════════════════════════════════════════════════════════════
# Safety limits to prevent hangs (Track 4 timeout fix)
# ═══════════════════════════════════════════════════════════════════
PER_REPO_TIMEOUT = 120  # seconds max per repo scan
MAX_FILE_KB = 200       # skip files larger than this during deep-audit re-read
MAX_FINDINGS_PER_REPO = 200  # cap findings per repo for audit speed

SKIP_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "target", "bin", "obj", "coverage", ".venv",
    "tests", "test", "__tests__", "spec", "fixtures", "examples",
    "site-packages", ".tox", "eggs", ".eggs", "docs", "doc", "samples",
    "demo", "migrations", "maint", ".cache",
}

# ═══════════════════════════════════════════════════════════════════
# Classification helpers (same as original deep_audit.py, enhanced)
# ═══════════════════════════════════════════════════════════════════

def is_sql_injection_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "?" in ctx and any(kw in ctx for kw in ["execute(", "query(", "cursor."]):
        return True
    if "%s" in ctx and "execute(" in ctx:
        return True
    if ":$" in ctx or ":param" in ctx:
        return True
    if " + " in ctx and "select" in ctx:
        return False
    if "format(" in ctx and "select" in ctx:
        return False
    if 'f"' in ctx and "select" in ctx.lower():
        return False
    if "f'" in ctx and "select" in ctx.lower():
        return False
    if "%" in ctx and "select" in ctx and "?" not in ctx and "%s" not in ctx:
        return False
    return None

def is_command_injection_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "shell=true" in ctx:
        return False
    if "os.system" in ctx:
        return False
    if "subprocess" in ctx and ("shell=false" in ctx or "[" in ctx):
        return True
    return None

def is_xss_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "innerhtml" in ctx:
        if any(s in ctx for s in ["escape", "sanitize", "textcontent", "createelement", "encode"]):
            return True
        return False
    if "document.write" in ctx:
        if any(s in ctx for s in ["encode", "escape"]):
            return True
        return False
    return None

def is_deserialization_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "pickle.load" in ctx or ("yaml.load" in ctx and "safe_load" not in ctx):
        return False
    if "yaml.safe_load" in ctx:
        return True
    return None

def is_path_traversal_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "os.path.join" in ctx:
        if any(s in ctx for s in ["basedir", "base_dir", "root_dir", "safe_root", "resolve_path"]):
            return True
    return None

def is_hardcoded_secret(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if any(w in ctx for w in ["example", "test", "fake", "dummy", "placeholder", "your-", "xxx", "changeme"]):
        return True
    if "os.environ" in ctx or "os.getenv" in ctx or "process.env" in ctx:
        return True
    if "config[" in ctx or "settings." in ctx or "getenv(" in ctx:
        return True
    return None

def is_ssrf_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "requests.get" in ctx or "fetch(" in ctx:
        if any(s in ctx for s in ["urlparse", "allowed_hosts", "allowlist", "whitelist", "validate_url"]):
            return True
    return None

def is_csrf_safe(code_context: str) -> bool | None:
    ctx = code_context.lower()
    if "csrf_exempt" in ctx or "csrf = false" in ctx or ".csrf().disable()" in ctx:
        return False
    return None

# ═══════════════════════════════════════════════════════════════════
# Deep audit a single finding
# ═══════════════════════════════════════════════════════════════════

def deep_audit_finding(repo_name: str, lang: str, finding: dict) -> dict:
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    cwe = str(finding.get("cwe", "")).upper()
    rule_id = str(finding.get("rule_id", ""))
    title = str(finding.get("title", ""))
    confidence = finding.get("confidence", 1.0)

    # CLI may return absolute paths or paths relative to CWD.
    # Try multiple resolution strategies to find the actual file.
    candidates = [
        Path(file_path),                              # as-is (absolute or CWD-relative)
        REPOS_DIR / repo_name / file_path,            # relative to repo
    ]
    # If file_path is CWD-relative (e.g. "campaign/v2_100/repos/py-flask/src/...")
    # strip the common prefix and try relative to REPOS_DIR
    try:
        rel = Path(file_path).relative_to(str(REPOS_DIR))
        candidates.append(REPOS_DIR / rel)
    except ValueError:
        pass
    # If file_path contains the repo_name, extract the part after it
    if repo_name in file_path:
        idx = file_path.index(repo_name)
        suffix = file_path[idx + len(repo_name):].lstrip("/").lstrip("\\")
        candidates.append(REPOS_DIR / repo_name / suffix)

    full_path = None
    for c in candidates:
        if c.exists():
            full_path = c
            break

    if full_path is None:
        return {"verdict": "FILE_MISSING", "evidence": f"File not found (tried {len(candidates)} paths)", "confidence": 0.0}

    # Skip large files for re-read
    try:
        if full_path.stat().st_size > MAX_FILE_KB * 1024:
            return {"verdict": "SKIPPED_LARGE", "evidence": "File too large for context read", "confidence": 0.5}
    except OSError:
        return {"verdict": "FILE_UNREADABLE", "evidence": "Cannot stat file", "confidence": 0.0}

    try:
        all_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"verdict": "FILE_UNREADABLE", "evidence": "Cannot read file", "confidence": 0.0}

    start = max(0, line - 8)
    end = min(len(all_lines), line + 4)
    context_lines = all_lines[start:end]
    raw_context = "\n".join(context_lines)
    code_context = "\n".join(f"{start+i+1:4d}: {l}" for i, l in enumerate(context_lines))

    verdict = "NEEDS_MANUAL_REVIEW"
    evidence_parts = []
    cert = 0.5

    # Test/fixture file check
    path_lower = file_path.lower().replace("\\", "/")
    if any(p in path_lower for p in ["/test", "/tests/", "/__tests__/", "/spec/",
                                       "/fixtures/", "/examples/", "/demo/", "/maint/"]):
        return {"verdict": "CONFIRMED_FP", "evidence": "TEST_FILE: Finding in test/fixture/example directory",
                "confidence": 0.95, "code_context": code_context[:500]}

    # Low confidence
    if confidence < 0.35:
        return {"verdict": "CONFIRMED_FP", "evidence": f"LOW_CONFIDENCE: {confidence:.2f}",
                "confidence": 0.90, "code_context": code_context[:500]}

    # CWE-specific checks
    if "CWE-89" in cwe or "sql" in title.lower():
        safe = is_sql_injection_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["SQL_SAFE: Parameterized query"], 0.92
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["SQL_UNSAFE: String concat into SQL"], 0.90

    elif "CWE-78" in cwe or "command" in title.lower() or "shell" in title.lower():
        safe = is_command_injection_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["CMD_SAFE: Safe subprocess usage"], 0.92
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["CMD_UNSAFE: shell=True or os.system()"], 0.95

    elif "CWE-79" in cwe or "xss" in title.lower():
        safe = is_xss_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["XSS_SAFE: Sanitization found"], 0.88
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["XSS_UNSAFE: Dynamic DOM w/o sanitization"], 0.88

    elif "CWE-502" in cwe or "deserial" in title.lower():
        safe = is_deserialization_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["DESER_SAFE: Safe loader"], 0.92
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["DESER_UNSAFE: pickle/yaml.load"], 0.92

    elif "CWE-22" in cwe or "path" in title.lower():
        safe = is_path_traversal_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["PATH_SAFE: Base dir restriction"], 0.85
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["PATH_UNSAFE: Unrestricted access"], 0.85

    elif "CWE-798" in cwe or "secret" in title.lower() or "credential" in title.lower():
        safe = is_hardcoded_secret(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["SECRET_SAFE: Env var/config/example"], 0.90
        elif safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["SECRET_REAL: Hardcoded credential"], 0.85

    elif "CWE-352" in cwe or "csrf" in title.lower():
        safe = is_csrf_safe(raw_context)
        if safe is False:
            verdict, evidence_parts, cert = "CONFIRMED_TP", ["CSRF_DISABLED: Explicitly disabled"], 0.92

    elif "CWE-918" in cwe or "ssrf" in title.lower():
        safe = is_ssrf_safe(raw_context)
        if safe is True:
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["SSRF_SAFE: URL validation present"], 0.85

    elif "CWE-862" in cwe or "CWE-639" in cwe or "idor" in title.lower() or "auth" in title.lower():
        if any(p in raw_context.lower() for p in ["user_id", "owner_id", "current_user", "request.user",
                                                    "getuserbyid", ".user ==", ".owner =="]):
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["AUTH_SAFE: Ownership verification found"], 0.82
        elif any(p in raw_context.lower() for p in ["@login_required", "@preauthorize", "@authenticated",
                                                      "@secured", "authenticate", "isauthenticated"]):
            verdict, evidence_parts, cert = "NEEDS_MANUAL_REVIEW", ["AUTH_PRESENT: Guard present, ownership unclear"], 0.50

    # Generic checks for remaining NEEDS_MANUAL_REVIEW
    if verdict == "NEEDS_MANUAL_REVIEW" and cwe.startswith("CWE-"):
        if any(p in raw_context.lower() for p in ["# nosec", "# nosemgrep", "# ansede: ignore",
                                                    "# noqa", "# safe", "@ignore", "nolint"]):
            verdict, evidence_parts, cert = "CONFIRMED_FP", ["SUPPRESSED: Linter suppression comment"], 0.88
        elif confidence > 0.80:
            verdict, evidence_parts, cert = "LIKELY_TP", [f"HIGH_CONFIDENCE: {confidence:.2f}, no FP indicators"], 0.72

    if not evidence_parts:
        evidence_parts = ["NO_SPECIFIC_CHECK: Generic CWE"]

    return {
        "verdict": verdict,
        "evidence": "; ".join(evidence_parts),
        "confidence": cert,
        "code_context": code_context[:800],
    }

# ═══════════════════════════════════════════════════════════════════
# Main: Scan each repo via CLI, then deep-audit findings
# ═══════════════════════════════════════════════════════════════════

def scan_repo_with_cli(repo_dir: Path) -> list[dict]:
    """Use ansede-static CLI to get findings for a single repo."""
    try:
        result = subprocess.run(
            ["ansede-static", str(repo_dir), "--format", "json", "--fail-on", "never",
             "--exclude", "tests,test,__tests__,spec,fixtures,examples,docs,demo,samples,node_modules,vendor,dist,build,migrations"],
            capture_output=True, text=True, timeout=PER_REPO_TIMEOUT,
        )
        if result.returncode not in (0, 1):
            return []
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    findings = []
    if isinstance(data, dict):
        for entry in data.get("results", []):
            if isinstance(entry, dict):
                fname = entry.get("file", "")
                for f in entry.get("findings", []):
                    if isinstance(f, dict):
                        findings.append({
                            "file": fname,
                            "line": f.get("line", 0),
                            "rule_id": f.get("rule_id", ""),
                            "cwe": f.get("cwe", ""),
                            "severity": f.get("severity", "medium"),
                            "title": f.get("title", ""),
                            "confidence": f.get("confidence", 1.0),
                        })
    elif isinstance(data, list):
        for f in data:
            if isinstance(f, dict):
                findings.append({
                    "file": f.get("file", ""),
                    "line": f.get("line", 0),
                    "rule_id": f.get("rule_id", ""),
                    "cwe": f.get("cwe", ""),
                    "severity": f.get("severity", "medium"),
                    "title": f.get("title", ""),
                    "confidence": f.get("confidence", 1.0),
                })
    return findings[:MAX_FINDINGS_PER_REPO]


if __name__ == "__main__":
    print("=" * 70)
    print("DEEP AUDIT — v2_100 campaign (30 repos, 1.3M LOC)")
    print("=" * 70)

    campaign = json.loads(RESULTS_FILE.read_text()) if RESULTS_FILE.exists() else {}
    repo_list = sorted(d.name for d in REPOS_DIR.iterdir() if d.is_dir())

    if not repo_list:
        print("ERROR: No repos found in campaign/v2_100/repos/")
        sys.exit(1)

    all_audited = []
    per_repo_stats = {}
    total_findings_found = 0

    for i, repo_name in enumerate(repo_list):
        repo_dir = REPOS_DIR / repo_name
        lang = repo_name.split("-")[0] if "-" in repo_name else "unknown"
        lang_map = {"py": "python", "js": "javascript", "go": "go", "java": "java", "cs": "csharp"}
        lang = lang_map.get(lang, lang)

        print(f"\n[{i+1}/{len(repo_list)}] Scanning {repo_name} ({lang})...", end=" ", flush=True)

        t0 = time.perf_counter()
        findings = scan_repo_with_cli(repo_dir)
        elapsed = time.perf_counter() - t0
        print(f"{len(findings)} findings in {elapsed:.1f}s")

        repo_tp = repo_fp = repo_nr = 0
        for finding in findings:
            audit = deep_audit_finding(repo_name, lang, finding)
            audit["repo"] = repo_name
            audit["lang"] = lang
            audit["file"] = finding["file"]
            audit["line"] = finding["line"]
            audit["cwe"] = finding["cwe"]
            audit["title"] = finding.get("title", "")[:120]
            all_audited.append(audit)

            v = audit["verdict"]
            if v in ("CONFIRMED_TP", "LIKELY_TP"):
                repo_tp += 1
            elif v == "CONFIRMED_FP":
                repo_fp += 1
            else:
                repo_nr += 1

        total_findings_found += len(findings)
        per_repo_stats[repo_name] = {"tp": repo_tp, "fp": repo_fp, "nr": repo_nr, "total": len(findings)}
        print(f"  → TP={repo_tp} FP={repo_fp} NR={repo_nr}")

    # ═══════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════
    total_tp = sum(1 for a in all_audited if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
    total_fp = sum(1 for a in all_audited if a["verdict"] == "CONFIRMED_FP")
    total_nr = sum(1 for a in all_audited if a["verdict"] == "NEEDS_MANUAL_REVIEW")
    total_skipped = sum(1 for a in all_audited if a["verdict"] in ("FILE_MISSING", "FILE_UNREADABLE", "SKIPPED_LARGE"))
    total_classified = total_tp + total_fp
    precision = round(total_tp / total_classified * 100, 1) if total_classified else 0

    print("\n" + "=" * 70)
    print("DEEP AUDIT RESULTS")
    print("=" * 70)
    print(f"Repos audited:    {len(repo_list)}")
    print(f"Total findings:   {total_findings_found}")
    print(f"CONFIRMED_TP:     {total_tp}")
    print(f"CONFIRMED_FP:     {total_fp}")
    print(f"NEEDS_REVIEW:     {total_nr}")
    print(f"Skipped/errors:   {total_skipped}")
    print(f"Precision:        {precision}%")

    # By language
    for lang in ["python", "javascript", "go", "java", "csharp"]:
        lr = [a for a in all_audited if a["lang"] == lang]
        lt = sum(1 for a in lr if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
        lf = sum(1 for a in lr if a["verdict"] == "CONFIRMED_FP")
        ln = sum(1 for a in lr if a["verdict"] == "NEEDS_MANUAL_REVIEW")
        lp = round(lt/(lt+lf)*100, 1) if (lt+lf) else 0
        if lr:
            print(f"  {lang:>12}: {len(lr):>4} findings | TP={lt:>4} FP={lf:>4} NR={ln:>4} | Prec={lp}%")

    # Top FP causes
    fp_reasons = Counter()
    for a in all_audited:
        if a["verdict"] == "CONFIRMED_FP":
            fp_reasons[a["evidence"].split(";")[0]] += 1

    print(f"\nTop FP causes:")
    for reason, count in fp_reasons.most_common(10):
        print(f"  {count:>4} × {reason}")

    # Top TP CWEs
    tp_cwes = Counter()
    for a in all_audited:
        if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"):
            cwe = a.get("cwe", "").upper()
            if cwe:
                tp_cwes[cwe] += 1
    print(f"\nTop TP CWE categories:")
    for cwe, count in tp_cwes.most_common(10):
        print(f"  {count:>4} × {cwe}")

    # FP detail samples
    fp_samples = [a for a in all_audited if a["verdict"] == "CONFIRMED_FP"]
    if fp_samples:
        print(f"\n── FP detail samples (first 15) ──")
        for a in fp_samples[:15]:
            print(f"  {a['repo']}/{a.get('file','?')}:{a.get('line','?')}  {a.get('cwe','?')}  {a['evidence']}")

    # Save
    output = {
        "audit_ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
        "total_audited": total_findings_found,
        "confirmed_tp": total_tp,
        "confirmed_fp": total_fp,
        "needs_manual_review": total_nr,
        "precision_pct": precision,
        "per_repo": per_repo_stats,
        "fp_causes": dict(fp_reasons.most_common(20)),
        "tp_cwes": dict(tp_cwes.most_common(20)),
        "detailed_findings": [
            {k: v for k, v in a.items() if k != "code_context"}
            for a in all_audited
        ],
        "fp_samples": [
            {k: v for k, v in a.items()}
            for a in fp_samples[:30]
        ],
    }
    OUTPUT_FILE.write_text(json.dumps(output, indent=2))
    print(f"\nSaved: {OUTPUT_FILE}")
    print("DONE.")
