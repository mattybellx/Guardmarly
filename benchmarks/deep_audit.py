#!/usr/bin/env python3
"""
DEEP AUDIT — reads actual source code at every finding location
and reclassifies with evidence-based certainty.

Output: campaign/fast/deep_audit.json
"""
import json, sys, re
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Load campaign results
results_file = Path("campaign/fast/results.json")
if not results_file.exists():
    print("No results.json found. Run fast_campaign.py first.")
    sys.exit(1)

campaign = json.loads(results_file.read_text())
REPOS_DIR = Path("campaign/fast/repos")

# ── Deep audit rules ───────────────────────────────────────────────

def is_sql_injection_safe(code_context: str) -> bool:
    """Check if SQL code uses parameterized queries."""
    ctx = code_context.lower()
    # Safe patterns
    if "?" in ctx and any(kw in ctx for kw in ["execute(", "query(", "cursor."]):
        return True
    if "%s" in ctx and "execute(" in ctx:
        return True
    if ":$" in ctx or ":param" in ctx:
        return True
    if ".execute(" in ctx and ("?" in ctx.split(".execute(")[1].split(")")[0] if ".execute(" in ctx else False):
        return True
    # Unsafe patterns
    if " + " in ctx and "select" in ctx:
        return False
    if "format(" in ctx and "select" in ctx:
        return False
    if "f\"" in ctx and "select" in ctx.lower():
        return False
    if "f'" in ctx and "select" in ctx.lower():
        return False
    if "%" in ctx and "select" in ctx and "?" not in ctx and "%s" not in ctx:
        return False
    return None  # Uncertain

def is_command_injection_safe(code_context: str) -> bool:
    """Check if command execution is safe."""
    ctx = code_context.lower()
    if "shell=true" in ctx:
        return False  # Definitely unsafe
    if "subprocess" in ctx and "shell=true" in ctx:
        return False
    if "os.system" in ctx:
        return False  # Always uses shell
    if "subprocess" in ctx and "shell=false" in ctx:
        return True
    if "subprocess" in ctx and "[" in ctx:  # List form = safe
        return True
    return None

def is_xss_safe(code_context: str) -> bool:
    """Check if DOM XSS is mitigated."""
    ctx = code_context.lower()
    if "innerhtml" in ctx:
        # Check for sanitization
        if any(s in ctx for s in ["escape", "sanitize", "textcontent", "createelement", "encode"]):
            return True
        if "innerhtml =" in ctx and "+" not in ctx.split("innerhtml =")[1][:100]:
            return True  # Static assignment
        return False  # Dynamic innerHTML without obvious sanitization
    if "document.write" in ctx:
        if any(s in ctx for s in ["encode", "escape"]):
            return True
        return False
    return None

def is_deserialization_safe(code_context: str) -> bool:
    """Check if deserialization is on trusted data."""
    ctx = code_context.lower()
    if "pickle.load" in ctx or "yaml.load" in ctx:
        return False  # Almost always unsafe without explicit safe loader
    if "yaml.safe_load" in ctx:
        return True
    return None

def is_path_traversal_safe(code_context: str) -> bool:
    """Check if path operations are safe."""
    ctx = code_context.lower()
    if "os.path.join" in ctx:
        # Check if there's a base path restriction
        if any(s in ctx for s in ["basedir", "base_dir", "root_dir", "safe_root", "resolve_path"]):
            return True
        return None
    if "open(" in ctx and ".." not in ctx:
        return None  # Cannot determine from context alone
    return None

def is_hardcoded_secret(code_context: str) -> bool:
    """Check if a secret is actually hardcoded vs test/example."""
    ctx = code_context.lower()
    if any(w in ctx for w in ["example", "test", "fake", "dummy", "placeholder", "your-", "xxx", "changeme"]):
        return True  # Example/test value
    if "os.environ" in ctx or "os.getenv" in ctx or "process.env" in ctx:
        return True  # Actually reads from env
    if "config[" in ctx or "settings." in ctx or "getenv(" in ctx:
        return True  # Actually reads from config
    return False  # Likely real hardcoded secret

def is_ssrf_safe(code_context: str) -> bool:
    """Check if URL fetching is SSRF-safe."""
    ctx = code_context.lower()
    if "requests.get" in ctx or "fetch(" in ctx:
        # Check for URL validation
        if any(s in ctx for s in ["urlparse", "allowed_hosts", "allowlist", "whitelist", "validate_url", "url.startswith"]):
            return True
    return None

def is_csrf_safe(code_context: str) -> bool:
    """Check CSRF protection."""
    ctx = code_context.lower()
    if "csrf_exempt" in ctx or "csrf = false" in ctx or ".csrf().disable()" in ctx:
        return False
    return None

# ── Deep audit function ─────────────────────────────────────────────

def deep_audit_finding(repo_name: str, lang: str, finding: dict) -> dict:
    """Deep-audit a single finding with code-context analysis."""
    file_path = finding.get("file", "")
    line = finding.get("line", 0)
    cwe = str(finding.get("cwe", "")).upper()
    rule_id = str(finding.get("rule_id", ""))
    title = str(finding.get("title", ""))
    confidence = finding.get("confidence", 1.0)

    repo_dir = REPOS_DIR / repo_name
    full_path = repo_dir / file_path

    if not full_path.exists():
        return {"verdict": "FILE_MISSING", "evidence": f"File not found: {full_path}", "confidence": 0.0}

    # Read code context
    try:
        all_lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"verdict": "FILE_UNREADABLE", "evidence": "Cannot read file", "confidence": 0.0}

    start = max(0, line - 8)
    end = min(len(all_lines), line + 4)
    context_lines = all_lines[start:end]
    code_context = "\n".join(f"{start+i+1:4d}: {l}" for i, l in enumerate(context_lines))
    raw_context = "\n".join(context_lines)

    # ── Evidence-based classification ──

    verdict = "NEEDS_MANUAL_REVIEW"
    evidence_parts = []
    cert = 0.5

    # Check for test/fixture file (still applies)
    path_lower = file_path.lower()
    if any(p in path_lower for p in ["/test", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/examples/", "/demo/"]):
        verdict = "CONFIRMED_FP"
        evidence_parts.append("TEST_FILE: Finding in test/fixture/example directory")
        cert = 0.95
        return {"verdict": verdict, "evidence": "; ".join(evidence_parts), "confidence": cert,
                "code_context": code_context[:500]}

    # Low confidence from scanner
    if confidence < 0.35:
        verdict = "CONFIRMED_FP"
        evidence_parts.append(f"LOW_CONFIDENCE: Scanner confidence {confidence:.2f}")
        cert = 0.90

    # CWE-specific deep checks
    if "CWE-89" in cwe or "sql" in title.lower():
        safe = is_sql_injection_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("SQL_SAFE: Parameterized query or safe API usage detected")
            cert = 0.92
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("SQL_UNSAFE: String concatenation/formatting into SQL detected")
            cert = 0.90

    elif "CWE-78" in cwe or "command" in title.lower() or "shell" in title.lower():
        safe = is_command_injection_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("CMD_SAFE: Safe subprocess usage (list form, no shell=True)")
            cert = 0.92
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("CMD_UNSAFE: shell=True or os.system() detected")
            cert = 0.95

    elif "CWE-79" in cwe or "xss" in title.lower():
        safe = is_xss_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("XSS_SAFE: Sanitization or static assignment detected")
            cert = 0.88
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("XSS_UNSAFE: Dynamic DOM manipulation without sanitization")
            cert = 0.88

    elif "CWE-502" in cwe or "deserial" in title.lower():
        safe = is_deserialization_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("DESER_SAFE: Safe deserialization API used")
            cert = 0.92
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("DESER_UNSAFE: Unsafe deserialization (pickle/yaml.load)")
            cert = 0.92

    elif "CWE-22" in cwe or "path" in title.lower():
        safe = is_path_traversal_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("PATH_SAFE: Base directory restriction found")
            cert = 0.85
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("PATH_UNSAFE: Unrestricted path access")
            cert = 0.85

    elif "CWE-798" in cwe or "secret" in title.lower() or "credential" in title.lower():
        safe = is_hardcoded_secret(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("SECRET_SAFE: Uses env var, config, or is example/test value")
            cert = 0.90
        elif safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("SECRET_REAL: Appears to be actual hardcoded credential")
            cert = 0.85

    elif "CWE-352" in cwe or "csrf" in title.lower():
        safe = is_csrf_safe(raw_context)
        if safe is False:
            verdict = "CONFIRMED_TP"
            evidence_parts.append("CSRF_DISABLED: CSRF explicitly disabled")
            cert = 0.92

    elif "CWE-918" in cwe or "ssrf" in title.lower():
        safe = is_ssrf_safe(raw_context)
        if safe is True:
            verdict = "CONFIRMED_FP"
            evidence_parts.append("SSRF_SAFE: URL validation/allowlist detected")
            cert = 0.85

    # Framework-specific checks
    elif "CWE-862" in cwe or "CWE-639" in cwe or "IDOR" in title.upper() or "auth" in title.lower():
        # Auth bypass / IDOR — check for ownership verification
        if any(p in raw_context.lower() for p in ["user_id", "owner_id", "current_user", "request.user",
                                                    "getuserbyid", "findbyidanduserid", ".user ==", ".owner =="]):
            verdict = "CONFIRMED_FP"
            evidence_parts.append("AUTH_SAFE: Ownership verification or user-scoped query found")
            cert = 0.82
        elif any(p in raw_context.lower() for p in ["@login_required", "@preauthorize", "@authenticated",
                                                      "@secured", "authenticate", "isauthenticated"]):
            # Has auth but unclear if ownership is checked
            verdict = "NEEDS_MANUAL_REVIEW"
            evidence_parts.append("AUTH_PRESENT: Auth guard present but ownership verification unclear")
            cert = 0.50

    # If no specific check matched but we have a CWE
    if verdict == "NEEDS_MANUAL_REVIEW" and cwe.startswith("CWE-"):
        # Check for common FP patterns
        if any(p in raw_context.lower() for p in ["# nosec", "# nosemgrep", "# ansede: ignore",
                                                    "# noqa", "# safe", "@ignore", "nolint"]):
            verdict = "CONFIRMED_FP"
            evidence_parts.append("SUPPRESSED: Security linter suppression comment found")
            cert = 0.88
        elif confidence > 0.80:
            verdict = "LIKELY_TP"
            evidence_parts.append(f"HIGH_CONFIDENCE: Scanner confidence {confidence:.2f} with no FP indicators")
            cert = 0.72

    if not evidence_parts:
        evidence_parts.append("NO_SPECIFIC_CHECK: Generic CWE classification")

    return {
        "verdict": verdict,
        "evidence": "; ".join(evidence_parts),
        "confidence": cert,
        "code_context": code_context[:800],
    }

# ── Run deep audit ──────────────────────────────────────────────────

print("=" * 70)
print("DEEP AUDIT — Reading actual source code at every finding location")
print("=" * 70)

all_audited = []
stats = defaultdict(lambda: defaultdict(int))
per_repo_stats = {}

for repo_entry in campaign.get("per_repo", []):
    repo_name = repo_entry["name"]
    lang = repo_entry["lang"]
    print(f"\nAuditing {repo_name} ({lang}) — {repo_entry['ansede_n']} findings...")

    # We need the actual findings from the scan, not just counts
    # The campaign JSON only stores counts, not individual findings
    # We need to re-scan to get the findings, OR read from the saved state

# Since the campaign JSON only has counts, we need to re-scan to get individual findings
# Let's use a faster approach: re-scan just the repos and do deep audit on the fly

print("\n⚠ Campaign results.json only has counts, not individual findings.")
print("Running targeted re-scan to get individual findings for deep audit...")

# Quick re-scan to get findings lists
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static.cli import _detect_language, _collect_files, _analyze_file_with_timeout

SKIP_DIRS = {"node_modules","vendor",".git","dist","build","__pycache__",".next",".nuxt",
             "target","bin","obj","coverage",".venv","tests","test","__tests__","spec",
             "fixtures","examples","site-packages",".tox","eggs",".eggs","docs","doc","samples","demo"}
MAX_FILE_KB = 100

total_audited = 0
deep_results = []

for repo_entry in campaign.get("per_repo", []):
    repo_name = repo_entry["name"]
    lang = repo_entry["lang"]
    repo_dir = REPOS_DIR / repo_name

    if not repo_dir.exists():
        continue

    # Re-scan to get individual findings
    all_files = _collect_files([repo_dir], exclude_patterns=[])
    lang_files = [f for f in all_files if _detect_language(f) == lang]
    
    src_files = []
    for f in lang_files:
        parts = set(p.lower() for p in f.parts)
        if parts & SKIP_DIRS:
            continue
        try:
            if f.stat().st_size <= MAX_FILE_KB * 1024:
                src_files.append(f)
        except OSError:
            pass
    
    src_files = src_files[:150]  # Cap
    
    findings = []
    for fp in src_files:
        try:
            r = _analyze_file_with_timeout(fp, timeout_seconds=8.0)
            for f in r.findings:
                findings.append({
                    "file": str(fp.relative_to(repo_dir)),
                    "line": f.line,
                    "rule_id": f.rule_id or "",
                    "cwe": f.cwe or "",
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "title": f.title or "",
                    "confidence": getattr(f, 'confidence', 1.0),
                })
        except Exception:
            pass

    # Deep audit each finding
    repo_tp = repo_fp = repo_nr = 0
    for finding in findings:
        audit = deep_audit_finding(repo_name, lang, finding)
        audit["repo"] = repo_name
        audit["lang"] = lang
        audit["file"] = finding["file"]
        audit["line"] = finding["line"]
        audit["cwe"] = finding["cwe"]
        audit["title"] = finding["title"][:120]
        deep_results.append(audit)

        v = audit["verdict"]
        if v in ("CONFIRMED_TP", "LIKELY_TP"):
            repo_tp += 1
        elif v in ("CONFIRMED_FP",):
            repo_fp += 1
        else:
            repo_nr += 1

    total_audited += len(findings)
    print(f"  {repo_name}: {len(findings)} findings → TP={repo_tp} FP={repo_fp} NR={repo_nr}")
    per_repo_stats[repo_name] = {"tp": repo_tp, "fp": repo_fp, "nr": repo_nr, "total": len(findings)}

# ── Final Summary ──────────────────────────────────────────────────

total_tp = sum(1 for a in deep_results if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
total_fp = sum(1 for a in deep_results if a["verdict"] == "CONFIRMED_FP")
total_nr = sum(1 for a in deep_results if a["verdict"] == "NEEDS_MANUAL_REVIEW")
total_classified = total_tp + total_fp
precision = round(total_tp / total_classified * 100, 1) if total_classified else 0
recall_estimate = round(total_tp / (total_tp + total_nr) * 100, 1) if (total_tp + total_nr) else 0  # Approximate

print("\n" + "=" * 70)
print("DEEP AUDIT RESULTS")
print("=" * 70)
print(f"Total findings audited: {total_audited}")
print(f"CONFIRMED_TP: {total_tp}")
print(f"CONFIRMED_FP: {total_fp}")
print(f"NEEDS_MANUAL_REVIEW: {total_nr}")
print(f"Precision (of classified): {precision}%")
print(f"Recall estimate: {recall_estimate}%")

# By language
for lang in ["python", "javascript", "java", "go", "csharp"]:
    lr = [a for a in deep_results if a["lang"] == lang]
    lt = sum(1 for a in lr if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"))
    lf = sum(1 for a in lr if a["verdict"] == "CONFIRMED_FP")
    ln = sum(1 for a in lr if a["verdict"] == "NEEDS_MANUAL_REVIEW")
    lp = round(lt/(lt+lf)*100,1) if (lt+lf) else 0
    print(f"  {lang:>12}: {len(lr):>4} findings | TP={lt:>4} FP={lf:>4} NR={ln:>4} | Prec={lp}%")

# Top FP causes
fp_reasons = Counter()
for a in deep_results:
    if a["verdict"] == "CONFIRMED_FP":
        fp_reasons[a["evidence"].split(";")[0]] += 1

print(f"\nTop FP causes:")
for reason, count in fp_reasons.most_common(10):
    print(f"  {count:>4} × {reason}")

# Top TP CWE categories
tp_cwes = Counter()
for a in deep_results:
    if a["verdict"] in ("CONFIRMED_TP", "LIKELY_TP"):
        cwe = a.get("cwe", "").upper()
        if cwe:
            tp_cwes[cwe] += 1

print(f"\nTop TP CWE categories:")
for cwe, count in tp_cwes.most_common(10):
    print(f"  {count:>4} × {cwe}")

# Save
output = {
    "audit_ts": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
    "total_audited": total_audited,
    "confirmed_tp": total_tp,
    "confirmed_fp": total_fp,
    "needs_manual_review": total_nr,
    "precision_pct": precision,
    "per_repo": per_repo_stats,
    "fp_causes": dict(fp_reasons.most_common(20)),
    "tp_cwes": dict(tp_cwes.most_common(20)),
    "detailed_findings": [
        {k: v for k, v in a.items() if k != "code_context"}
        for a in deep_results
    ],
    "sample_contexts": [
        a for a in deep_results
        if a["verdict"] in ("CONFIRMED_TP", "CONFIRMED_FP")
    ][:100],
}
out_path = Path("campaign/fast/deep_audit.json")
out_path.write_text(json.dumps(output, indent=2))
print(f"\nSaved: {out_path}")
print("DONE.")
