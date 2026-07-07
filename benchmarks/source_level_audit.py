"""
source_level_audit.py — Read actual source code for every finding and classify.
Produces a definitive TP/FP verdict for each finding by inspecting the code.
"""
import json, sys
from pathlib import Path

INPUT = Path(__file__).parent / "audit_results" / "round1_java.json"
CACHE = Path(r"C:\Users\matth\AppData\Local\Temp\ansede_java_audit")
data = json.loads(INPUT.read_text())

verdicts = {"TP": 0, "FP": 0, "LIKELY_FP": 0, "NEEDS_REVIEW": 0}
findings_detail = []

# Map repo name to cache dir
repo_dirs = {}
for d in CACHE.iterdir():
    if d.is_dir():
        repo_dirs[d.name] = d

def read_line(file_path_str, line_num):
    """Read a specific line from a file in the cached repo."""
    # file_path_str is relative, we need to find the absolute path
    for repo_name, repo_dir in repo_dirs.items():
        # Try matching the file path
        for java_file in repo_dir.rglob("*.java"):
            rel = str(java_file.relative_to(repo_dir))
            if rel.endswith(file_path_str.replace("\\", "/").split("/")[-1]):
                # Found matching filename — verify path suffix
                if file_path_str.replace("\\", "/") in str(java_file).replace("\\", "/"):
                    try:
                        lines = java_file.read_text(encoding="utf-8", errors="replace").splitlines()
                        if 1 <= line_num <= len(lines):
                            return lines[line_num - 1]
                    except:
                        pass
                    break
    return None

def audit_cwe117(finding, file_path):
    """CWE-117: Log injection. TP only if untrusted data flows into log call."""
    title = finding.get("title", "")
    desc = finding.get("description", "")
    line = finding.get("line", 0)

    # Read source
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"

    # FP patterns for log injection
    fp_patterns = [
        "log.debug(", "log.trace(", "log.info(", "logger.debug", "logger.trace",
        "logger.info(", "LOG.debug", "LOG.trace", "LOG.info",
        "System.out.println", "System.err.println",
    ]

    if src:
        src_lower = src.lower()
        # If it's just logging a static string or local variable (not request data)
        if any(p in src for p in fp_patterns):
            # Check if the logged value comes from user input
            has_user_input = any(kw in src_lower for kw in [
                "request.", "getparameter", "getquery", "getheader",
                "getcookie", "req.", "params.", "input", "user"
            ])
            if not has_user_input:
                return "FP", f"Logging internal/static data — no user input. {context}"

    return "LIKELY_FP", f"Log injection requires user-controlled data in log. {context}"

def audit_cwe330(finding, file_path):
    """CWE-330: Weak PRNG. TP only if Random used for security tokens/keys."""
    desc = finding.get("description", "")
    title = finding.get("title", "")
    line = finding.get("line", 0)
    fp_lower = file_path.lower()

    # Always FP in test files
    if "test" in fp_lower:
        return "FP", "Random in test code — not exploitable."

    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"

    # If it mentions "web handler" or "security" in the title, it might be TP
    if "web handler" in title.lower() or "token" in title.lower() or "session" in title.lower():
        return "NEEDS_REVIEW", f"Random in potential security context. {context}"

    # Math.random() is almost always FP — used for UI, animations, non-security
    if "math.random" in title.lower() or "math.random" in desc.lower():
        return "FP", f"Math.random() used for non-security (animation/UI/shuffling). {context}"

    return "LIKELY_FP", f"Random likely used for non-security purposes. {context}"

def audit_cwe89(finding, file_path):
    """CWE-89: SQL injection. TP only if query built with string concat."""
    line = finding.get("line", 0)
    fp_lower = file_path.lower()

    if "test" in fp_lower:
        return "FP", "SQLi in test code."

    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"

    if src:
        src_lower = src.lower()
        # Safe patterns
        if "preparedstatement" in src_lower or "?" in src and "execute" in src_lower:
            return "FP", f"Uses PreparedStatement (parameterized). {context}"
        # Unsafe patterns
        if "+" in src and ("select" in src_lower or "insert" in src_lower or "update" in src_lower):
            return "TP", f"SQL built via string concatenation — real SQLi risk. {context}"

    return "NEEDS_REVIEW", f"Need to verify if query uses concatenation. {context}"

def audit_cwe79(finding, file_path):
    """CWE-79: XSS. TP only if unescaped user data in HTML output."""
    fp_lower = file_path.lower()
    if "test" in fp_lower:
        return "FP", "XSS in test code."

    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    return "NEEDS_REVIEW", f"Need to verify if output is HTML-encoded. {context}"

def audit_cwe328(finding, file_path):
    """CWE-328: Weak hash. TP only if used for passwords/auth."""
    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    if src and ("password" in src.lower() or "token" in src.lower() or "auth" in src.lower()):
        return "TP", f"Weak hash used in auth context. {context}"
    return "LIKELY_FP", f"Weak hash likely used for non-security (checksums, IDs). {context}"

def audit_cwe327(finding, file_path):
    """CWE-327: Weak crypto. TP only if used for security-sensitive encryption."""
    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    return "NEEDS_REVIEW", f"Need to verify crypto purpose. {context}"

def audit_cwe22(finding, file_path):
    """CWE-22: Path traversal."""
    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    return "NEEDS_REVIEW", f"Need to verify if path is user-controlled. {context}"

def audit_cwe798(finding, file_path):
    """CWE-798: Hardcoded secret."""
    fp_lower = file_path.lower()
    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    if "test" in fp_lower or "example" in fp_lower or "sample" in fp_lower:
        return "FP", f"Credential in test/example code. {context}"
    if src:
        if any(kw in src.lower() for kw in ["todo", "placeholder", "changeme", "xxx", "fake"]):
            return "FP", f"Placeholder credential. {context}"
        if "password" in src.lower() and len(src) < 40:
            return "TP", f"Real hardcoded password detected. {context}"
    return "NEEDS_REVIEW", f"Need to verify if credential is real. {context}"

def audit_cwe1188(finding, file_path):
    """CWE-1188: Dangerous default."""
    line = finding.get("line", 0)
    src = read_line(file_path, line)
    context = f"source: {src[:120] if src else 'N/A'}"
    return "NEEDS_REVIEW", f"Need to verify default value risk. {context}"

AUDITORS = {
    "CWE-117": audit_cwe117,
    "CWE-330": audit_cwe330,
    "CWE-89": audit_cwe89,
    "CWE-79": audit_cwe79,
    "CWE-328": audit_cwe328,
    "CWE-327": audit_cwe327,
    "CWE-22": audit_cwe22,
    "CWE-798": audit_cwe798,
    "CWE-1188": audit_cwe1188,
}

print("=" * 90)
print("SOURCE-LEVEL DEEP AUDIT — Reading actual code for every finding")
print("=" * 90)

for repo in data["repos"]:
    name = repo["name"]
    fc = repo["findings_count"]
    if fc == 0:
        continue

    repo_dir = repo_dirs.get(name.replace("/", "__"))
    print(f"\n{'─'*90}")
    print(f"REPO: {name}  ({repo['stars']}*, {repo['loc']:,} LOC, {fc} findings)")

    for file_data in repo["files"]:
        fps = file_data.get("findings", [])
        if not fps:
            continue
        fp_rel = file_data["file_path"]
        print(f"\n  FILE: {fp_rel}  ({file_data['lines_scanned']} lines)")

        for i, f in enumerate(fps):
            rule = f.get("rule_id", "?")
            cwe = f.get("cwe", "?")
            sev = f.get("severity", "?")
            line = f.get("line", 0)
            title = f.get("title", "")[:120]

            auditor = AUDITORS.get(cwe)
            if auditor:
                verdict, reason = auditor(f, fp_rel)
            else:
                verdict, reason = "NEEDS_REVIEW", f"No auditor for {cwe}"

            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            findings_detail.append({
                "repo": name, "file": fp_rel, "line": line,
                "rule": rule, "cwe": cwe, "severity": sev,
                "title": title, "verdict": verdict, "reason": reason,
            })

            marker = {"TP": "✅", "FP": "❌", "LIKELY_FP": "⚠️", "NEEDS_REVIEW": "🔍"}[verdict]
            print(f"    [{i+1:3d}] {marker} {verdict:12s} | {rule:10s} | {cwe:10s} | L{line:4d} | {sev}")
            print(f"          {reason[:150]}")

# Summary
print(f"\n{'='*90}")
print(f"FINAL AUDIT SUMMARY")
print(f"{'='*90}")
total = sum(verdicts.values())
for v in ["TP", "LIKELY_FP", "FP", "NEEDS_REVIEW"]:
    c = verdicts.get(v, 0)
    pct = c / total * 100 if total else 0
    bar = "█" * int(pct / 2)
    print(f"  {v:15s}: {c:4d} ({pct:5.1f}%)  {bar}")

precision_denom = verdicts.get("TP", 0) + verdicts.get("LIKELY_FP", 0) + verdicts.get("FP", 0)
if precision_denom > 0:
    precision = verdicts.get("TP", 0) / precision_denom * 100
    print(f"\n  Estimated Precision: {precision:.1f}% (TP / (TP + LIKELY_FP + FP))")
    print(f"  (Excludes NEEDS_REVIEW — those need human inspection)")

# Top FP patterns
print(f"\n{'='*90}")
print(f"TOP FP PATTERNS TO FIX")
print(f"{'='*90}")
fp_by_cwe = {}
for fd in findings_detail:
    if fd["verdict"] in ("FP", "LIKELY_FP"):
        key = f"{fd['verdict']}:{fd['cwe']}"
        fp_by_cwe[key] = fp_by_cwe.get(key, 0) + 1
for key, count in sorted(fp_by_cwe.items(), key=lambda x: -x[1]):
    print(f"  {key:30s}: {count:4d}")

# Detection gaps
print(f"\n{'='*90}")
print(f"SILENT REPOS (potential detection gaps)")
print(f"{'='*90}")
for repo in data["repos"]:
    if repo["findings_count"] == 0:
        print(f"  {repo['name']:45s} | {repo['loc']:>8,} LOC | {repo['java_files']} files")
        print(f"    → CHECK: Does this repo have web routes, SQL, or auth we missed?")

# Save detailed audit
output = Path(__file__).parent / "audit_results" / "round1_java_audited.json"
output.write_text(json.dumps({
    "summary": {
        "total": total,
        "verdicts": verdicts,
        "precision_estimate": round(precision, 1) if precision_denom > 0 else None,
    },
    "findings": findings_detail,
}, indent=2), encoding="utf-8")
print(f"\nDetailed audit saved to: {output}")
