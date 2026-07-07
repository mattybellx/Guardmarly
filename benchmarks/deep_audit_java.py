"""
deep_audit_java.py — Thorough manual-style audit of Java blind sample findings.
Prints every finding with context, then classifies each as TP/FP/LIKELY_FP/NEEDS_REVIEW.
"""
import json, sys
from pathlib import Path

INPUT = Path(__file__).parent / "audit_results" / "round1_java.json"
data = json.loads(INPUT.read_text())

# ── Audit heuristics ──────────────────────────────────────────────
# These are pattern-based verdicts applied before human review.
# Each is (rule_id_contains, cwe, path_contains, verdict, reason)

AUTO_RULES = [
    # CWE-330 / insecure random — almost always FP in Java (non-security Random usage)
    ("JAVA-", "CWE-330", "", "LIKELY_FP",
     "java.util.Random used for non-security purposes (shuffling, UI, testing). "
     "Only java.security.SecureRandom is required for crypto. Check if used for tokens/keys."),

    # CWE-330 in test files
    ("JAVA-", "CWE-330", "test", "FP",
     "Random in test code is never a security issue."),

    # CWE-330 in Android/widget code
    ("JAVA-", "CWE-330", "widget", "FP",
     "Random in Android UI/widget code — not security-sensitive."),

    # CWE-117 log injection — context-dependent
    ("JAVA-", "CWE-117", "", "NEEDS_REVIEW",
     "Log injection requires untrusted data flowing into log calls. "
     "Check if logged data comes from user input (request params, headers, etc)."),

    # CWE-117 in test files
    ("JAVA-", "CWE-117", "test", "FP",
     "Log injection in test code is not exploitable."),

    # CWE-798 hardcoded secrets — needs context
    ("JAVA-", "CWE-798", "", "NEEDS_REVIEW",
     "Hardcoded secret — check if it's a real credential, a placeholder, or documentation."),

    # CWE-798 in test files
    ("JAVA-", "CWE-798", "test", "FP",
     "Hardcoded credentials in test fixtures are expected."),

    # CWE-79 XSS in Java
    ("JAVA-", "CWE-79", "", "NEEDS_REVIEW",
     "XSS in Java — check if output is HTML-encoded. JSP expressions <%= %> auto-encode; "
     "<% out.print() %> does not."),

    # CWE-89 SQL injection
    ("JAVA-", "CWE-89", "", "NEEDS_REVIEW",
     "SQL injection — check if query uses PreparedStatement/parameterized queries vs string concatenation."),

    # CWE-89 in test
    ("JAVA-", "CWE-89", "test", "FP",
     "SQL injection in test code — not exploitable in production."),

    # CWE-328 weak hash
    ("JAVA-", "CWE-328", "", "NEEDS_REVIEW",
     "Weak hash (MD4/SHA1) — check if used for security (passwords/tokens) or non-security (checksums)."),

    # CWE-601 open redirect
    ("JAVA-", "CWE-601", "", "NEEDS_REVIEW",
     "Open redirect — check if redirect URL is user-controlled without validation."),

    # CWE-78 command injection
    ("JAVA-", "CWE-78", "", "NEEDS_REVIEW",
     "Command injection — check if Runtime.exec/ProcessBuilder uses unsanitized user input."),

    # CWE-327 weak crypto
    ("JAVA-", "CWE-327", "", "NEEDS_REVIEW",
     "Weak cryptography — check if used for security-sensitive operations."),
]


def classify(finding, file_path):
    """Return (verdict, reason) for a finding."""
    rule = finding.get("rule_id", "")
    cwe = finding.get("cwe", "")
    fp_lower = file_path.lower()

    for r_contains, r_cwe, path_contains, verdict, reason in AUTO_RULES:
        if r_contains and r_contains not in rule:
            continue
        if r_cwe and cwe != r_cwe:
            continue
        if path_contains and path_contains.lower() not in fp_lower:
            continue
        return verdict, reason

    return "NEEDS_REVIEW", "No auto-rule matched — requires human inspection."


# ── Main audit ────────────────────────────────────────────────────

verdicts = {"TP": 0, "FP": 0, "LIKELY_FP": 0, "NEEDS_REVIEW": 0}
cwe_verdicts = {}

for repo in data["repos"]:
    name = repo["name"]
    print(f"\n{'='*80}")
    print(f"REPO: {name}  ({repo['stars']}*, {repo['loc']:,} LOC, {repo['findings_count']} findings)")
    print(f"{'='*80}")

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

            verdict, reason = classify(f, fp_rel)

            verdicts[verdict] = verdicts.get(verdict, 0) + 1
            key = f"{verdict}:{cwe}"
            cwe_verdicts[key] = cwe_verdicts.get(key, 0) + 1

            marker = {"TP": "✅", "FP": "❌", "LIKELY_FP": "⚠️", "NEEDS_REVIEW": "🔍"}[verdict]
            print(f"    [{i+1:3d}] {marker} {verdict:12s} | {rule:10s} | {cwe:10s} | L{line:4d} | {sev:8s}")
            print(f"          {title}")
            print(f"          → {reason}")

print(f"\n{'='*80}")
print(f"AUDIT SUMMARY")
print(f"{'='*80}")
for v in ["TP", "LIKELY_FP", "FP", "NEEDS_REVIEW"]:
    print(f"  {v:15s}: {verdicts.get(v, 0):4d}")

print(f"\n  BY CWE + VERDICT:")
for key, count in sorted(cwe_verdicts.items(), key=lambda x: -x[1]):
    print(f"    {key:40s}: {count:4d}")

# ── Per-repo summary ──────────────────────────────────────────────
print(f"\n{'='*80}")
print(f"PER-REPO SUMMARY")
print(f"{'='*80}")
for repo in data["repos"]:
    name = repo["name"]
    fc = repo["findings_count"]
    # Count file types
    test_files = sum(1 for fd in repo["files"] if "test" in fd["file_path"].lower())
    total_files = len(repo["files"])
    print(f"  {name:45s} | {fc:3d} findings | {total_files:4d} files ({test_files:3d} test) | {repo['loc']:>8,} LOC | {repo['scan_time_s']:>6.1f}s")

# ── Silent repos check ────────────────────────────────────────────
print(f"\n{'='*80}")
print(f"SILENT REPOS (0 findings — potential detection gaps)")
print(f"{'='*80}")
for repo in data["repos"]:
    if repo["findings_count"] == 0:
        print(f"  {repo['name']:45s} | {repo['stars']}* | {repo['loc']:,} LOC | {repo['java_files']} .java files")
        print(f"    → MANUAL CHECK: Are there any web routes, SQL queries, or auth checks we missed?")
