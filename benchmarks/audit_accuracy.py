"""Audit every finding for accuracy (TP vs FP) with source-code-level verification.

Uses OWASP naming convention as ground truth (even-numbered = safe/patched, odd = vulnerable)
plus semantic checks on the actual source line for non-OWASP files.
"""
import json, sys, re
from pathlib import Path
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, "src")

RESULTS = Path("benchmarks/campaign_results.json")
OWASP_ROOT = Path("benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode")

# ── CWE-specific safe pattern detectors ──

SAFE_PATTERNS = {
    "CWE-89": [  # SQLi
        r'prepareStatement\s*\([^)]*\?[^)]*\)',  # parameterized
        r'prepareCall\s*\([^)]*\?[^)]*\)',
        r'\.setString\s*\(',  # param binding
        r'\.setInt\s*\(',
        r'\.setLong\s*\(',
        r'ESAPI\.encoder\(\)',  # ESAPI encoding
        r'Encoder\.encodeForSQL',
        r'ESAPI\.randomizer\(\)\.getRandomString',  # safe random
    ],
    "CWE-78": [  # CMDi
        r'ESAPI\.encoder\(\)\.encodeForOS',
        r'Encoder\.encodeForOS',
        r'cmd\.addArgument\("echo"\)',  # hardcoded safe
        r'cmd\.addArgument\("hostname"\)',
        r'cmd\.addArgument\("dir"\)',
        r'cmd\.addCommand\("echo"\)',
        r'String\s+\w+\s*=\s*"echo"',
        r'String\s+\w+\s*=\s*"hostname"',
        r'String\s+\w+\s*=\s*"dir"',
    ],
    "CWE-79": [  # XSS
        r'ESAPI\.encoder\(\)\.encodeForHTML',
        r'Encoder\.encodeForHTML',
        r'\.encodeForHTML\(',
        r'Encode\.forHtml\(',
        r'StringEscapeUtils\.escapeHtml',
        r'htmlEncode\(',
        r'escapeHtml\(',
        r'encodeForJavaScript\(',
        r'encodeForCSS\(',
        r'ESAPI\.randomizer\(\)\.getRandomString',  # safe random data
    ],
    "CWE-22": [  # Path Traversal
        r'ESAPI\.validator\(\)\.getValidDirectoryPath',
        r'getCanonicalPath\(\)',
        r'\.normalize\(\)',
        r'Paths\.get\([^)]*\)\.normalize',
        r'FilenameUtils\.normalize',
        r'ESAPI\.randomizer\(\)\.getRandomString',
    ],
    "CWE-327": [  # Weak Crypto (used vs declared)
        # Hard to distinguish - check if it's just a test label
    ],
    "CWE-328": [  # Weak Hash
        # Same issue - check if MD5/SHA1 is actually used
    ],
    "CWE-501": [  # Trust Boundary
        r'\.setAttribute\([^)]*\)',  # setting attribute is the violation
    ],
    "CWE-330": [  # Weak Random
        r'SecureRandom',  # using SecureRandom is safe
        r'ESAPI\.randomizer\(\)',
    ],
    "CWE-614": [  # Secure Cookie
        r'\.setSecure\(true\)',  # setting secure flag is safe
    ],
    "CWE-90": [  # LDAP Injection
        r'ESAPI\.encoder\(\)\.encodeForLDAP',
        r'Encoder\.encodeForLDAP',
    ],
    "CWE-643": [  # XPath Injection
        r'ESAPI\.encoder\(\)\.encodeForXPath',
        r'Encoder\.encodeForXPath',
    ],
}

def test_number_from_filename(filepath: str) -> int | None:
    """Extract OWASP test number from filename."""
    m = re.search(r'BenchmarkTest(\d{5})', filepath)
    return int(m.group(1)) if m else None

def is_owasp_safe(test_num: int) -> bool:
    """OWASP convention: even numbers are patched/safe, odd are vulnerable."""
    return test_num % 2 == 0

def has_safe_pattern(code: str, line_num: int, cwe: str) -> bool:
    """Check if the source around the finding line contains safe patterns."""
    lines = code.split("\n")
    # Check 5 lines around finding
    start = max(0, line_num - 1 - 3)
    end = min(len(lines), line_num + 3)
    context = "\n".join(lines[start:end])
    
    patterns = SAFE_PATTERNS.get(cwe, [])
    for pat in patterns:
        if re.search(pat, context, re.IGNORECASE):
            return True
    return False

def classify_finding(finding: dict, code: str) -> str:
    """Classify a single finding as TP, FP, or UNCERTAIN."""
    test_num = test_number_from_filename(finding.get("file", ""))
    cwe = finding.get("cwe", "?")
    line = finding.get("line", 0)
    rule = finding.get("rule_id", "?")
    
    # For OWASP files, use naming convention as ground truth
    if test_num is not None:
        expected_safe = is_owasp_safe(test_num)
        if expected_safe:
            return "FP"  # Should NOT have finding on a safe test
        else:
            # Vulnerable test - check for false positives via safe patterns
            if has_safe_pattern(code, line, cwe):
                return "FP"  # Has safe pattern despite being vulnerable test
            return "TP"  # Correctly found on vulnerable test
    
    # Non-OWASP file - use semantic analysis
    if has_safe_pattern(code, line, cwe):
        return "FP"
    
    return "TP"

# ── Load results ──
print("=" * 60)
print("ANSEDE ACCURACY AUDIT")
print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
print("=" * 60)

data = json.load(open(RESULTS))
print(f"Findings to audit: {len(data.get('findings', []))}")

# Reconstruct findings from the scan results
# We need the full finding list with file paths from the scan
# Let me re-run with enriched output including file paths

# Since campaign_results.json doesn't have per-finding file paths,
# let's rebuild by directly scanning the OWASP files and auditing
print("\nRe-running with per-finding file tracking...")

# Read the campaign scanner's output to get file paths
# Actually, let's read the OWASP files directly and cross-reference
total_findings = data["total_findings"]
by_cwe = data.get("by_cwe", {})

print(f"\nFindings to audit: {total_findings}")
print(f"CWE breakdown: {json.dumps(by_cwe, indent=2)}")

print("\n── Audit Strategy ──")
print("Using OWASP naming convention:")
print("  - Even-numbered test (BenchmarkTestXXXX0, XXXX2, ...) = SAFE/patched")
print("  - Odd-numbered test (BenchmarkTestXXXX1, XXXXX3, ...) = VULNERABLE")
print("  - Finding on safe test = False Positive")
print("  - Finding on vulnerable test = True Positive (after safe-pattern check)")

print("\n── Detailed Audit Results ──")
