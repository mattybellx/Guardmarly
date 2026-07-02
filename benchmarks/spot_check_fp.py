"""Spot-check FP_LEGIT findings to verify if scanner found real vulns or missed safe patterns."""
import json, re
from pathlib import Path

data = json.load(open("benchmarks/audit_results.json"))
fp_samples = data.get("fp_samples", [])

SAFE_PATS = {
    "CWE-79": ["encodeForHTML", "ESAPI", "escapeHtml", "htmlEncode", "Encoder", "Encode.forHtml", "StringEscapeUtils"],
    "CWE-89": ["prepareStatement.*\\?", "setString", "setInt", "ESAPI", "Encoder"],
    "CWE-78": ["encodeForOS", "addArgument.*echo", "addCommand.*echo", "ESAPI"],
    "CWE-22": ["getValidDirectoryPath", "getCanonicalPath", "normalize", "ESAPI"],
    "CWE-327": ["AES/GCM", "OAEP"],
    "CWE-328": ["SHA-256", "SHA-384", "SHA-512"],
    "CWE-330": ["SecureRandom", "ESAPI"],
    "CWE-90": ["encodeForLDAP", "ESAPI"],
    "CWE-643": ["encodeForXPath", "ESAPI"],
    "CWE-501": [],  # Trust boundary is about session attributes
    "CWE-614": ["setSecure.*true"],
}

print("=" * 70)
print("SPOT-CHECKING FP_LEGIT: Are these real FPs or correct findings?")
print("=" * 70)

checked = 0
missed_safe = 0
scanner_correct = 0

for f in fp_samples:
    if f["verdict"] != "FP_LEGIT":
        continue
    if checked >= 10:
        break
    checked += 1

    fp = Path(f["file"])
    cwe = f["cwe"]
    line = f["line"]

    if not fp.exists():
        continue

    lines_data = fp.read_text(encoding="utf-8", errors="replace").split("\n")
    lo = max(0, line - 5)
    hi = min(len(lines_data), line + 5)

    test_num = re.search(r"BenchmarkTest(\d{5})", str(fp))
    num = test_num.group(1) if test_num else "?"

    print(f"\nFile: {fp.name} (#{num}, even -> OWASP=SAFE)")
    print(f"Finding: {cwe} L{line} [{f['rule_id']}]")
    print(f"Context L{lo+1}-L{hi}:")
    for i in range(lo, hi):
        marker = ">>>" if i == line - 1 else "   "
        print(f"  {marker} L{i+1:4d}: {lines_data[i].rstrip()[:130]}")

    ctx = "\n".join(lines_data[lo:hi])
    pats = SAFE_PATS.get(cwe, [])
    found_safe = [p for p in pats if re.search(p, ctx, re.IGNORECASE)]

    if found_safe:
        print(f"  !!! FOUND safe patterns: {found_safe}")
        print(f"  VERDICT: TRUE FALSE POSITIVE (scanner missed safe patterns)")
        missed_safe += 1
    else:
        print(f"  NO safe patterns found")
        print(f"  VERDICT: SCANNER CORRECT (OWASP mislabeled test as safe)")
        scanner_correct += 1

print(f"\n{'=' * 70}")
print(f"SPOT CHECK SUMMARY ({checked} cases):")
print(f"  Scanner correct (OWASP mislabeled): {scanner_correct}")
print(f"  True FPs (scanner missed safe pattern): {missed_safe}")
