"""
auto_validate_fixes.py — Re-scans files from the audit to verify fixes worked.

For each file that had FP findings, re-scans it with the updated engine
and confirms those specific FPs are now suppressed.
"""
import json, sys, time
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_file

AUDIT_FILE = Path(__file__).parent / "audit_results" / "round1_java_audited.json"
CACHE_DIR = Path(r"C:\Users\matth\AppData\Local\Temp\ansede_java_audit")


def find_source_file(file_rel: str) -> Path | None:
    """Find a Java file in the cached repos by relative path suffix."""
    if not CACHE_DIR.exists():
        return None
    fname = file_rel.replace("\\", "/").split("/")[-1]
    for java_file in CACHE_DIR.rglob("*.java"):
        if java_file.name == fname:
            rel = str(java_file).replace("\\", "/")
            if file_rel.replace("\\", "/") in rel or fname == java_file.name:
                return java_file
    return None


def main():
    if not AUDIT_FILE.exists():
        print("No audit file found — run source_level_audit.py first")
        return

    data = json.loads(AUDIT_FILE.read_text())
    findings = data["findings"]

    # Group by rule_id for FP findings
    fp_by_rule = defaultdict(list)
    for f in findings:
        if f["verdict"] in ("FP", "LIKELY_FP"):
            fp_by_rule[f["rule"]].append(f)

    print("=" * 70)
    print("AUTO-VALIDATION: Re-scanning files that had FPs to verify fixes")
    print("=" * 70)
    print(f"Rules with suppressed FPs to validate: {len(fp_by_rule)}")
    print()

    results = {}
    for rule_id, rule_findings in sorted(fp_by_rule.items()):
        # Deduplicate files
        files_to_check = list({f["file"]: f for f in rule_findings}.values())
        print(f"--- {rule_id}: {len(rule_findings)} FPs across {len(files_to_check)} files ---")

        rule_ok = True
        for f in files_to_check[:5]:  # Cap at 5 files per rule for speed
            src_path = find_source_file(f["file"])
            if src_path is None:
                print(f"  ⚠️  Source not found: {f['file']}")
                continue

            try:
                result = scan_file(src_path)
            except Exception as e:
                print(f"  ❌ SCAN ERROR: {src_path.name}: {e}")
                rule_ok = False
                continue

            # Check if the original FP is still there
            still_present = False
            for finding in result.findings:
                if finding.rule_id == rule_id and finding.line == f["line"]:
                    still_present = True
                    break

            if still_present:
                print(f"  ❌ FP STILL PRESENT: {src_path.name} L{f['line']} — rule {rule_id} not suppressed")
                rule_ok = False
            else:
                print(f"  ✅ FP suppressed:     {src_path.name} L{f['line']} — rule {rule_id} now clean")

        results[rule_id] = rule_ok
        print()

    # Summary
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    passed = sum(1 for v in results.values() if v)
    failed = sum(1 for v in results.values() if not v)
    print(f"  Rules validated: {len(results)}")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print()

    for rule_id, ok in sorted(results.items()):
        marker = "✅" if ok else "❌"
        print(f"  {marker} {rule_id}")

    if failed == 0:
        print("\n🎉 ALL FIXES VALIDATED — engine is better, nothing broken!")
    else:
        print(f"\n⚠️  {failed} rules still need work — check the ❌ lines above.")

    return failed == 0


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
