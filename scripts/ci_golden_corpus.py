# Golden Corpus Validation — CI Workflow Step
# ============================================
# Run this in CI to validate that every rule still detects its paired
# vulnerable test cases without false positives on secure cases.
#
# Usage:
#   python scripts/ci_golden_corpus.py              # validate only
#   python scripts/ci_golden_corpus.py --strict      # fail on any regression
#
# Exit codes:
#   0 — all pairs pass or no corpus found
#   1 — one or more regressions detected
#   2 — corpus directory missing (warning only if not --strict)

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / ".ansede" / "golden_corpus"


@dataclass
class CIResult:
    cwe: str
    language: str
    passed: bool
    fn: bool  # false negative — missed vulnerable
    fp: bool  # false positive — flagged secure
    vuln_findings: int = 0
    secure_findings: int = 0
    elapsed_ms: float = 0.0
    error: str = ""


def discover_pairs() -> dict[str, dict[str, Path]]:
    if not CORPUS_ROOT.exists():
        return {}
    pairs: dict[str, dict[str, Path]] = {}
    for cwe_dir in sorted(CORPUS_ROOT.iterdir()):
        if not cwe_dir.is_dir() or not cwe_dir.name.startswith("CWE-"):
            continue
        vuln_files = sorted(cwe_dir.glob("vulnerable.*.test"))
        secure_files = sorted(cwe_dir.glob("secure.*.test"))
        if vuln_files and secure_files:
            pairs[cwe_dir.name] = {"vulnerable": vuln_files[0], "secure": secure_files[0]}
    return pairs


def scan_file(filepath: Path) -> tuple[int, float]:
    """Copy to temp with correct extension, scan, return finding count."""
    suffixes = filepath.suffixes
    lang_ext = suffixes[0] if len(suffixes) >= 2 and suffixes[-1] == ".test" else filepath.suffix

    with tempfile.NamedTemporaryFile(suffix=lang_ext, delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.write(filepath.read_text(encoding="utf-8", errors="replace"))
        tmp_path = Path(tmp.name)

    try:
        start = time.perf_counter()
        result = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(tmp_path),
             "--format", "json", "--no-triage", "--no-colour"],
            capture_output=True, text=True, timeout=15,
            cwd=str(REPO_ROOT),
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        data = json.loads(result.stdout)
        return data.get("summary", {}).get("total_findings", 0), elapsed
    except Exception:
        return 0, (time.perf_counter() - start) * 1000.0
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="CI Golden Corpus Validation")
    parser.add_argument("--strict", action="store_true", help="Fail on any regression")
    parser.add_argument("--json", action="store_true", help="Output JSON for CI parsing")
    args = parser.parse_args()

    pairs = discover_pairs()
    if not pairs:
        msg = "No golden corpus found. Skipping validation."
        if args.json:
            print(json.dumps({"status": "skipped", "reason": msg}))
        else:
            print(msg)
        sys.exit(0 if not args.strict else 2)

    results: list[CIResult] = []
    passed = 0
    failed = 0

    for cwe_id, files in sorted(pairs.items()):
        vuln_count, vuln_ms = scan_file(files["vulnerable"])
        secure_count, secure_ms = scan_file(files["secure"])

        fn = vuln_count == 0
        fp = secure_count > 0
        ok = not fn and not fp

        lang = "py" if ".py" in files["vulnerable"].suffixes else "js"

        results.append(CIResult(
            cwe=cwe_id, language=lang, passed=ok,
            fn=fn, fp=fp,
            vuln_findings=vuln_count, secure_findings=secure_count,
            elapsed_ms=vuln_ms + secure_ms,
        ))

        if ok:
            passed += 1
            status = "PASS"
        else:
            failed += 1
            status = "FN" if fn else "FP"

        if not args.json:
            print(f"  [{status}] {cwe_id} ({lang}): vuln={vuln_count}, secure={secure_count} [{vuln_ms + secure_ms:.0f}ms]")

    # ── Output ──────────────────────────────────────────────────────────────
    pct = (passed / len(results) * 100) if results else 0

    if args.json:
        print(json.dumps({
            "status": "pass" if failed == 0 else "fail",
            "total": len(results),
            "passed": passed,
            "failed": failed,
            "pass_rate_pct": round(pct, 1),
            "results": [
                {"cwe": r.cwe, "language": r.language, "passed": r.passed,
                 "fn": r.fn, "fp": r.fp, "vuln_findings": r.vuln_findings,
                 "secure_findings": r.secure_findings, "elapsed_ms": round(r.elapsed_ms, 2)}
                for r in results
            ],
        }))
    else:
        print(f"\n  Golden Corpus: {passed}/{len(results)} passed ({pct:.0f}%)")

    sys.exit(1 if (failed > 0 and args.strict) else 0)


if __name__ == "__main__":
    main()
