"""
benchmarks.quality_benchmark
────────────────────────────
Signal-quality benchmark for ansede-static.

This focuses on trust-oriented cases: expected hits must fire and safe fixtures
must stay quiet for the targeted rule family.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_code
from benchmarks.quality_corpus import QUALITY_CORPUS, QualityCase


def _scan_case(case: QualityCase):
    return scan_code(
        case.snippet,
        language=case.language,
        filename=case.filename or f"{case.case_id}.{ 'py' if case.language == 'python' else 'js' }",
        js_backend=case.js_backend,
    )


def _evaluate_case(case: QualityCase) -> dict[str, Any]:
    result = _scan_case(case)
    seen_cwes = {finding.cwe for finding in result.findings if finding.cwe}
    seen_rule_ids = {finding.rule_id for finding in result.findings if finding.rule_id}

    checks: list[dict[str, Any]] = []

    for token in case.expected_cwes:
        checks.append({
            "token": token,
            "kind": "expected-cwe",
            "passed": token in seen_cwes,
        })
    for token in case.forbidden_cwes:
        checks.append({
            "token": token,
            "kind": "forbidden-cwe",
            "passed": token not in seen_cwes,
        })
    for token in case.expected_rule_ids:
        checks.append({
            "token": token,
            "kind": "expected-rule",
            "passed": token in seen_rule_ids,
        })
    for token in case.forbidden_rule_ids:
        checks.append({
            "token": token,
            "kind": "forbidden-rule",
            "passed": token not in seen_rule_ids,
        })

    return {
        "case_id": case.case_id,
        "language": case.language,
        "js_backend": case.js_backend,
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "findings": [finding.as_dict(language=result.language) for finding in result.sorted_findings()],
        "notes": case.notes,
    }


def run_quality_benchmark(lang_filter: str | None = None, quiet: bool = False) -> dict[str, Any]:
    cases = [case for case in QUALITY_CORPUS if lang_filter is None or case.language == lang_filter]
    if not cases:
        return {
            "cases": [],
            "summary": {"total_cases": 0, "passed_cases": 0, "checks_total": 0, "checks_passed": 0, "score_pct": 0.0},
            "per_token": {},
        }

    case_results = [_evaluate_case(case) for case in cases]
    checks_total = sum(len(case["checks"]) for case in case_results)
    checks_passed = sum(1 for case in case_results for check in case["checks"] if check["passed"])
    passed_cases = sum(1 for case in case_results if case["passed"])

    per_token: dict[str, dict[str, int]] = defaultdict(lambda: {"checks": 0, "passed": 0})
    for case in case_results:
        for check in case["checks"]:
            bucket = per_token[check["token"]]
            bucket["checks"] += 1
            bucket["passed"] += 1 if check["passed"] else 0

    summary = {
        "total_cases": len(case_results),
        "passed_cases": passed_cases,
        "checks_total": checks_total,
        "checks_passed": checks_passed,
        "score_pct": round((checks_passed / checks_total * 100.0) if checks_total else 0.0, 2),
    }

    report = {
        "cases": case_results,
        "summary": summary,
        "per_token": dict(sorted(per_token.items())),
    }

    if not quiet:
        print()
        print("┌" + "─" * 72 + "┐")
        print("│{:^72}│".format("ansede-static Quality Benchmark"))
        print("│{:^72}│".format("Trust-oriented hit + silence checks for high-value detectors"))
        print("└" + "─" * 72 + "┘")
        print()
        for case in case_results:
            icon = "✓" if case["passed"] else "✗"
            print(f"  {icon}  {case['case_id']:<24} {case['language']:<11} backend={case['js_backend']:<10} checks={len(case['checks'])}")
            for check in case["checks"]:
                status = "pass" if check["passed"] else "FAIL"
                print(f"       - {status:<4} {check['kind']:<14} {check['token']}")
        print()
        print(f"  Score: {summary['checks_passed']}/{summary['checks_total']} checks passed  ({summary['score_pct']:.2f}%)")
        print(f"  Cases: {summary['passed_cases']}/{summary['total_cases']} fully green")
        print()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static quality benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python -m benchmarks.quality_benchmark
              python -m benchmarks.quality_benchmark --lang python
              python -m benchmarks.quality_benchmark --fail-under 95
              python -m benchmarks.quality_benchmark --quiet --json
        """),
    )
    parser.add_argument("--lang", choices=["python", "javascript"], default=None,
                        help="Only evaluate one language slice")
    parser.add_argument("--fail-under", type=float, default=0.0, metavar="PCT",
                        help="Exit with code 1 if score is below this percentage")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress the human summary")
    parser.add_argument("--json", action="store_true",
                        help="Print the final report as JSON")
    args = parser.parse_args()

    report = run_quality_benchmark(lang_filter=args.lang, quiet=args.quiet)

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if args.fail_under and report["summary"]["score_pct"] < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
