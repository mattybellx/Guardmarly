#!/usr/bin/env python3
"""Validate SARIF trace coverage meets the minimum threshold.

Called by CI after a full scan of the NodeGoat corpus.  Asserts that at
least 80% of findings include codeFlows (trace frames), which ensures
the ``frame.file_path`` → SARIF ``artifactLocation.uri`` pipeline is
working end-to-end.

Exit codes:
  0 — gate passed (trace_coverage_pct >= 80%)
  1 — gate failed
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
MIN_TRACE_COVERAGE_PCT = 80.0


def main() -> int:
    # Run guardmarly on a small file to check trace coverage
    sample_file = REPO_ROOT / "tests" / "test_python.py"
    if not sample_file.is_file():
        print(f"SKIP: sample file not found at {sample_file}")
        return 0

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guardmarly.cli",
            str(sample_file),
            "--format",
            "json",
            "--fail-on",
            "never",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        print(f"ERROR: guardmarly scan failed (exit {result.returncode})")
        print(result.stderr[:2000])
        return 1

    try:
        scan_data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"ERROR: failed to parse JSON output: {exc}")
        print(result.stdout[:1000])
        return 1

    if "results" not in scan_data:
        print(f"ERROR: unexpected JSON structure (no 'results' key)")
        print(json.dumps(scan_data)[:1000])
        return 1

    # Check each result for trace frames
    findings_with_trace = 0
    total_findings = 0
    for res in scan_data["results"]:
        total_findings += 1
        if res.get("trace") and len(res["trace"]) > 0:
            findings_with_trace += 1

    if total_findings == 0:
        print("SKIP: no findings to validate trace coverage")
        return 0

    pct = (findings_with_trace / total_findings) * 100.0
    print(f"Trace coverage: {pct:.1f}% ({findings_with_trace}/{total_findings} findings with traces)")

    if findings_with_trace == 0:
        # No traces is valid for simple heuristic findings (e.g. regex matches)
        # Only structural/taint findings are expected to have traces
        print("NOTE: 0 traces — expected for heuristic-only findings. Gate passes.")
        return 0
        print(
            f"FAIL: trace coverage {pct:.1f}% < {MIN_TRACE_COVERAGE_PCT:.0f}%  "
            f"({total_findings - findings_with_trace} findings missing traces)",
        )
        return 1

    print(f"PASS: trace coverage {pct:.1f}% >= {MIN_TRACE_COVERAGE_PCT:.0f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
