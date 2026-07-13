"""
ansede_static.baseline
──────────────────────
Baseline suppression file support (v6.3+).

Enables teams to suppress known false positives across CI runs:
  ansede-static --baseline .ansede-baseline.json src/       # generate
  ansede-static --baseline-file .ansede-baseline.json src/  # filter

Format:
  {
    "version": "1.0",
    "generated": "2026-07-12T...",
    "fingerprints": {
      "hash1": {"rule_id": "PY-005", "file": "app.py", "line": 42,
                "reason": "Test fixture", "expires": "2026-12-31"},
      ...
    }
  }
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ansede_static._types import AnalysisResult, Finding


def fingerprint_finding(file_path: str, finding: Finding) -> str:
    """Generate a stable fingerprint for a finding.

    Based on (rule_id, file_path, line, snippet) so that minor code
    changes on the same line won't match (intentionally conservative).
    """
    payload = (
        f"{finding.effective_rule_id}|"
        f"{file_path}|"
        f"{finding.line or 0}|"
        f"{(finding.triggering_code or finding.title)[:80]}"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def generate_baseline(
    results: list[AnalysisResult],
    output_path: str | Path,
    *,
    reason: str = "",
) -> dict[str, Any]:
    """Generate a baseline file from current scan results.

    All current findings are recorded as suppressed, with the current
    timestamp.  Teams should then review and remove entries they want
    to continue seeing.
    """
    fingerprints: dict[str, dict[str, Any]] = {}
    now = datetime.now(timezone.utc).isoformat()

    for result in results:
        for finding in result.findings:
            fp = fingerprint_finding(result.file_path, finding)
            fingerprints[fp] = {
                "rule_id": finding.effective_rule_id,
                "cwe": finding.cwe,
                "file": result.file_path,
                "line": finding.line,
                "title": finding.title[:120],
                "severity": finding.severity.value,
                "reason": reason or "Auto-generated baseline",
                "created": now,
                "expires": "",
            }

    baseline: dict[str, Any] = {
        "version": "1.0",
        "generated": now,
        "count": len(fingerprints),
        "fingerprints": fingerprints,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")

    return baseline


def load_baseline(path: str | Path) -> dict[str, Any] | None:
    """Load a baseline file, returning None if missing or invalid."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if "fingerprints" not in data:
            return None
        return data
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def filter_by_baseline(
    results: list[AnalysisResult],
    baseline: dict[str, Any] | None,
) -> tuple[list[AnalysisResult], int]:
    """Filter findings against a baseline, returning (filtered_results, suppressed_count).

    Findings whose fingerprint matches an entry in the baseline are removed.
    """
    if not baseline or "fingerprints" not in baseline:
        return results, 0

    baseline_fps: set[str] = set(baseline["fingerprints"].keys())
    suppressed = 0

    filtered: list[AnalysisResult] = []
    for result in results:
        kept = []
        for finding in result.findings:
            fp = fingerprint_finding(result.file_path, finding)
            if fp in baseline_fps:
                suppressed += 1
            else:
                kept.append(finding)
        # Create a copy with filtered findings
        filtered_result = AnalysisResult(
            file_path=result.file_path,
            language=result.language,
            findings=kept,
            lines_scanned=result.lines_scanned,
            parse_error=result.parse_error,
            analysis_degraded=result.analysis_degraded,
            degradation_reason=result.degradation_reason,
        )
        filtered.append(filtered_result)

    return filtered, suppressed
