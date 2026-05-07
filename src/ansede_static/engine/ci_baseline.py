"""
CI-Native Baseline Auto-Management
───────────────────────────────────
Automatically manages scan baselines for CI/CD pipelines. Compares the current
scan against the "master branch baseline" and only fails if NEW high-criticality
vulnerabilities are introduced.

Workflow:
  1. On main/master merge: save scan result as baseline
  2. On PR: scan, compare against baseline, report NEW findings only
  3. Auto-promotion: if PR merges clean, update baseline
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ansede_static._types import Finding

_log = logging.getLogger(__name__)

DEFAULT_BASELINE_FILE = ".ansede-baseline.json"


@dataclass
class BaselineEntry:
    """A single finding recorded in the baseline."""
    rule_id: str
    cwe: str
    file: str
    line: int
    title_hash: str    # stable hash of title for dedup
    severity: str
    confidence: float
    first_seen: str = ""  # ISO timestamp


@dataclass
class BaselineReport:
    """Comparison result between current scan and baseline."""
    baseline_file: str
    baseline_count: int
    current_count: int
    new_findings: list[Finding] = field(default_factory=list)
    fixed_findings: list[str] = field(default_factory=list)   # rule_id:file:line
    unchanged_count: int = 0
    is_clean: bool = True  # True if no new high/critical findings


def _hash_title(title: str) -> str:
    return hashlib.sha256(title.encode()).hexdigest()[:12]


def _finding_to_entry(finding: Finding, file_path: str) -> BaselineEntry:
    return BaselineEntry(
        rule_id=finding.rule_id or "",
        cwe=finding.cwe or "",
        file=file_path.replace("\\", "/"),
        line=finding.line or 0,
        title_hash=_hash_title(finding.title),
        severity=str(finding.severity).lower() if hasattr(finding.severity, 'value') else str(finding.severity).lower(),
        confidence=finding.confidence,
        first_seen=datetime.now(timezone.utc).isoformat(),
    )


def _entry_key(entry: BaselineEntry) -> str:
    return f"{entry.rule_id}:{entry.file}:{entry.line}:{entry.title_hash}"


def save_baseline(
    findings: list[Finding],
    file_paths: dict[int, str],  # id(path) → relative path
    *,
    baseline_file: str | Path = DEFAULT_BASELINE_FILE,
) -> Path:
    """Save current findings as the baseline."""
    entries: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fp = file_paths.get(id(finding), file_paths.get(hash(finding.title), ""))
        entry = _finding_to_entry(finding, fp)
        key = _entry_key(entry)
        entries[key] = {
            "rule_id": entry.rule_id,
            "cwe": entry.cwe,
            "file": entry.file,
            "line": entry.line,
            "title_hash": entry.title_hash,
            "severity": entry.severity,
            "confidence": entry.confidence,
            "first_seen": entry.first_seen,
        }

    baseline_path = Path(baseline_file)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps({
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(entries),
        "entries": list(entries.values()),
    }, indent=2), encoding="utf-8")

    _log.info("Baseline saved: %d findings → %s", len(entries), baseline_path)
    return baseline_path


def load_baseline(baseline_file: str | Path = DEFAULT_BASELINE_FILE) -> dict[str, BaselineEntry]:
    """Load a saved baseline."""
    path = Path(baseline_file)
    if not path.exists():
        _log.warning("Baseline not found: %s", path)
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    entries: dict[str, BaselineEntry] = {}
    for item in data.get("entries", []):
        if not isinstance(item, dict):
            continue
        entry = BaselineEntry(
            rule_id=item.get("rule_id", ""),
            cwe=item.get("cwe", ""),
            file=item.get("file", ""),
            line=item.get("line", 0),
            title_hash=item.get("title_hash", ""),
            severity=item.get("severity", "info"),
            confidence=item.get("confidence", 0.0),
            first_seen=item.get("first_seen", ""),
        )
        entries[_entry_key(entry)] = entry
    return entries


def compare_against_baseline(
    findings: list[Finding],
    file_paths: dict[int, str],
    *,
    baseline_file: str | Path = DEFAULT_BASELINE_FILE,
    fail_on_new: bool = True,
    severity_threshold: str = "high",
) -> BaselineReport:
    """
    Compare current findings against the baseline.

    Returns a BaselineReport with new, fixed, and unchanged findings.
    Only findings at or above severity_threshold are considered for
    fail_on_new logic.
    """
    baseline = load_baseline(baseline_file)
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = sev_order.get(severity_threshold.lower(), 3)

    baseline_keys = set(baseline.keys())
    current_entries: dict[str, BaselineEntry] = {}
    for finding in findings:
        fp = file_paths.get(id(finding), "")
        entry = _finding_to_entry(finding, fp)
        current_entries[_entry_key(entry)] = entry

    current_keys = set(current_entries.keys())

    new_keys = current_keys - baseline_keys
    fixed_keys = baseline_keys - current_keys
    unchanged_keys = current_keys & baseline_keys

    new_findings: list[Finding] = []
    is_clean = True

    for key in new_keys:
        entry = current_entries[key]
        sev_val = sev_order.get(entry.severity, 0)
        if fail_on_new and sev_val >= threshold:
            is_clean = False
        # Find the original finding back
        for finding in findings:
            if _hash_title(finding.title) == entry.title_hash:
                new_findings.append(finding)
                break

    report = BaselineReport(
        baseline_file=str(baseline_file),
        baseline_count=len(baseline),
        current_count=len(current_entries),
        new_findings=new_findings,
        fixed_findings=sorted(fixed_keys),
        unchanged_count=len(unchanged_keys),
        is_clean=is_clean,
    )

    return report


def auto_promote_baseline(
    findings: list[Finding],
    file_paths: dict[int, str],
    *,
    baseline_file: str | Path = DEFAULT_BASELINE_FILE,
) -> bool:
    """
    Auto-promote: if the current scan has FEWER high/critical findings
    than the baseline, update the baseline. Returns True if promoted.
    """
    baseline = load_baseline(baseline_file)
    if not baseline:
        # No baseline exists — create one
        save_baseline(findings, file_paths, baseline_file=baseline_file)
        return True

    report = compare_against_baseline(
        findings, file_paths, baseline_file=baseline_file,
        fail_on_new=False,  # Don't fail, just compare
    )

    # Promote if we have fewer findings (improvement) and no regressions
    new_high = sum(1 for f in report.new_findings
                   if str(f.severity).lower() in ("critical", "high"))
    fixed = len(report.fixed_findings)

    if new_high == 0 and fixed > 0:
        save_baseline(findings, file_paths, baseline_file=baseline_file)
        _log.info("Baseline auto-promoted: %d findings fixed", fixed)
        return True

    if new_high == 0 and report.current_count < report.baseline_count:
        save_baseline(findings, file_paths, baseline_file=baseline_file)
        _log.info("Baseline auto-promoted: improved from %d to %d findings",
                  report.baseline_count, report.current_count)
        return True

    return False
