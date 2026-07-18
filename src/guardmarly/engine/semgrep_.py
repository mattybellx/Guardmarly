"""
guardmarly.engine.semgrep_
─────────────────────────────
Semgrep integration wrapper (ROADMAP Section 11).

Provides a secondary SAST validation layer. When semgrep is installed,
runs semgrep rules alongside guardmarly's native analysis and merges findings
with deduplication and confidence reconciliation.

Zero dependencies — invokes the `semgrep` CLI as a subprocess.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from guardmarly._types import Finding, Severity, TraceFrame

_log = logging.getLogger(__name__)

_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def _find_semgrep() -> Optional[str]:
    """Locate the semgrep binary."""
    for candidate in ("semgrep", "semgrep.exe"):
        try:
            result = subprocess.run(
                [candidate, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _parse_semgrep_json(output: str) -> list[dict]:
    """Parse semgrep JSON output."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    return data.get("results", [])


def _build_guardmarly_finding(sr: dict, filepath: str) -> Finding:
    """Convert a semgrep result to an guardmarly Finding."""
    extra = sr.get("extra", {})
    check_id = sr.get("check_id", "semgrep/unknown")
    severity_str = extra.get("severity", "WARNING")
    severity = _SEMGREP_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
    message = extra.get("message", "")
    metadata = extra.get("metadata", {})
    cwe = None
    if isinstance(metadata, dict):
        cwe_list = metadata.get("cwe", [])
        if cwe_list and isinstance(cwe_list, list):
            cwe = cwe_list[0]
        elif isinstance(cwe_list, str):
            cwe = cwe_list

    line = sr.get("start", {}).get("line", 1)

    trace: tuple[TraceFrame, ...] = (
        TraceFrame(kind="source", label=f"semgrep rule `{check_id}`", line=line),
        TraceFrame(kind="sink", label=message[:80], line=line),
    )

    return Finding(
        category=metadata.get("category", "security") if isinstance(metadata, dict) else "security",
        severity=severity,
        title=f"[semgrep] {check_id}: {message[:70]}",
        description=f"Semgrep detected: {message} (rule: {check_id})",
        line=line,
        suggestion=metadata.get("remediation", "") if isinstance(metadata, dict) else "",
        rule_id=f"semgrep/{check_id}",
        cwe=cwe,
        agent="semgrep",
        confidence=0.80,
        analysis_kind="semgrep-rule",
        trace=trace,
    )


def run_semgrep_on_path(
    target: str | Path,
    *,
    config: Optional[str] = None,
    lang: Optional[str] = None,
    severity: Optional[str] = None,
) -> list[Finding]:
    """Run semgrep against a file or directory.

    Args:
        target: File or directory to scan
        config: Semgrep config (ruleset name or path). Default: 'auto'
        lang: Language filter
        severity: Minimum severity (ERROR, WARNING, INFO)
    """
    semgrep = _find_semgrep()
    if not semgrep:
        return []

    cmd = [semgrep, "--json", "--quiet", "--no-git-ignore"]
    if config:
        cmd.extend(["--config", config])
    else:
        cmd.extend(["--config", "auto"])
    if lang:
        cmd.extend(["--lang", lang])
    if severity:
        cmd.extend(["--severity", severity])
    cmd.append(str(target))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError) as exc:
        _log.debug("semgrep scan failed: %s", exc)
        return []

    raw_results = _parse_semgrep_json(result.stdout)
    filepath = str(target)
    return [_build_guardmarly_finding(sr, filepath) for sr in raw_results]


def merge_semgrep_findings(
    guardmarly_findings: list[Finding],
    semgrep_findings: list[Finding],
) -> list[Finding]:
    """Merge semgrep findings into guardmarly findings with deduplication.

    Semgrep findings that overlap with guardmarly findings (same CWE + line)
    are skipped to avoid double-counting. Non-overlapping semgrep findings
    are added as supplementary detections with reduced confidence.
    """
    guardmarly_keys: set[tuple[str, int]] = set()
    for f in guardmarly_findings:
        guardmarly_keys.add((f.cwe or "", f.line or 0))

    merged = list(guardmarly_findings)
    for sf in semgrep_findings:
        key = (sf.cwe or "", sf.line or 0)
        if key in guardmarly_keys:
            continue
        sf.confidence = min(sf.confidence, 0.65)
        sf.title = f"{sf.title} [supplementary]"
        merged.append(sf)

    return merged


def is_available() -> bool:
    """Check if semgrep is installed and available."""
    return _find_semgrep() is not None
