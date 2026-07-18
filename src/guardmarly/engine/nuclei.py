"""
guardmarly.engine.nuclei
───────────────────────────
Nuclei integration wrapper (ROADMAP Section 10).

Provides protocol-aware smart probes via the Nuclei template engine.
When nuclei is installed, this module can run targeted templates against
discovered endpoints and merge findings into guardmarly's SARIF output.

Zero dependencies — invokes the `nuclei` CLI as a subprocess.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from guardmarly._types import Finding, Severity, TraceFrame

_log = logging.getLogger(__name__)

_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _find_nuclei() -> Optional[str]:
    """Locate the nuclei binary."""
    for candidate in ("nuclei", "nuclei.exe"):
        try:
            result = subprocess.run(
                [candidate, "-version"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return candidate
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _parse_nuclei_json(output: str) -> list[dict]:
    """Parse nuclei JSONL output into a list of result dicts."""
    results: list[dict] = []
    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def run_nuclei_on_url(
    url: str,
    *,
    templates: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
    severity: Optional[str] = None,
    timeout: int = 30,
) -> list[Finding]:
    """Run nuclei against a URL and return guardmarly Findings.

    Args:
        url: Target URL to probe
        templates: Specific template paths or names
        tags: Template tags to filter (e.g., ['cve', 'exposure'])
        severity: Minimum severity filter
        timeout: Maximum runtime in seconds
    """
    nuclei = _find_nuclei()
    if not nuclei:
        return []

    cmd = [nuclei, "-u", url, "-jsonl", "-silent", "-timeout", str(timeout)]
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    if severity:
        cmd.extend(["-severity", severity])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
    except (subprocess.TimeoutExpired, OSError) as exc:
        _log.debug("nuclei scan failed: %s", exc)
        return []

    raw_results = _parse_nuclei_json(result.stdout)
    findings: list[Finding] = []
    for nr in raw_results:
        info = nr.get("info", {})
        sev = _NUCLEI_SEVERITY_MAP.get(
            info.get("severity", "medium").lower(), Severity.MEDIUM,
        )
        matcher = nr.get("matcher-name", "")
        template_id = nr.get("template-id", "")

        trace: tuple[TraceFrame, ...] = (
            TraceFrame(kind="source", label=f"nuclei probe at {url}", line=1),
            TraceFrame(kind="sink", label=f"template `{template_id}`", line=1),
        )

        findings.append(Finding(
            category="security",
            severity=sev,
            title=f"[nuclei] {info.get('name', template_id)}",
            description=(
                f"Nuclei detected {info.get('name', template_id)} on {url}. "
                f"{info.get('description', '')} (matcher: {matcher})"
            ),
            line=1,
            suggestion=info.get("remediation", "Review the nuclei finding and apply the recommended fix."),
            rule_id=f"nuclei/{template_id}",
            cwe=_nuclei_cwe(info),
            agent="nuclei",
            confidence=0.90,
            analysis_kind="nuclei-probe",
            trace=trace,
        ))
    return findings


def _nuclei_cwe(info: dict) -> Optional[str]:
    """Map nuclei classification to CWE."""
    classification = info.get("classification", {})
    cwe_ids = classification.get("cwe-id", [])
    if cwe_ids:
        return cwe_ids[0] if isinstance(cwe_ids[0], str) else f"CWE-{cwe_ids[0]}"
    return None


def run_nuclei_on_file(
    filepath: str | Path,
    *,
    templates: Optional[list[str]] = None,
    tags: Optional[list[str]] = None,
) -> list[Finding]:
    """Run nuclei templates against source/config files."""
    nuclei = _find_nuclei()
    if not nuclei:
        return []

    cmd = [nuclei, "-target", str(filepath), "-jsonl", "-silent"]
    if templates:
        for t in templates:
            cmd.extend(["-t", t])
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError) as exc:
        _log.debug("nuclei file scan failed: %s", exc)
        return []

    raw_results = _parse_nuclei_json(result.stdout)
    findings: list[Finding] = []
    for nr in raw_results:
        info = nr.get("info", {})
        findings.append(Finding(
            category="security",
            severity=_NUCLEI_SEVERITY_MAP.get(info.get("severity", "medium").lower(), Severity.MEDIUM),
            title=f"[nuclei] {info.get('name', '')}",
            description=f"Nuclei file scan: {info.get('description', '')}",
            line=nr.get("line", 1),
            suggestion=info.get("remediation", ""),
            rule_id=f"nuclei/{nr.get('template-id', 'unknown')}",
            cwe=_nuclei_cwe(info),
            agent="nuclei",
            confidence=0.85,
            analysis_kind="nuclei-file-scan",
            trace=(),
        ))
    return findings


def is_available() -> bool:
    """Check if nuclei is installed and available."""
    return _find_nuclei() is not None
