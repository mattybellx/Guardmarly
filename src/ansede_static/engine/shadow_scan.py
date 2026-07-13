"""
ansede_static.engine.shadow_scan
─────────────────────────────────
Parallel simplified "shadow" analysis engine for failure attribution.

Runs a lightweight pattern-only scan alongside the full IFDS analysis
and diffs the results to attribute every FN/FP to a specific analyzer gap.

Architecture:
  1. Shadow scan uses regex/pattern rules only (no IFDS, no taint tracking)
  2. Diff produces four categories per finding:
     - "both_hit"    → both engines found it (high confidence)
     - "ifds_only"   → only IFDS found it (potential FP from false flow)
     - "shadow_only" → only shadow found it (potential FN from broken flow)
     - "both_miss"   → neither found it (gap in both approaches)
  3. Attribution links each FP/FN to the closest rule, heuristic, or flow break

Zero-dependency; used by --dump-failures and --diagnostics modes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ansede_static._types import Finding

# ── Shadow pattern catalog ──────────────────────────────────────────────────
# Each entry is (cwe, severity, regex) — deliberately simpler than IFDS rules
_SHADOW_PATTERNS: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    # Python patterns
    ("CWE-78", "critical", "shell injection", re.compile(r"shell\s*=\s*True|subprocess\.(?:run|call|Popen|check_output)", re.IGNORECASE)),
    ("CWE-89", "critical", "SQL injection", re.compile(r"(?:execute|cursor)\.\s*(?:execute|executemany)\s*\([^\n]*?(?:\+|%|\.format|f[\"'])", re.IGNORECASE)),
    ("CWE-95", "critical", "eval/exec", re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(", re.IGNORECASE)),
    ("CWE-79", "high", "XSS", re.compile(r"(?:innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML)", re.IGNORECASE)),
    ("CWE-918", "high", "SSRF", re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|axios", re.IGNORECASE)),
    ("CWE-22", "high", "path traversal", re.compile(r"os\.path\.join\s*\(|open\s*\([^\n]*?(?:request\.|req\.|filename|path)", re.IGNORECASE)),
    ("CWE-601", "medium", "open redirect", re.compile(r"(?:redirect|location\.(?:replace|href))\s*\([^\n]*(?:request\.|req\.|\?)", re.IGNORECASE)),
    ("CWE-502", "critical", "unsafe deserialization", re.compile(r"pickle\.(?:loads|load)\s*\(|yaml\.load\s*\(|marshal\.loads\s*\(", re.IGNORECASE)),
    ("CWE-798", "high", "hardcoded secret", re.compile(r"(?:password|secret|api_key|token)\s*=\s*[\"'][^\n]{6,}", re.IGNORECASE)),
    ("CWE-327", "high", "weak crypto", re.compile(r"hashlib\.(?:md5|sha1)\s*\(|\"md5\"|\"sha1\"|crypto\.createHash\s*\(\s*[\"']md5", re.IGNORECASE)),
    ("CWE-78", "critical", "JS exec", re.compile(r"child_process\.exec\s*\(|\.execSync\s*\(", re.IGNORECASE)),
    ("CWE-89", "critical", "JS SQLi", re.compile(r"(?:query|execute)\s*\(\s*[\"']SELECT|SELECT\s+.+\s*\+\s*", re.IGNORECASE)),
    ("CWE-79", "high", "JS innerHTML", re.compile(r"\.innerHTML\s*=\s*(?![\"']\s*[\"'])", re.IGNORECASE)),
    ("CWE-22", "high", "JS path", re.compile(r"path\.(?:join|resolve)\s*\([^\n]*req\.", re.IGNORECASE)),
    ("CWE-918", "high", "JS SSRF", re.compile(r"axios\.(?:get|post|put|delete)\s*\([^\n]*req\.|\bfetch\s*\([^\n]*req\.", re.IGNORECASE)),
    ("CWE-1333", "medium", "ReDoS", re.compile(r"new\s+RegExp\s*\(\s*[\"'][^\"']*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*])", re.IGNORECASE)),
)


@dataclass
class ShadowMatch:
    """A single shadow-pattern match in source text."""
    cwe: str
    severity: str
    label: str
    line: int
    pattern: str
    snippet: str = ""


@dataclass
class DiffEntry:
    """Attribution result for a single finding."""
    cwe: str
    rule_id: str
    line: int
    category: str  # "both_hit", "ifds_only", "shadow_only"
    real_finding: Finding | None = None
    shadow_match: ShadowMatch | None = None
    attribution: str = ""
    flow_break_at: str = ""  # where taint flow broke (for shadow_only)
    heuristic_trigger: str = ""  # which heuristic triggered (for ifds_only)


@dataclass
class ShadowScanReport:
    """Full diff report between IFDS and shadow scans."""
    file_path: str
    language: str
    total_real: int
    total_shadow: int
    both_hit: list[DiffEntry] = field(default_factory=list)
    ifds_only: list[DiffEntry] = field(default_factory=list)
    shadow_only: list[DiffEntry] = field(default_factory=list)
    unmatched_real: list[Finding] = field(default_factory=list)
    unmatched_shadow: list[ShadowMatch] = field(default_factory=list)

    @property
    def total_diffs(self) -> int:
        return len(self.ifds_only) + len(self.shadow_only)


def _line_of_offset(code: str, offset: int) -> int:
    return code[:offset].count("\n") + 1


def run_shadow_scan(code: str, language: str, *, include_low_confidence: bool = False) -> list[ShadowMatch]:
    """Run pattern-only shadow scan over source code."""
    matches: list[ShadowMatch] = []
    seen: set[tuple[str, int]] = set()

    for cwe, severity, label, pattern in _SHADOW_PATTERNS:
        for match in pattern.finditer(code):
            line = _line_of_offset(code, match.start())
            key = (cwe, line)
            if key in seen:
                continue
            seen.add(key)

            # Extract a short snippet around the match
            start = max(0, match.start() - 20)
            end = min(len(code), match.end() + 40)
            snippet = code[start:end].replace("\n", " ").strip()

            matches.append(ShadowMatch(
                cwe=cwe,
                severity=severity,
                label=label,
                line=line,
                pattern=pattern.pattern[:120],
                snippet=snippet[:120],
            ))

    return matches


def _findings_to_cwe_map(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group findings by (cwe, line)."""
    grouped: dict[str, list[Finding]] = {}
    for f in findings:
        cwe = (f.cwe or "").strip().upper()
        if not cwe.startswith("CWE-"):
            continue
        key = f"{cwe}:{f.line}"
        grouped.setdefault(key, []).append(f)
    return grouped


def _matches_to_cwe_map(matches: list[ShadowMatch]) -> dict[str, ShadowMatch]:
    """Map shadow matches by (cwe, line)."""
    return {f"{m.cwe}:{m.line}": m for m in matches}


def diff_scans(
    real_findings: list[Finding],
    shadow_matches: list[ShadowMatch],
    *,
    file_path: str = "",
    language: str = "",
) -> ShadowScanReport:
    """Diff IFDS findings against shadow-pattern matches with attribution."""

    real_map = _findings_to_cwe_map(real_findings)
    shadow_map = _matches_to_cwe_map(shadow_matches)

    all_keys = set(real_map.keys()) | set(shadow_map.keys())

    both_hit: list[DiffEntry] = []
    ifds_only: list[DiffEntry] = []
    shadow_only: list[DiffEntry] = []
    unmatched_real: list[Finding] = []
    unmatched_shadow: list[ShadowMatch] = []

    for key in sorted(all_keys):
        real_hits = real_map.get(key, [])
        shadow_hit = shadow_map.get(key)

        cwe = key.split(":")[0]
        line = int(key.split(":")[1]) if ":" in key else 0

        if real_hits and shadow_hit:
            both_hit.append(DiffEntry(
                cwe=cwe,
                rule_id=real_hits[0].rule_id or "",
                line=line,
                category="both_hit",
                real_finding=real_hits[0],
                shadow_match=shadow_hit,
                attribution="Both engines detected this pattern — high confidence.",
            ))
        elif real_hits and not shadow_hit:
            entry = DiffEntry(
                cwe=cwe,
                rule_id=real_hits[0].rule_id or "",
                line=line,
                category="ifds_only",
                real_finding=real_hits[0],
                attribution="",
                heuristic_trigger=real_hits[0].analysis_kind or "unknown",
            )
            _attribute_ifds_only(entry, real_hits[0])
            ifds_only.append(entry)
        elif shadow_hit and not real_hits:
            entry = DiffEntry(
                cwe=cwe,
                rule_id="",
                line=line,
                category="shadow_only",
                shadow_match=shadow_hit,
                attribution="",
            )
            _attribute_shadow_only(entry, shadow_hit)
            shadow_only.append(entry)

    # Collect completely unmatched findings (no CWE or line overlap at all)
    real_seen_keys = {f"{f.cwe}:{f.line}" for f in real_findings if (f.cwe or "").startswith("CWE-")}
    shadow_seen_keys = {f"{m.cwe}:{m.line}" for m in shadow_matches}
    for f in real_findings:
        key = f"{f.cwe or ''}:{f.line}"
        if key not in real_seen_keys:
            unmatched_real.append(f)
    for m in shadow_matches:
        key = f"{m.cwe}:{m.line}"
        if key not in shadow_seen_keys:
            unmatched_shadow.append(m)

    return ShadowScanReport(
        file_path=file_path,
        language=language,
        total_real=len(real_findings),
        total_shadow=len(shadow_matches),
        both_hit=both_hit,
        ifds_only=ifds_only,
        shadow_only=shadow_only,
        unmatched_real=unmatched_real,
        unmatched_shadow=unmatched_shadow,
    )


def _attribute_ifds_only(entry: DiffEntry, finding: Finding) -> None:
    """Attribute an IFDS-only finding to the heuristic that triggered it."""
    analysis_kind = getattr(finding, "analysis_kind", "") or ""
    agent = getattr(finding, "agent", "") or ""

    if analysis_kind == "pattern":
        entry.attribution = (
            f"Triggered by pattern rule {entry.rule_id} — shadow pattern missed this variant. "
            "Likely a legitimate finding the shadow scanner is too simple to catch."
        )
    elif "taint" in analysis_kind or "flow" in analysis_kind:
        entry.attribution = (
            f"Triggered by taint/flow analysis ({analysis_kind}) via {agent}. "
            "Shadow scan cannot track interprocedural flow. "
            "Verify the flow is not a false positive by checking source/sink connectivity."
        )
    elif "guard" in analysis_kind.lower() or "auth" in analysis_kind.lower():
        entry.attribution = (
            f"Triggered by guard/auth analysis ({analysis_kind}) via {agent}. "
            "Shadow scan has no concept of framework authentication. "
            "Verify the route is actually unprotected."
        )
    elif "minified" in analysis_kind.lower():
        entry.attribution = (
            "Triggered by minified-heuristic on bundled code. "
            "Shadow scan uses similar regex heuristics — this may be an overlapping hit. "
            "Check if source-map resolution could improve confidence."
        )
    else:
        entry.attribution = (
            f"IFDS-only finding ({analysis_kind or 'unknown kind'}) not matched by shadow patterns. "
            "Review the finding for false-positive potential, especially if the flow crosses "
            "multiple files or framework boundaries."
        )


def _attribute_shadow_only(entry: DiffEntry, match: ShadowMatch) -> None:
    """Attribute a shadow-only match to where the IFDS engine likely lost the flow."""
    entry.attribution = (
        f"Shadow pattern '{match.label}' ({match.pattern[:60]}...) matched at line {match.line} "
        f"but the IFDS engine did not produce a finding for {match.cwe}. "
        "Likely causes: (1) taint flow broke at a function call boundary, "
        "(2) sanitizer/safe-pattern false-suppression, "
        "(3) source not recognized as user-controllable input, "
        "(4) sink not in the IFDS sink catalog."
    )
    entry.flow_break_at = (
        f"Shadow hit at line {match.line}: {match.snippet}. "
        "Investigate: is this a true source→sink flow that IFDS should track? "
        "Check if the source is recognized (request, req, input), "
        "and if the sink is in the IFDS sink catalog."
    )


def generate_shadow_report(
    code: str,
    real_findings: list[Finding],
    *,
    file_path: str = "",
    language: str = "",
) -> ShadowScanReport:
    """Run shadow scan and diff against real findings — one-call API."""
    shadow_matches = run_shadow_scan(code, language)
    return diff_scans(real_findings, shadow_matches, file_path=file_path, language=language)


def shadow_report_to_dict(report: ShadowScanReport) -> dict[str, Any]:
    """Serialize a ShadowScanReport to a JSON-serializable dict."""
    def _finding_dict(f: Finding | None) -> dict[str, Any] | None:
        if f is None:
            return None
        return {
            "cwe": f.cwe,
            "rule_id": f.rule_id,
            "severity": f.severity,
            "title": f.title,
            "line": f.line,
            "analysis_kind": getattr(f, "analysis_kind", ""),
            "agent": getattr(f, "agent", ""),
            "confidence": getattr(f, "confidence", None),
        }

    def _shadow_dict(m: ShadowMatch | None) -> dict[str, Any] | None:
        if m is None:
            return None
        return {
            "cwe": m.cwe,
            "severity": m.severity,
            "label": m.label,
            "line": m.line,
            "pattern": m.pattern,
            "snippet": m.snippet,
        }

    return {
        "file_path": report.file_path,
        "language": report.language,
        "total_real": report.total_real,
        "total_shadow": report.total_shadow,
        "total_diffs": report.total_diffs,
        "both_hit": [
            {
                "cwe": e.cwe,
                "rule_id": e.rule_id,
                "line": e.line,
                "category": e.category,
                "real_finding": _finding_dict(e.real_finding),
                "shadow_match": _shadow_dict(e.shadow_match),
                "attribution": e.attribution,
            }
            for e in report.both_hit
        ],
        "ifds_only": [
            {
                "cwe": e.cwe,
                "rule_id": e.rule_id,
                "line": e.line,
                "category": e.category,
                "real_finding": _finding_dict(e.real_finding),
                "attribution": e.attribution,
                "heuristic_trigger": e.heuristic_trigger,
            }
            for e in report.ifds_only
        ],
        "shadow_only": [
            {
                "cwe": e.cwe,
                "line": e.line,
                "category": e.category,
                "shadow_match": _shadow_dict(e.shadow_match),
                "attribution": e.attribution,
                "flow_break_at": e.flow_break_at,
            }
            for e in report.shadow_only
        ],
    }
