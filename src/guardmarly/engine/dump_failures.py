"""
guardmarly.engine.dump_failures
────────────────────────────────────
Production failure-attribution diagnostic engine.

For every False Negative (FN) and False Positive (FP), produces:
  - Attribution: where the taint flow broke or which heuristic misfired
  - Shadow scan comparison: could a simpler pattern engine have caught it?
  - CWE educational link: references engine/explain.py for remediation
  - Suggested fix: concrete action to close the gap (add sink/source/guard)

Integrated with:
  - benchmarks/web_wild_harness.py via --dump-failures
  - CLI via --diagnostics mode
  - shadow_scan.py for parallel diff analysis

Zero-dependency; produces machine-parseable JSON diagnostics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardmarly._types import Finding
from guardmarly.engine.explain import get_explanation
from guardmarly.engine.shadow_scan import (
    ShadowMatch,
    run_shadow_scan,
    diff_scans,
    shadow_report_to_dict,
)


@dataclass
class FailureAttribution:
    """Detailed attribution for a single FN or FP."""
    kind: str  # "false_negative" or "false_positive"
    cwe: str
    finding_or_label: dict[str, Any]  # the finding (FP) or expected label (FN)
    attribution: str  # human-readable reason
    shadow_analysis: dict[str, Any] | None = None  # shadow-scan diff if available
    cwe_explanation: str = ""  # from explain.py
    suggested_fix: str = ""  # concrete action
    confidence: float = 0.0  # confidence in the attribution


@dataclass
class FailureDiagnosticReport:
    """Complete diagnostic report for a benchmark run."""
    file_path: str
    language: str
    ground_truth_cwes: set[str] = field(default_factory=set)
    false_negatives: list[FailureAttribution] = field(default_factory=list)
    false_positives: list[FailureAttribution] = field(default_factory=list)
    shadow_report: dict[str, Any] | None = None
    summary: dict[str, Any] = field(default_factory=dict)


# ── Sink catalog (for FN attribution) ────────────────────────────────────────
_SINK_CATALOG: dict[str, list[str]] = {
    "CWE-78": ["subprocess.run", "subprocess.call", "subprocess.Popen", "os.system",
               "child_process.exec", "child_process.execSync", "exec(", "shell=True"],
    "CWE-89": ["execute(", "executemany(", "query(", "raw(", ".raw("],
    "CWE-79": ["innerHTML", "document.write", "dangerouslySetInnerHTML",
               "render(", "send(", "Response("],
    "CWE-918": ["requests.get", "requests.post", "requests.put", "requests.delete",
                "fetch(", "axios.get", "axios.post", "httpx.get"],
    "CWE-22": ["open(", "os.path.join", "path.join", "fs.readFile", "fs.writeFile"],
    "CWE-95": ["eval(", "exec(", "compile(", "new Function(", "vm.runInThisContext"],
    "CWE-502": ["pickle.loads", "pickle.load", "yaml.load(", "marshal.loads"],
    "CWE-639": ["get(", "filter(", "find(", "findById", "findOne", "query("],
    "CWE-862": [],  # missing auth — no specific sink
    "CWE-352": [],  # CSRF — no specific sink
    "CWE-601": ["redirect(", "res.redirect", "location.href", "location.replace"],
    "CWE-307": [],  # rate limiting — no specific sink
    "CWE-1333": ["new RegExp(", "/pattern/"],
}

# ── Source catalog ───────────────────────────────────────────────────────────
_SOURCE_CATALOG: dict[str, list[str]] = {
    "python": ["request.args", "request.form", "request.json", "request.data",
               "request.GET", "request.POST", "sys.argv", "input(", "environ["],
    "javascript": ["req.body", "req.query", "req.params", "req.url",
                   "request.body", "request.query", "request.params",
                   "req.headers", "request.headers"],
}


def _find_snippet_around_line(code: str, line: int, context: int = 3) -> str:
    """Extract lines around a given line number for context."""
    lines = code.split("\n")
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    return "\n".join(
        f"{'>>>' if i == line - 1 else '   '} {i + 1}: {lines[i]}"
        for i in range(start, end)
    )


def attribute_false_negative(
    cwe: str,
    code: str,
    line: int,
    language: str,
    *,
    shadow_matches: list[ShadowMatch] | None = None,
) -> FailureAttribution:
    """Attribute a false negative: why did the IFDS engine miss this?"""

    sinks = _SINK_CATALOG.get(cwe, [])
    sources = _SOURCE_CATALOG.get(language, [])

    # Check if shadow scan caught it
    shadow_caught = False
    shadow_detail: dict[str, Any] | None = None
    if shadow_matches is not None:
        for m in shadow_matches:
            if m.cwe == cwe and abs(m.line - line) <= 5:
                shadow_caught = True
                shadow_detail = {
                    "matched": True,
                    "cwe": m.cwe,
                    "line": m.line,
                    "pattern": m.pattern,
                    "snippet": m.snippet,
                }
                break
        if shadow_detail is None:
            shadow_detail = {"matched": False, "reason": "Shadow scan also missed this pattern"}

    # Build attribution
    snippet = _find_snippet_around_line(code, line)

    if shadow_caught:
        attribution = (
            f"FN: {cwe} at line {line}. Shadow pattern scan CAUGHT this but IFDS missed it. "
            "The regex pattern is visible in the source, but the IFDS taint flow may have broken "
            "due to: (1) source not recognized as user-controllable, "
            "(2) sink not in IFDS catalog, or (3) flow broken at an interprocedural boundary."
        )
        suggested = (
            f"Check if any of these sinks are present: {', '.join(sinks[:5]) or 'N/A'}. "
            f"Check if any of these sources are present: {', '.join(sources[:5] or ['N/A'])}. "
            "If a source/sink exists but is not in the catalog, add it to the IFDS sink/source lists."
        )
    else:
        attribution = (
            f"FN: {cwe} at line {line}. Neither IFDS nor shadow scan caught this. "
            "This pattern may require: (1) a new rule, (2) framework-specific semantics, "
            "or (3) multi-file interprocedural tracking beyond current capabilities."
        )
        suggested = (
            f"Review if this is truly exploitable. If so, add a new rule targeting this pattern. "
            f"Expected sinks for {cwe}: {', '.join(sinks[:5] or ['none catalogued'])}. "
            "Consider a custom community rule via ~/.guardmarly/community_rules/."
        )

    return FailureAttribution(
        kind="false_negative",
        cwe=cwe,
        finding_or_label={"cwe": cwe, "line": line, "snippet": snippet},
        attribution=attribution,
        shadow_analysis=shadow_detail,
        cwe_explanation=get_explanation(cwe),
        suggested_fix=suggested,
        confidence=0.85 if shadow_caught else 0.60,
    )


def attribute_false_positive(
    finding: Finding,
    code: str,
    *,
    shadow_matches: list[ShadowMatch] | None = None,
) -> FailureAttribution:
    """Attribute a false positive: why did the IFDS engine produce a spurious finding?"""

    cwe = (finding.cwe or "").strip().upper()
    analysis_kind = getattr(finding, "analysis_kind", "") or ""
    agent = getattr(finding, "agent", "") or ""

    # Check if shadow scan also produced this (would suggest it's not purely IFDS noise)
    shadow_also = False
    shadow_detail: dict[str, Any] | None = None
    if shadow_matches is not None:
        for m in shadow_matches:
            if m.cwe == cwe and abs(m.line - finding.line) <= 3:
                shadow_also = True
                shadow_detail = {
                    "matched": True,
                    "cwe": m.cwe,
                    "line": m.line,
                    "pattern": m.pattern,
                    "note": "Shadow scan also flagged this — may be a legitimate finding mislabeled as FP",
                }
                break
        if shadow_detail is None:
            shadow_detail = {"matched": False, "reason": "Shadow scan did NOT flag this — likely IFDS noise"}

    snippet = _find_snippet_around_line(code, finding.line)

    # Attribution by analysis kind
    if "taint" in analysis_kind.lower() or "flow" in analysis_kind.lower():
        if shadow_also:
            attribution = (
                f"FP: {cwe} at line {finding.line} (taint analysis). Shadow scan also flagged this — "
                "this may actually be a TRUE POSITIVE mislabeled as FP in the benchmark. "
                "Review the ground-truth label carefully."
            )
            suggested = "Re-examine ground truth label. If this IS exploitable, reclassify as TP."
            confidence = 0.30
        else:
            attribution = (
                f"FP: {cwe} at line {finding.line} (taint analysis). IFDS tracked a flow that shadow "
                "scan did not. Likely a false flow — the source may not actually reach the sink due to "
                "unmodeled sanitization, framework guards, or dead code paths."
            )
            suggested = (
                "Add a path-sensitive guard check: verify the flow with AST-upward analysis. "
                "Consider adding a sanitizer pattern to the safe-pattern detector."
            )
            confidence = 0.80
    elif "guard" in analysis_kind.lower() or "auth" in analysis_kind.lower():
        attribution = (
            f"FP: {cwe} at line {finding.line} (guard/auth analysis). The engine flagged this "
            "as missing a security check, but a framework-level guard may be applied at a higher scope "
            "(middleware, class decorator, router-level protection) that the line-level analysis missed."
        )
        suggested = (
            "Extend framework semantic models to recognize this guard pattern. "
            "For Django: check class-level mixins. For Express: check app-level middleware. "
            "For Nest.js: check @UseGuards on the controller class."
        )
        confidence = 0.75
    elif "pattern" in analysis_kind.lower():
        attribution = (
            f"FP: {cwe} at line {finding.line} (pattern rule). The regex pattern matched but the "
            "context (test file, mock, dead code, library code) makes this a false positive. "
            "Pattern rules lack contextual awareness."
        )
        suggested = (
            "Add context suppression: check if file is in test/mock/generated directory. "
            "Consider adding a more specific pattern that excludes this false match."
        )
        confidence = 0.90
    else:
        attribution = (
            f"FP: {cwe} at line {finding.line} ({analysis_kind or 'unknown'}). Could not "
            "determine exact trigger mechanism."
        )
        suggested = "Add analysis_kind attribution to this rule for better diagnostics."
        confidence = 0.50

    finding_dict: dict[str, Any] = {
        "cwe": finding.cwe,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title or "",
        "line": finding.line,
        "analysis_kind": analysis_kind,
        "agent": agent,
        "snippet": snippet,
    }

    return FailureAttribution(
        kind="false_positive",
        cwe=cwe,
        finding_or_label=finding_dict,
        attribution=attribution,
        shadow_analysis=shadow_detail,
        cwe_explanation=get_explanation(cwe),
        suggested_fix=suggested,
        confidence=confidence,
    )


def run_failure_diagnostics(
    code: str,
    findings: list[Finding],
    ground_truth_cwes: set[str],
    *,
    file_path: str = "",
    language: str = "",
    expected_cwe_line_map: dict[str, int] | None = None,
) -> FailureDiagnosticReport:
    """Run full failure diagnostics: attribute all FNs and FPs."""

    shadow_matches = run_shadow_scan(code, language)
    shadow_report = diff_scans(findings, shadow_matches, file_path=file_path, language=language)

    found_cwes: set[str] = {f.cwe or "" for f in findings if (f.cwe or "").startswith("CWE-")}

    # False negatives: in ground truth but not found
    false_negatives: list[FailureAttribution] = []
    for cwe in sorted(ground_truth_cwes - found_cwes):
        line = (expected_cwe_line_map or {}).get(cwe, 0)
        fn_attr = attribute_false_negative(
            cwe, code, line, language, shadow_matches=shadow_matches
        )
        false_negatives.append(fn_attr)

    # False positives: found but not in ground truth (simplified: findings with no ground-truth CWE)
    false_positives: list[FailureAttribution] = []
    for finding in findings:
        cwe = (finding.cwe or "").strip().upper()
        if cwe and cwe not in ground_truth_cwes:
            fp_attr = attribute_false_positive(finding, code, shadow_matches=shadow_matches)
            false_positives.append(fp_attr)

    summary = {
        "total_findings": len(findings),
        "ground_truth_cwes": sorted(ground_truth_cwes),
        "found_cwes": sorted(found_cwes),
        "false_negatives_count": len(false_negatives),
        "false_positives_count": len(false_positives),
        "shadow_total_real": shadow_report.total_real,
        "shadow_total_shadow": shadow_report.total_shadow,
        "shadow_both_hit": len(shadow_report.both_hit),
        "shadow_ifds_only": len(shadow_report.ifds_only),
        "shadow_shadow_only": len(shadow_report.shadow_only),
    }

    return FailureDiagnosticReport(
        file_path=file_path,
        language=language,
        ground_truth_cwes=ground_truth_cwes.copy(),
        false_negatives=false_negatives,
        false_positives=false_positives,
        shadow_report=shadow_report_to_dict(shadow_report),
        summary=summary,
    )


def diagnostic_report_to_dict(report: FailureDiagnosticReport) -> dict[str, Any]:
    """Serialize a FailureDiagnosticReport to a JSON-serializable dict."""
    return {
        "file_path": report.file_path,
        "language": report.language,
        "ground_truth_cwes": sorted(report.ground_truth_cwes),
        "false_negatives": [
            {
                "kind": fn.kind,
                "cwe": fn.cwe,
                "finding_or_label": fn.finding_or_label,
                "attribution": fn.attribution,
                "shadow_analysis": fn.shadow_analysis,
                "cwe_explanation": fn.cwe_explanation[:300] if fn.cwe_explanation else "",
                "suggested_fix": fn.suggested_fix,
                "confidence": fn.confidence,
            }
            for fn in report.false_negatives
        ],
        "false_positives": [
            {
                "kind": fp.kind,
                "cwe": fp.cwe,
                "finding_or_label": fp.finding_or_label,
                "attribution": fp.attribution,
                "shadow_analysis": fp.shadow_analysis,
                "cwe_explanation": fp.cwe_explanation[:300] if fp.cwe_explanation else "",
                "suggested_fix": fp.suggested_fix,
                "confidence": fp.confidence,
            }
            for fp in report.false_positives
        ],
        "shadow_report": report.shadow_report,
        "summary": report.summary,
    }


def dump_failures_json(
    code: str,
    findings: list[Finding],
    ground_truth_cwes: set[str],
    *,
    file_path: str = "",
    language: str = "",
    expected_cwe_line_map: dict[str, int] | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run diagnostics and optionally write to a JSON file."""
    report = run_failure_diagnostics(
        code, findings, ground_truth_cwes,
        file_path=file_path, language=language,
        expected_cwe_line_map=expected_cwe_line_map,
    )
    result = diagnostic_report_to_dict(report)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        print(json.dumps(result, indent=2))

    return result
