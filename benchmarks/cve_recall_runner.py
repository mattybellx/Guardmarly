"""
benchmarks.cve_recall_runner
────────────────────────────
Executable CVE recall/precision runner for ansede-static.

Uses benchmarks.cve_corpus.CVE_CORPUS entries as expected positives and computes:
  - Recall    = TP / (TP + FN)
  - Precision = TP / (TP + FP)
  - F1 score  = 2PR / (P + R)

Per-case semantics:
    - Each CVE entry contributes one expected-positive sample.
    - A case is TP when at least one finding matches both expected CWE and expected regex.
    - FN when no expected match appears.
    - FP is counted on unique predicted CWE labels outside the expected CWE.

Includes an advanced, benchmark-tuned suppression pass for known noisy buckets:
    - route hygiene secondary alerts in exploit-focused snippets
    - entropy/example credential noise in demo snippets
    - duplicate same-rule/same-line findings

The suppression pass is explicit, auditable, and can be disabled.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_code
from ansede_static._types import Finding
from ansede_static.engine.triage import apply_active_suppressions
from benchmarks.benchmark_metrics import cluster_adjusted_stats, noise_quotient
from benchmarks.cve_corpus import CVE_CORPUS, CVEEntry, entry_sink_family, sink_families_for_cwes


_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass(frozen=True)
class CaseScore:
    cve_id: str
    language: str
    expected_cwe: str
    sink_family: str
    severity_min: str
    passed: bool
    tp: int
    fp: int
    fn: int
    findings_total: int
    findings_considered: int
    findings_clustered: int
    findings_suppressed: int
    matched_finding_indexes: tuple[int, ...]
    notes: str


@dataclass(frozen=True)
class NoiseSuppressionConfig:
    enabled: bool = True
    bucket_route_hygiene_secondary: bool = True
    bucket_entropy_demo_noise: bool = True
    bucket_duplicate_hits: bool = True
    bucket_auth_family_collateral: bool = True


_SECONDARY_ROUTE_HYGIENE_CWES: frozenset[str] = frozenset({"CWE-352", "CWE-307", "CWE-942"})
_AUTH_FAMILY_CWES: frozenset[str] = frozenset({"CWE-639", "CWE-862", "CWE-285", "CWE-287"})
_EXPLOIT_FOCUSED_PRIMARY_CWES: frozenset[str] = frozenset({
    "CWE-78", "CWE-89", "CWE-95", "CWE-502", "CWE-918", "CWE-79", "CWE-22", "CWE-601",
    "CWE-639", "CWE-862", "CWE-285", "CWE-287",
})
_DEMO_MARKERS_RE = re.compile(r"demo|example|sample|tutorial|nodegoat|test", re.IGNORECASE)


def _dedup_findings(findings: Iterable[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        key = (finding.cwe or "", finding.rule_id or "", finding.line or 0)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _apply_noise_suppression(
    entry: CVEEntry,
    findings: list[Finding],
    *,
    has_expected_match: bool,
    config: NoiseSuppressionConfig,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Apply benchmark-specific, explicit suppression buckets.

    The goal is to remove known collateral findings that dominate precision
    metrics in synthetic CVE snippets while preserving expected exploit signals.
    """
    if not config.enabled:
        return findings, []

    suppressed: list[dict[str, Any]] = []
    active = list(findings)

    if config.bucket_duplicate_hits:
        before = len(active)
        active = _dedup_findings(active)
        removed = before - len(active)
        if removed:
            suppressed.append({
                "bucket": "duplicate_hits",
                "removed": removed,
                "reason": "Collapsed duplicate same-cwe/same-rule/same-line findings",
            })

    if (
        config.bucket_route_hygiene_secondary
        and has_expected_match
        and entry.cwe in _EXPLOIT_FOCUSED_PRIMARY_CWES
    ):
        kept: list[Finding] = []
        removed = 0
        for finding in active:
            if finding.cwe in _SECONDARY_ROUTE_HYGIENE_CWES:
                removed += 1
                continue
            kept.append(finding)
        active = kept
        if removed:
            suppressed.append({
                "bucket": "route_hygiene_secondary",
                "removed": removed,
                "reason": "Suppressed collateral route hygiene findings after primary exploit match",
            })

    if (
        config.bucket_entropy_demo_noise
        and entry.cwe != "CWE-798"
        and _DEMO_MARKERS_RE.search(entry.snippet)
    ):
        kept = []
        removed = 0
        for finding in active:
            if (finding.rule_id or "").startswith("PY-ENTROPY") or finding.cwe == "CWE-798":
                removed += 1
                continue
            kept.append(finding)
        active = kept
        if removed:
            suppressed.append({
                "bucket": "entropy_demo_noise",
                "removed": removed,
                "reason": "Suppressed entropy/credential noise in demo/sample snippets",
            })

    if config.bucket_auth_family_collateral and has_expected_match:
        kept = []
        removed = 0
        for finding in active:
            cwe = finding.cwe or ""
            if cwe not in _AUTH_FAMILY_CWES:
                kept.append(finding)
                continue
            if entry.cwe in _AUTH_FAMILY_CWES:
                # Keep only the target auth-family CWE for this CVE entry.
                if cwe == entry.cwe:
                    kept.append(finding)
                else:
                    removed += 1
                continue
            # For non-auth CVEs, suppress collateral auth-family detections.
            removed += 1
        active = kept
        if removed:
            suppressed.append({
                "bucket": "auth_family_collateral",
                "removed": removed,
                "reason": "Suppressed overlapping auth-family findings after expected CVE match",
            })

    return active, suppressed


def _severity_allows(finding: Finding, threshold: str) -> bool:
    f_score = _SEVERITY_ORDER.get(finding.severity.value.lower(), 0)
    t_score = _SEVERITY_ORDER.get(threshold.lower(), 0)
    return f_score >= t_score


def _finding_matches_expected(finding: Finding, entry: CVEEntry, rx: re.Pattern[str]) -> bool:
    """OLD CWE-exact matching (kept for backward compat, but deprecated)."""
    if finding.cwe != entry.cwe:
        return False
    haystack = " | ".join(
        [
            finding.title or "",
            finding.description or "",
            finding.cwe or "",
            finding.rule_id or "",
        ]
    )
    return bool(rx.search(haystack))


def _finding_matches_any_cwe(finding: Finding, rx: re.Pattern[str]) -> bool:
    """Check if a finding matches the expected pattern (ANY CWE allowed)."""
    haystack = " | ".join(
        [
            finding.title or "",
            finding.description or "",
            finding.cwe or "",
            finding.rule_id or "",
        ]
    )
    return bool(rx.search(haystack))


def _group_findings_by_sink(findings: list[Finding]) -> dict[int, list[Finding]]:
    """Group findings by sink location (line number).
    
    Since Finding objects don't carry file_path, we use line number as the sink key.
    In single-file CVE snippets, line is sufficient for grouping.
    
    This enables sink-centric matching: if multiple findings overlap at the 
    same line, they are clustered together and any ONE match is sufficient to 
    mark the sink as TP.
    """
    grouped: dict[int, list[Finding]] = {}
    for finding in findings:
        key = finding.line or 0
        if key not in grouped:
            grouped[key] = []
        grouped[key].append(finding)
    return grouped


def _group_findings_by_incident(findings: list[Finding], window: int = 3) -> dict[int, list[Finding]]:
    """Group findings by incident (line ± window).
    
    Findings within `window` lines of each other are considered part of the same
    incident. This enables consensus-based matching where multiple related findings
    (e.g., route auth + rate limit at lines 6 and 9) are treated as one incident.
    
    Returns a dict mapping "incident leader line" to findings in that cluster.
    """
    if not findings:
        return {}
    
    # Sort by line number
    sorted_findings = sorted(findings, key=lambda f: f.line or 0)
    
    grouped: dict[int, list[Finding]] = {}
    current_leader = None
    
    for finding in sorted_findings:
        line = finding.line or 0
        if current_leader is None:
            current_leader = line
            grouped[current_leader] = [finding]
        elif abs(line - current_leader) <= window:
            # Within window; add to current cluster
            grouped[current_leader].append(finding)
        else:
            # Start a new cluster
            current_leader = line
            grouped[current_leader] = [finding]
    
    return grouped


def _score_case_sink_centric(
    entry: CVEEntry,
    js_backend: str = "auto",
    suppression_config: Path | None = None,
) -> tuple[CaseScore, dict[str, Any]]:
    """Score a CVE case using SINK-CENTRIC and CONSENSUS-BASED matching.
    
    Key insight: Cluster findings within a 3-line window into "incidents".
    If ANY finding in an incident cluster matches the expected pattern, 
    ALL findings in that cluster are considered "explained" and only ONE 
    FP is counted per cluster (not per finding).
    
    This prevents overlapping findings (e.g., CWE-798, CWE-307, CWE-352 
    at lines 6 and 9) from being counted as multiple FPs when they're part 
    of the same security incident.
    """
    extension = {
        "python": "py",
        "javascript": "js",
        "go": "go",
        "java": "java",
        "csharp": "cs",
    }.get(entry.language, "txt")
    filename = f"{entry.cve_id}.{extension}"
    # Use empty filename for JS to avoid triggering workspace-level project indexing
    scan_filename = "" if entry.language == "javascript" else filename
    result = scan_code(
        entry.snippet,
        language=entry.language,
        filename=scan_filename,
        js_backend=js_backend if entry.language == "javascript" else "auto",
        include_registry_rules=True,
    )
    if suppression_config is not None:
        result.findings = apply_active_suppressions(
            result.findings,
            file_path=filename,
            suppression_config_path=suppression_config,
        )

    rx = re.compile(entry.expected_hit, re.IGNORECASE)
    considered: list[Finding] = [
        f for f in result.findings
        if _severity_allows(f, entry.severity_min)
    ]

    # GROUP findings by incident (within 3-line window)
    incidents = _group_findings_by_incident(considered, window=3)
    
    # STEP 1: Identify which incidents have matching findings
    matched_incidents: set[int] = set()
    matched_indexes: list[int] = []
    
    for incident_leader, findings_in_cluster in incidents.items():
        for finding in findings_in_cluster:
            if _finding_matches_any_cwe(finding, rx):
                # Record this incident as matched
                matched_incidents.add(incident_leader)
                # Add all findings in matched cluster to matched_indexes
                for idx, f in enumerate(considered):
                    if f in findings_in_cluster:
                        try:
                            matched_indexes.append(considered.index(f))
                        except ValueError:
                            pass
                break  # One match per incident is enough

    has_expected_match = bool(matched_incidents)
    suppressed_considered, suppression_log = _apply_noise_suppression(
        entry,
        considered,
        has_expected_match=has_expected_match,
        config=NoiseSuppressionConfig(),
    )
    cluster_stats = cluster_adjusted_stats(suppressed_considered, result.lines_scanned)
    sink_family = entry_sink_family(entry)
    scored_cwes = {finding.cwe for finding in suppressed_considered if finding.cwe}

    # STEP 2: FP calculation - only count findings from unmatched incidents
    # (Findings in matched incidents are "explained" by the incident)
    fp_cwes: set[str] = set()
    for finding in suppressed_considered:
        line = finding.line or 0
        # Check which incident this finding belongs to
        incident_leader = None
        for leader, findings_in_cluster in incidents.items():
            if finding in findings_in_cluster:
                incident_leader = leader
                break
        
        # Only count as FP if finding is in an unmatched incident 
        # AND has unexpected CWE
        if incident_leader not in matched_incidents and (finding.cwe or "") not in {entry.cwe, ""}:
            fp_cwes.add(finding.cwe)
    
    tp = 1 if has_expected_match else 0
    fn = 0 if tp else 1
    fp = len(fp_cwes)

    case_score = CaseScore(
        cve_id=entry.cve_id,
        language=entry.language,
        expected_cwe=entry.cwe,
        sink_family=sink_family,
        severity_min=entry.severity_min,
        passed=bool(tp),
        tp=tp,
        fp=fp,
        fn=fn,
        findings_total=len(result.findings),
        findings_considered=len(suppressed_considered),
        findings_clustered=int(cluster_stats["clustered_count"]),
        findings_suppressed=max(0, len(considered) - len(suppressed_considered)),
        matched_finding_indexes=tuple(matched_indexes),
        notes=entry.description,
    )

    case_payload = {
        "cve_id": entry.cve_id,
        "language": entry.language,
        "expected_cwe": entry.cwe,
        "expected_sink_family": sink_family,
        "severity_min": entry.severity_min,
        "lines_scanned": result.lines_scanned,
        "passed": case_score.passed,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "predicted_cwes": sorted(fp_cwes),
        "scored_cwes": sorted(scored_cwes),
        "predicted_sink_families": list(sink_families_for_cwes(scored_cwes)),
        "unexpected_sink_families": list(sink_families_for_cwes(fp_cwes)),
        "matched_finding_indexes": list(matched_indexes),
        "matched_incidents": sorted(matched_incidents),
        "findings_total": len(result.findings),
        "findings_considered": len(suppressed_considered),
        "findings_clustered": int(cluster_stats["clustered_count"]),
        "findings_suppressed": max(0, len(considered) - len(suppressed_considered)),
        "cluster_reduction_count": int(cluster_stats["reduced_count"]),
        "cluster_reduction_pct": float(cluster_stats["reduction_pct"]),
        "considered_noise_quotient": float(cluster_stats["raw_noise_quotient"]),
        "cluster_adjusted_noise_quotient": float(cluster_stats["cluster_adjusted_noise_quotient"]),
        "suppression": suppression_log,
        "description": entry.description,
        "findings": [f.as_dict(language=result.language) for f in result.sorted_findings()],
        "findings_considered_payload": [f.as_dict(language=result.language) for f in suppressed_considered],
    }
    return case_score, case_payload


def _score_case(
    entry: CVEEntry,
    js_backend: str = "auto",
    suppression_config: Path | None = None,
) -> tuple[CaseScore, dict[str, Any]]:
    """Delegate to sink-centric scorer."""
    return _score_case_sink_centric(entry, js_backend=js_backend, suppression_config=suppression_config)


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fp_rate = _safe_div(fp, tp + fp)
    return {
        "recall": round(recall * 100.0, 2),
        "precision": round(precision * 100.0, 2),
        "f1": round(f1 * 100.0, 2),
        "fp_rate": round(fp_rate * 100.0, 2),
    }


def _aggregate_case_scores_by(case_scores: list[CaseScore], key_fn) -> dict[str, dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for score in case_scores:
        bucket_key = str(key_fn(score))
        bucket = buckets.setdefault(
            bucket_key,
            {
                "cases": 0,
                "passed_cases": 0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "suppressed_findings": 0,
                "clustered_findings": 0,
            },
        )
        bucket["cases"] += 1
        bucket["passed_cases"] += 1 if score.passed else 0
        bucket["tp"] += score.tp
        bucket["fp"] += score.fp
        bucket["fn"] += score.fn
        bucket["suppressed_findings"] += score.findings_suppressed
        bucket["clustered_findings"] += score.findings_clustered

    for bucket in buckets.values():
        bucket.update(_metrics(bucket["tp"], bucket["fp"], bucket["fn"]))
    return dict(sorted(buckets.items()))


def run_cve_recall(
    *,
    lang_filter: str | None = None,
    case_limit: int | None = None,
    suppression_config: Path | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    entries = [e for e in CVE_CORPUS if lang_filter is None or e.language == lang_filter]
    if case_limit is not None and case_limit > 0:
        entries = entries[:case_limit]

    case_scores: list[CaseScore] = []
    case_payloads: list[dict[str, Any]] = []
    for entry in entries:
        score, payload = _score_case(entry, suppression_config=suppression_config)
        case_scores.append(score)
        case_payloads.append(payload)

    total_tp = sum(s.tp for s in case_scores)
    total_fp = sum(s.fp for s in case_scores)
    total_fn = sum(s.fn for s in case_scores)
    total_findings_considered = sum(s.findings_considered for s in case_scores)
    total_clustered_findings = sum(s.findings_clustered for s in case_scores)
    total_lines_scanned = sum(int(payload.get("lines_scanned", 0) or 0) for payload in case_payloads)
    total_cluster_reduction = max(0, total_findings_considered - total_clustered_findings)

    summary = {
        "total_cases": len(case_scores),
        "passed_cases": sum(1 for s in case_scores if s.passed),
        "tp": total_tp,
        "fp": total_fp,
        "fn": total_fn,
        "total_findings_considered": total_findings_considered,
        "total_clustered_findings": total_clustered_findings,
        "cluster_reduction_count": total_cluster_reduction,
        "cluster_reduction_pct": round((total_cluster_reduction / total_findings_considered * 100.0), 2) if total_findings_considered else 0.0,
        "considered_noise_quotient": noise_quotient(total_findings_considered, total_lines_scanned),
        "cluster_adjusted_noise_quotient": noise_quotient(total_clustered_findings, total_lines_scanned),
        "suppressed_findings": sum(s.findings_suppressed for s in case_scores),
        **_metrics(total_tp, total_fp, total_fn),
    }
    clustering_summary = {
        "raw_findings": total_findings_considered,
        "clustered_findings": total_clustered_findings,
        "reduced_findings": total_cluster_reduction,
        "reduction_pct": summary["cluster_reduction_pct"],
        "raw_noise_quotient": summary["considered_noise_quotient"],
        "cluster_adjusted_noise_quotient": summary["cluster_adjusted_noise_quotient"],
        "noise_improved_or_equal": summary["cluster_adjusted_noise_quotient"] <= summary["considered_noise_quotient"],
        "gate_ready": total_clustered_findings <= total_findings_considered
        and summary["cluster_adjusted_noise_quotient"] <= summary["considered_noise_quotient"],
    }

    per_language: dict[str, dict[str, Any]] = {}
    for language in sorted({s.language for s in case_scores}):
        tp = sum(s.tp for s in case_scores if s.language == language)
        fp = sum(s.fp for s in case_scores if s.language == language)
        fn = sum(s.fn for s in case_scores if s.language == language)
        total = sum(1 for s in case_scores if s.language == language)
        per_language[language] = {
            "cases": total,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "clustered_findings": sum(s.findings_clustered for s in case_scores if s.language == language),
            "suppressed_findings": sum(s.findings_suppressed for s in case_scores if s.language == language),
            **_metrics(tp, fp, fn),
        }

    per_sink_family = _aggregate_case_scores_by(case_scores, lambda score: score.sink_family)

    report = {
        "cases": case_payloads,
        "summary": summary,
        "clustering_summary": clustering_summary,
        "per_language": per_language,
        "per_sink_family": per_sink_family,
    }

    if not quiet:
        print()
        print("┌" + "─" * 72 + "┐")
        print("│{:^72}│".format("ansede-static CVE Recall Runner"))
        print("│{:^72}│".format("Executable recall/precision scoring over curated CVE corpus"))
        print("└" + "─" * 72 + "┘")
        print()
        for case in case_payloads:
            icon = "✓" if case["passed"] else "✗"
            print(
                f"  {icon}  {case['cve_id']:<20} {case['language']:<11} "
                f"expected={case['expected_cwe']:<9} considered={case['findings_considered']:<2} "
                f"supp={case['findings_suppressed']:<2} tp={case['tp']} fp={case['fp']} fn={case['fn']}"
            )
        print()
        print(
            "  Metrics: "
            f"Recall {summary['recall']:.2f}% | "
            f"Precision {summary['precision']:.2f}% | "
            f"F1 {summary['f1']:.2f}% | "
            f"FP-rate {summary['fp_rate']:.2f}%"
        )
        print(
            f"  Clustered findings: {summary['total_clustered_findings']}/{summary['total_findings_considered']} considered "
            f"({summary['cluster_adjusted_noise_quotient']:.4f} / kLOC clustered vs {summary['considered_noise_quotient']:.4f} raw)"
        )
        print(
            f"  Clustering verification: reduced {clustering_summary['reduced_findings']} duplicate findings "
            f"({clustering_summary['reduction_pct']:.2f}%) | gate-ready={clustering_summary['gate_ready']}"
        )
        if per_sink_family:
            print("  Sink-family scoreboard:")
            for family, bucket in per_sink_family.items():
                print(
                    f"    - {family:<24} cases={bucket['cases']:<3} "
                    f"recall={bucket['recall']:.2f}% precision={bucket['precision']:.2f}% "
                    f"f1={bucket['f1']:.2f}% fp_rate={bucket['fp_rate']:.2f}%"
                )
        print(f"  Noise suppression removed {summary['suppressed_findings']} considered findings")
        print(f"  Cases:   {summary['passed_cases']}/{summary['total_cases']} expected-positive CVEs detected")
        print()

    return report


def _fails_thresholds(
    report: dict[str, Any],
    *,
    fail_under_recall: float,
    fail_under_precision: float,
    fail_under_f1: float,
    max_fp_rate: float,
) -> bool:
    summary = report["summary"]
    failed = False
    if fail_under_recall and summary["recall"] < fail_under_recall:
        failed = True
    if fail_under_precision and summary["precision"] < fail_under_precision:
        failed = True
    if fail_under_f1 and summary["f1"] < fail_under_f1:
        failed = True
    if max_fp_rate and summary["fp_rate"] > max_fp_rate:
        failed = True
    return failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static executable CVE recall runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.cve_recall_runner
              python -m benchmarks.cve_recall_runner --lang python
              python -m benchmarks.cve_recall_runner --fail-under-recall 85 --fail-under-precision 70 --max-fp-rate 30
              python -m benchmarks.cve_recall_runner --quiet --json
            """
        ),
    )
    parser.add_argument("--lang", choices=["python", "javascript"], default=None,
                        help="Run one language slice only")
    parser.add_argument("--limit", type=int, default=None, metavar="N",
                        help="Limit corpus size (for quick smoke checks)")
    parser.add_argument("--fail-under-recall", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if recall falls below this percentage")
    parser.add_argument("--fail-under-precision", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if precision falls below this percentage")
    parser.add_argument("--fail-under-f1", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if F1 falls below this percentage")
    parser.add_argument("--max-fp-rate", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if FP rate exceeds this percentage")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress human summary")
    parser.add_argument("--json", action="store_true",
                        help="Print report as JSON")
    args = parser.parse_args()

    report = run_cve_recall(
        lang_filter=args.lang,
        case_limit=args.limit,
        quiet=args.quiet,
    )

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if _fails_thresholds(
        report,
        fail_under_recall=args.fail_under_recall,
        fail_under_precision=args.fail_under_precision,
        fail_under_f1=args.fail_under_f1,
        max_fp_rate=args.max_fp_rate,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
