"""
ansede_static.schema
────────────────────
Versioned report-envelope helpers used by JSON and downstream integrations.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ansede_static._types import AnalysisResult
from ansede_static.engine_version import ENGINE_NAME, SCHEMA_VERSION, get_engine_record, get_engine_version


FINGERPRINT_VERSION = "2"


def build_summary(results: list[AnalysisResult], *, clustered: bool = False) -> dict[str, Any]:
    """Build aggregate counts across the full scan result set."""
    category_counts: dict[str, int] = {}
    for result in results:
        for category, count in result.category_counts().items():
            category_counts[category] = category_counts.get(category, 0) + count

    raw_total = sum(len(r.findings) for r in results)
    summary = {
        "files_scanned": len(results),
        "clean_files": sum(1 for r in results if not r.findings and not r.parse_error),
        "parse_errors": sum(1 for r in results if r.parse_error),
        "critical": sum(r.critical_count for r in results),
        "high": sum(r.high_count for r in results),
        "medium": sum(r.medium_count for r in results),
        "low": sum(r.low_count for r in results),
        "info": sum(r.info_count for r in results),
        "security_findings": sum(r.security_count for r in results),
        "quality_findings": sum(r.quality_count for r in results),
        "by_category": dict(sorted(category_counts.items())),
        "total_findings": raw_total,
    }
    if clustered:
        summary["raw_findings"] = raw_total
    return summary


def build_report(results: list[AnalysisResult], *, execution: dict[str, Any] | None = None, cluster: bool = False) -> dict[str, Any]:
    """Build the canonical JSON envelope for a scan.
    
    If cluster=True, incident clustering is applied to reduce duplicate findings.
    """
    # ── Incident clustering ──────────────────────────────────────────
    cluster_stats: dict[str, Any] | None = None
    if cluster:
        try:
            from ansede_static.engine.clustering import cluster_findings
            raw_total = sum(len(r.findings) for r in results)
            results = cluster_findings(results)
            clustered_total = sum(len(r.findings) for r in results)
            reduction_pct = round((1 - clustered_total / raw_total) * 100, 1) if raw_total else 0
            cluster_stats = {
                "raw_findings": raw_total,
                "clustered_findings": clustered_total,
                "reduction_pct": reduction_pct,
            }
        except Exception:
            pass
    
    summary = build_summary(results, clustered=cluster)
    version = get_engine_version()
    report = {
        "schema_version": SCHEMA_VERSION,
        "fingerprint_version": FINGERPRINT_VERSION,
        "tool": ENGINE_NAME,
        "version": version,
        "engine_version": version,
        "engine": get_engine_record(),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files_scanned": summary["files_scanned"],
        "total_findings": summary["total_findings"],
        "summary": summary,
        "results": [r.as_dict() for r in results],
    }
    if cluster_stats:
        report["clustering"] = cluster_stats
    if execution:
        report["execution"] = execution
    return report