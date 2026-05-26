"""
benchmarks.benchmark_metrics
────────────────────────────
Shared helpers for benchmark scorecards and noise accounting.

Provides raw vs. cluster-adjusted incident counts so benchmark reports can
compare duplicated findings against high-fidelity incidents.
"""
from __future__ import annotations

from typing import Any

from ansede_static._types import Finding
from ansede_static.engine.clustering import cluster_findings as cluster_incident_findings


def noise_quotient(findings_count: int, lines_scanned: int) -> float:
    if lines_scanned <= 0:
        return 0.0
    return round(findings_count / (lines_scanned / 1000.0), 4)


def cluster_adjusted_findings(findings: list[Finding]) -> list[Finding]:
    if not findings:
        return []
    return cluster_incident_findings(findings)


def cluster_adjusted_stats(findings: list[Finding], lines_scanned: int) -> dict[str, Any]:
    clustered = cluster_adjusted_findings(findings)
    raw_count = len(findings)
    clustered_count = len(clustered)
    reduced = max(0, raw_count - clustered_count)
    reduction_pct = round((reduced / raw_count * 100.0), 2) if raw_count else 0.0
    return {
        "raw_count": raw_count,
        "clustered_count": clustered_count,
        "reduced_count": reduced,
        "reduction_pct": reduction_pct,
        "raw_noise_quotient": noise_quotient(raw_count, lines_scanned),
        "cluster_adjusted_noise_quotient": noise_quotient(clustered_count, lines_scanned),
    }