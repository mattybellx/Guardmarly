from __future__ import annotations

from benchmarks.perf_benchmark import run_perf_benchmark
from benchmarks.quality_benchmark import run_quality_benchmark


def test_quality_benchmark_corpus_is_green():
    report = run_quality_benchmark(quiet=True)

    assert report["summary"]["checks_total"] > 0
    assert report["summary"]["score_pct"] == 100.0


def test_perf_benchmark_returns_positive_metrics():
    report = run_perf_benchmark(iterations=1, quiet=True)

    assert report["cases_per_iteration"] > 0
    assert report["avg_ms"] > 0
    assert report["cases_per_second"] > 0
