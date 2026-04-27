"""
benchmarks.perf_benchmark
─────────────────────────
Small deterministic performance smoke benchmark for ansede-static.

This is not a substitute for large-repo profiling, but it gives CI and local
contributors a stable way to watch for obvious regressions in the core scanning
loop.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_code
from benchmarks.quality_corpus import QUALITY_CORPUS


def run_perf_benchmark(iterations: int = 5, quiet: bool = False) -> dict[str, Any]:
    if iterations <= 0:
        raise ValueError("iterations must be positive")

    cases = list(QUALITY_CORPUS)
    durations_ms: list[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        for case in cases:
            scan_code(
                case.snippet,
                language=case.language,
                filename=case.filename,
                js_backend=case.js_backend,
            )
        durations_ms.append((time.perf_counter() - t0) * 1000.0)

    total_cases = len(cases)
    avg_ms = sum(durations_ms) / len(durations_ms)
    fastest_ms = min(durations_ms)
    slowest_ms = max(durations_ms)
    cases_per_second = (total_cases / (avg_ms / 1000.0)) if avg_ms else 0.0

    report = {
        "iterations": iterations,
        "cases_per_iteration": total_cases,
        "avg_ms": round(avg_ms, 3),
        "fastest_ms": round(fastest_ms, 3),
        "slowest_ms": round(slowest_ms, 3),
        "cases_per_second": round(cases_per_second, 2),
    }

    if not quiet:
        print()
        print("ansede-static performance smoke benchmark")
        print("-" * 46)
        print(f"Iterations         : {iterations}")
        print(f"Cases / iteration  : {total_cases}")
        print(f"Average time       : {report['avg_ms']:.3f} ms")
        print(f"Fastest time       : {report['fastest_ms']:.3f} ms")
        print(f"Slowest time       : {report['slowest_ms']:.3f} ms")
        print(f"Cases / second     : {report['cases_per_second']:.2f}")
        print()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static performance smoke benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python -m benchmarks.perf_benchmark
              python -m benchmarks.perf_benchmark --iterations 20 --quiet --json
        """),
    )
    parser.add_argument("--iterations", type=int, default=5, metavar="N",
                        help="How many full passes over the benchmark corpus to run")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress the human summary")
    parser.add_argument("--json", action="store_true",
                        help="Print the final report as JSON")
    args = parser.parse_args()

    report = run_perf_benchmark(iterations=args.iterations, quiet=args.quiet)

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
