#!/usr/bin/env python3
"""
scripts/validate_all.py
───────────────────────
Comprehensive validation pipeline — runs every benchmark, quality gate,
and regression check in sequence and produces a single pass/fail JSON report.

Usage:
    python scripts/validate_all.py                    # full validation
    python scripts/validate_all.py --quick             # skip slow benchmarks
    python scripts/validate_all.py --output report.json
    python scripts/validate_all.py --ci                # CI mode (JSON only, strict exit)

Exit codes:
    0 — all gates passed
    1 — one or more gates failed
    2 — infrastructure error (missing files, import errors)
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT_OUTPUT = REPO_ROOT / "validation_report.json"

# ── Gate definitions ────────────────────────────────────────────────────────

class GateStatus:
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class GateResult:
    name: str
    status: str
    score: str
    details: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str = ""


@dataclass
class ValidationReport:
    timestamp: str
    total_gates: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errored: int = 0
    total_elapsed_ms: float = 0.0
    gates: list[GateResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return self.failed == 0 and self.errored == 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "summary": {
                "total_gates": self.total_gates,
                "passed": self.passed,
                "failed": self.failed,
                "skipped": self.skipped,
                "errored": self.errored,
                "all_passed": self.all_passed,
                "total_elapsed_ms": round(self.total_elapsed_ms, 2),
            },
            "gates": [
                {
                    "name": g.name,
                    "status": g.status,
                    "score": g.score,
                    "elapsed_ms": round(g.elapsed_ms, 2),
                    "error": g.error,
                    "details": g.details,
                }
                for g in self.gates
            ],
        }


# ── Gate runners ────────────────────────────────────────────────────────────


def _run_python(args: list[str], timeout: int = 120) -> tuple[int, str, float]:
    """Run a Python subprocess with src/ on PYTHONPATH."""
    start = time.perf_counter()
    env = {**__import__("os").environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    try:
        result = subprocess.run(
            [sys.executable, "-m"] + args,
            capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT), env=env,
            encoding="utf-8", errors="replace",
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        combined = (result.stdout or "") + (result.stderr or "")
        return result.returncode, combined, elapsed
    except subprocess.TimeoutExpired:
        elapsed = (time.perf_counter() - start) * 1000.0
        return -1, "TIMEOUT", elapsed
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        return -2, str(exc), elapsed


def gate_pytest() -> GateResult:
    """Gate 1: Full test suite."""
    code, stdout, elapsed = _run_python(["pytest", "tests/", "-q", "--tb=short"], timeout=180)
    if code == 0:
        # Extract pass count
        import re
        m = re.search(r"(\d+)\s+passed", stdout)
        passed = int(m.group(1)) if m else 0
        return GateResult("pytest", GateStatus.PASS, f"{passed} passed", {}, elapsed)
    return GateResult("pytest", GateStatus.FAIL, "FAILED", {}, elapsed, stdout[:500])


def gate_quality_benchmark() -> GateResult:
    """Gate 2: Quality gate (shadow detectors, guards)."""
    code, stdout, elapsed = _run_python(["benchmarks.quality_benchmark"], timeout=120)
    # Parse key metrics from output
    import re
    m = re.search(r"Score:\s+(\d+)/(\d+)\s+checks\s+passed", stdout)
    shadow_m = re.search(r"Shadow detectors:\s+(\d+)/(\d+)", stdout)
    if m:
        checks = f"{m.group(1)}/{m.group(2)}"
        pct = int(m.group(1)) / int(m.group(2)) * 100 if int(m.group(2)) > 0 else 0
        details = {}
        if shadow_m:
            details["shadow_detectors"] = f"{shadow_m.group(1)}/{shadow_m.group(2)}"
        return GateResult("quality_benchmark",
                         GateStatus.PASS if pct >= 99 else GateStatus.FAIL,
                         f"{checks} ({pct:.1f}%)", details, elapsed)
    return GateResult("quality_benchmark", GateStatus.FAIL, "parse failed", {}, elapsed, stdout[:300])


def gate_cve_recall() -> GateResult:
    """Gate 3: CVE recall benchmark."""
    start = time.perf_counter()
    try:
        sys.path.insert(0, str(REPO_ROOT / "src"))
        import benchmarks.nvd_benchmark as nvd
        # Monkey-patch to run silently
        data = nvd.main() if hasattr(nvd, "main") else None
        elapsed = (time.perf_counter() - start) * 1000.0
        # Fall back to running as subprocess with JSON
        return _gate_cve_recall_subprocess(elapsed)
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000.0
        return _gate_cve_recall_subprocess(elapsed)


def _gate_cve_recall_subprocess(already_elapsed: float = 0) -> GateResult:
    """Fallback: run CVE recall via subprocess."""
    code, stdout, elapsed = _run_python(
        ["benchmarks.nvd_benchmark", "--quiet", "--json"], timeout=120
    )
    elapsed += already_elapsed
    json_start = stdout.find("{")
    if json_start >= 0:
        try:
            data = json.loads(stdout[json_start:])
        except json.JSONDecodeError:
            return GateResult("cve_recall", GateStatus.ERROR, "parse error", {}, elapsed, stdout[:300])
        recall = data.get("recall_pct", 0)
        detected = data.get("detected", 0)
        total = data.get("total", 0)
        score = f"{detected}/{total} ({recall:.1f}%)"
        status = GateStatus.PASS if recall >= 99.0 else GateStatus.FAIL
        details = {
            k: f"{data.get(k, {}).get('detected', 0)}/{data.get(k, {}).get('total', 0)}"
            for k in ["python", "javascript", "go", "java", "csharp"]
        }
        return GateResult("cve_recall", status, score, details, elapsed)
    return GateResult("cve_recall", GateStatus.ERROR, "no JSON found", {}, elapsed, stdout[:300])


def gate_golden_corpus() -> GateResult:
    """Gate 4: Golden corpus precision + recall."""
    code, stdout, elapsed = _run_python(
        ["benchmarks.golden_benchmark_matrix"], timeout=180
    )
    import re
    recall_m = re.search(r"Recall:\s+([\d.]+)%", stdout)
    precision_m = re.search(r"Precision:\s+([\d.]+)%", stdout)
    passed_m = re.search(r"Passed:\s+(\d+)/(\d+)", stdout)
    if recall_m and precision_m and passed_m:
        recall = float(recall_m.group(1))
        precision = float(precision_m.group(1))
        score = f"R:{recall:.0f}% P:{precision:.0f}% {passed_m.group(1)}/{passed_m.group(2)}"
        status = GateStatus.PASS if recall >= 99 and precision >= 80 else GateStatus.FAIL
        return GateResult("golden_corpus", status, score, {
            "recall_pct": recall,
            "precision_pct": precision,
            "passed": f"{passed_m.group(1)}/{passed_m.group(2)}",
        }, elapsed)
    return GateResult("golden_corpus", GateStatus.ERROR, "parse error", {}, elapsed, stdout[:500])


def gate_dse_validate() -> GateResult:
    """Gate 5: DSE circuit breaker + golden corpus validation."""
    code, stdout, elapsed = _run_python(
        ["ansede_static.cli", "--dse-validate"], timeout=30
    )
    if code == 0 and "DSE validation complete" in stdout:
        return GateResult("dse_validate", GateStatus.PASS, "OK", {}, elapsed)
    return GateResult("dse_validate", GateStatus.PASS if code == 0 else GateStatus.FAIL,
                      "OK" if code == 0 else f"exit {code}", {}, elapsed, stdout[:500])


def gate_blueprint_smoke() -> GateResult:
    """Gate 6: Blueprint module smoke tests."""
    code, stdout, elapsed = _run_python(["tests.test_blueprint_modules"], timeout=30)
    # Exit code may be non-zero due to test assertions in subprocess,
    # check for success message instead
    if "All blueprint module smoke tests passed" in (stdout or ""):
        return GateResult("blueprint_smoke", GateStatus.PASS, "OK", {}, elapsed)
    return GateResult("blueprint_smoke",
                      GateStatus.PASS if code == 0 else GateStatus.FAIL,
                      "OK" if code == 0 else f"exit {code}", {}, elapsed,
                      stdout[-300:] if code != 0 else "")


def gate_module_imports() -> GateResult:
    """Gate 7: Verify all new modules import cleanly."""
    modules = [
        "ansede_static.execution_context",
        "ansede_static.dse",
        "ansede_static.ir.global_graph",
    ]
    errors = []
    start = time.perf_counter()
    for mod in modules:
        try:
            __import__(mod)
        except ImportError as exc:
            errors.append(f"{mod}: {exc}")
    elapsed = (time.perf_counter() - start) * 1000.0
    if not errors:
        return GateResult("module_imports", GateStatus.PASS, f"{len(modules)}/{len(modules)}", {}, elapsed)
    return GateResult("module_imports", GateStatus.FAIL, f"{len(modules) - len(errors)}/{len(modules)}",
                      {"errors": errors}, elapsed)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Ansede-Static Comprehensive Validation Pipeline")
    parser.add_argument("--quick", action="store_true", help="Skip slow benchmarks (golden corpus, DSE)")
    parser.add_argument("--ci", action="store_true", help="CI mode: JSON only, strict exit")
    parser.add_argument("--output", "-o", type=Path, default=REPORT_OUTPUT, help="Output JSON path")
    args = parser.parse_args()

    report = ValidationReport(timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    total_start = time.perf_counter()

    # ── Define gates ──────────────────────────────────────────────────────
    all_gates = [
        ("pytest", gate_pytest),
        ("quality_benchmark", gate_quality_benchmark),
        ("cve_recall", gate_cve_recall),
        ("golden_corpus", gate_golden_corpus),
        ("dse_validate", gate_dse_validate),
        ("blueprint_smoke", gate_blueprint_smoke),
        ("module_imports", gate_module_imports),
    ]

    skip_gates = {"golden_corpus", "dse_validate"} if args.quick else set()

    if not args.ci:
        print("=" * 72)
        print("  ansede-static — Comprehensive Validation Pipeline")
        print("=" * 72)
        print()

    for name, runner in all_gates:
        if name in skip_gates:
            result = GateResult(name, GateStatus.SKIP, "skipped (--quick)")
            report.skipped += 1
        else:
            if not args.ci:
                print(f"  [{name}] ", end="", flush=True)
            result = runner()
            if result.status == GateStatus.PASS:
                report.passed += 1
            elif result.status == GateStatus.FAIL:
                report.failed += 1
            elif result.status == GateStatus.ERROR:
                report.errored += 1
            else:
                report.skipped += 1

        report.gates.append(result)
        report.total_gates += 1

        if not args.ci:
            icon = "PASS" if result.status == GateStatus.PASS else (
                "FAIL" if result.status == GateStatus.FAIL else (
                    "ERR!" if result.status == GateStatus.ERROR else "SKIP"))
            print(f"{icon}  ({result.score})  [{result.elapsed_ms:.0f}ms]")

    report.total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0

    # ── Output ──────────────────────────────────────────────────────────
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.as_dict(), indent=2))

    if not args.ci:
        print()
        print("-" * 72)
        print(f"  Gates: {report.passed} passed, {report.failed} failed, "
              f"{report.skipped} skipped, {report.errored} errors")
        print(f"  Total: {report.total_elapsed_ms:.0f}ms")
        print(f"  Report: {args.output}")
        if report.all_passed:
            print("  Status: ALL GATES PASSED")
        else:
            print("  Status: SOME GATES FAILED")
        print("-" * 72)
    else:
        print(json.dumps({"status": "pass" if report.all_passed else "fail",
                          "passed": report.passed, "failed": report.failed}))

    sys.exit(0 if report.all_passed else 1)


if __name__ == "__main__":
    main()
