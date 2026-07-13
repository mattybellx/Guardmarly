"""
Competitive Benchmark: Ansede vs Semgrep vs CodeQL

Runs all available scanners on the CVE corpus and produces comparison metrics.
Usage: python benchmarks/competitive_bench.py [--corpus-path PATH]
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

BENCH_DIR = Path(__file__).resolve().parent
ROOT = BENCH_DIR.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


def run_ansede(path: Path) -> dict[str, Any]:
    """Run Ansede on a path and return parsed results."""
    from ansede_static import scan_code
    start = time.perf_counter()
    code = path.read_text(encoding="utf-8", errors="replace")
    result = scan_code(code, path.suffix.lstrip("."), str(path))
    elapsed = time.perf_counter() - start
    findings = result.findings if hasattr(result, "findings") else []
    return {
        "findings": [
            {"cwe": f.cwe, "rule_id": f.rule_id, "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
             "line": f.line, "title": f.title}
            for f in findings
        ],
        "count": len(findings),
        "time_sec": round(elapsed, 3),
    }


def run_semgrep(path: Path) -> dict[str, Any] | None:
    """Run Semgrep if installed."""
    semgrep = "semgrep"
    try:
        start = time.perf_counter()
        r = subprocess.run(
            [semgrep, "scan", "--config=auto", "--json", str(path)],
            capture_output=True, text=True, timeout=120
        )
        elapsed = time.perf_counter() - start
        if r.returncode == 0:
            data = json.loads(r.stdout)
            findings = data.get("results", [])
            return {
                "findings": [
                    {"cwe": ", ".join(f.get("extra", {}).get("metadata", {}).get("cwe", [])),
                     "rule_id": f.get("check_id", ""),
                     "severity": f.get("extra", {}).get("severity", ""),
                     "line": f.get("start", {}).get("line", 0)}
                    for f in findings
                ],
                "count": len(findings),
                "time_sec": round(elapsed, 3),
            }
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return None


def run_codeql(path: Path) -> dict[str, Any] | None:
    """Run CodeQL if installed."""
    codeql = "codeql"
    db_dir = Path("tmp/codeql_db")
    try:
        # Create database (language auto-detect)
        subprocess.run([codeql, "database", "create", str(db_dir), "--language=python", f"--source-root={path.parent}"],
                       capture_output=True, text=True, timeout=120, check=True)
        # Run analysis
        start = time.perf_counter()
        r = subprocess.run(
            [codeql, "database", "analyze", str(db_dir), "--format=sarif-latest", "--output=tmp/codeql_results.sarif"],
            capture_output=True, text=True, timeout=300
        )
        elapsed = time.perf_counter() - start
        # Parse SARIF
        if Path("tmp/codeql_results.sarif").exists():
            sarif = json.loads(Path("tmp/codeql_results.sarif").read_text())
            findings = []
            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    findings.append({
                        "cwe": "",
                        "rule_id": result.get("ruleId", ""),
                        "severity": result.get("level", ""),
                        "line": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0),
                    })
            return {"findings": findings, "count": len(findings), "time_sec": round(elapsed, 3)}
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return None


def benchmark_corpus(corpus_path: Path | None = None):
    """Run all scanners on the CVE corpus and compare."""
    if corpus_path is None:
        # Use CVE corpus entries
        from benchmarks.cve_corpus import CVE_CORPUS
        entries = CVE_CORPUS
    else:
        entries = []

    results = {
        "ansede": {"total_findings": 0, "total_time": 0.0, "cwes_found": set(), "cases": 0},
        "semgrep": {"total_findings": 0, "total_time": 0.0, "cwes_found": set(), "cases": 0},
        "codeql": {"total_findings": 0, "total_time": 0.0, "cwes_found": set(), "cases": 0},
    }

    for entry in entries:
        snippet = entry.code
        lang = entry.language
        tmpfile = Path(f"tmp/corpus_{entry.cve_id}.{lang}")
        tmpfile.parent.mkdir(exist_ok=True)
        tmpfile.write_text(snippet, encoding="utf-8")

        # Ansede
        a = run_ansede(tmpfile)
        results["ansede"]["total_findings"] += a["count"]
        results["ansede"]["total_time"] += a["time_sec"]
        results["ansede"]["cases"] += 1
        for f in a["findings"]:
            if f["cwe"]:
                results["ansede"]["cwes_found"].add(f["cwe"])

        # Semgrep
        s = run_semgrep(tmpfile)
        if s:
            results["semgrep"]["total_findings"] += s["count"]
            results["semgrep"]["total_time"] += s["time_sec"]
            results["semgrep"]["cases"] += 1
            for f in s["findings"]:
                if f["cwe"]:
                    results["semgrep"]["cwes_found"].add(f["cwe"])

        tmpfile.unlink(missing_ok=True)

    # Print comparison
    print("\n" + "=" * 70)
    print("COMPETITIVE BENCHMARK: Ansede vs Semgrep vs CodeQL")
    print("=" * 70)
    print(f"{'Metric':<25} {'Ansede':>12} {'Semgrep':>12} {'CodeQL':>12}")
    print("-" * 70)
    print(f"{'Total findings':<25} {results['ansede']['total_findings']:>12} {results['semgrep']['total_findings']:>12} {'N/A':>12}")
    print(f"{'Total time (sec)':<25} {results['ansede']['total_time']:>11.1f}s {results['semgrep']['total_time']:>11.1f}s {'N/A':>12}")
    print(f"{'Unique CWEs':<25} {len(results['ansede']['cwes_found']):>12} {len(results['semgrep']['cwes_found']):>12} {'N/A':>12}")
    print(f"{'Cases scanned':<25} {results['ansede']['cases']:>12} {results['semgrep']['cases']:>12} {'N/A':>12}")

    return results


if __name__ == "__main__":
    benchmark_corpus()
