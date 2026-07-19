#!/usr/bin/env python3
"""
benchmark.py — Guardmarly SAST benchmark harness.

Runs Guardmarly against every corpus in .corpora/ and emits structured
benchmark results to results/benchmarks/<version>.json.

Usage:
    python scripts/benchmark.py                    # full benchmark run
    python scripts/benchmark.py --corpus owasp-benchmark-java  # single corpus
    python scripts/benchmark.py --category clean   # clean-corpus FP measurement only
    python scripts/benchmark.py --compare          # compare against committed baseline
    python scripts/benchmark.py --quick            # 5-file sample per corpus (fast)

No network access required — all corpora must be pre-fetched via fetch_corpora.py.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CORPORA_DIR = ROOT / ".corpora"
RESULTS_DIR = ROOT / "results" / "benchmarks"
MANIFEST_PATH = CORPORA_DIR / "manifest.json"

# Guardmarly CLI entry points to try, in order
_CLI_CANDIDATES = [
    ["python", "-m", "guardmarly.cli"],
    ["guardmarly"],
    ["python3", "-m", "guardmarly.cli"],
]


def _find_guardmarly_cli() -> list[str]:
    """Find a working guardmarly CLI command."""
    for cmd in _CLI_CANDIDATES:
        try:
            result = subprocess.run(
                [*cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(ROOT),
            )
            if result.returncode == 0:
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    # Fallback: use the local module
    return ["python", "-m", "guardmarly.cli"]


# ── OWASP Benchmark expected-result parsing ───────────────────────────────
# OWASP Benchmark test case filenames encode expected results:
#   BenchmarkTest00001.java → expected: true (vulnerable)
#   BenchmarkTest00002.java → expected: false (not vulnerable)
# The expected result is in benchmark/expectedresults-1.2.csv

def _parse_owasp_expected(corpus_dir: Path) -> dict[str, bool]:
    """Parse OWASP Benchmark expected results CSV.
    Returns mapping of test-number → expected-vulnerable (bool).
    """
    expected_csv = corpus_dir / "expectedresults-1.2.csv"
    if not expected_csv.exists():
        # Try common locations
        for cand in corpus_dir.glob("**/expectedresults*.csv"):
            expected_csv = cand
            break

    if not expected_csv.exists():
        return {}

    expected: dict[str, bool] = {}
    try:
        lines = expected_csv.read_text(errors="replace").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                test_num = parts[0].strip()
                expected_val = parts[1].strip().lower()
                if test_num.isdigit():
                    expected[test_num] = expected_val == "true"
    except (OSError, UnicodeDecodeError):
        pass
    return expected


def _parse_juliet_expected(filepath: Path) -> bool | None:
    """Determine if a Juliet test case file should be flagged as vulnerable.

    Juliet naming convention:
      - File has 'good' in path → not vulnerable (fixed/patched variant)
      - File has 'bad' in path → vulnerable
      - Otherwise → unknown
    """
    path_lower = str(filepath).lower()
    if "good" in path_lower:
        return False
    if "bad" in path_lower:
        return True
    return None


# ── File / LOC counting ───────────────────────────────────────────────────

def _count_files_and_loc(corpus_dir: Path, extensions: set[str]) -> tuple[int, int]:
    """Count scannable files and lines of code in a directory."""
    file_count = 0
    loc = 0
    for ext in extensions:
        for f in corpus_dir.rglob(f"*{ext}"):
            # Skip test directories and vendored code for LOC counting
            path_str = str(f)
            if any(skip in path_str for skip in ["/test/", "/tests/", "/vendor/", "/node_modules/", "/target/"]):
                continue
            file_count += 1
            try:
                loc += sum(1 for _ in open(f, errors="replace"))
            except OSError:
                pass
    return file_count, loc


# ── Scan runner ───────────────────────────────────────────────────────────

def _get_lang_extensions(languages: list[str]) -> set[str]:
    """Map language names to file extensions."""
    ext_map: dict[str, list[str]] = {
        "python": [".py", ".pyi", ".pyw"],
        "javascript": [".js", ".mjs", ".cjs"],
        "typescript": [".ts", ".tsx"],
        "java": [".java"],
        "csharp": [".cs"],
        "go": [".go"],
        "php": [".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps"],
        "ruby": [".rb", ".rake", ".gemspec"],
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cxx", ".cc", ".hpp", ".c++"],
        "kotlin": [".kt", ".kts"],
        "swift": [".swift"],
        "rust": [".rs"],
    }
    exts: set[str] = set()
    for lang in languages:
        exts.update(ext_map.get(lang, []))
    return exts


def run_scan(corpus_dir: Path, cli: list[str], timeout: int = 600) -> dict[str, Any]:
    """Run Guardmarly on a corpus directory. Returns JSON findings."""
    try:
        result = subprocess.run(
            [*cli, str(corpus_dir), "--format", "json", "--all-findings"],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(ROOT),
        )
        if result.returncode not in (0, 1):  # 1 = findings found (expected)
            return {"error": f"Exit code {result.returncode}", "stderr": result.stderr[:500]}
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": "JSON parse failed", "stdout": result.stdout[:500]}
    except subprocess.TimeoutExpired:
        return {"error": f"Timeout after {timeout}s"}
    except Exception as e:
        return {"error": str(e)}


# ── Results computation ────────────────────────────────────────────────────

def _compute_owasp_benchmark_metrics(
    findings_raw: list[dict],
    corpus_dir: Path,
) -> dict[str, Any]:
    """Compute TP/FP/FN for OWASP Benchmark corpus."""
    expected = _parse_owasp_expected(corpus_dir)
    if not expected:
        return {"note": "No expected-results CSV found — raw counts only"}

    # Build set of test numbers that were flagged
    flagged: set[str] = set()
    for f in findings_raw:
        filepath = f.get("file", "")
        # Extract test number from filename like BenchmarkTest00042.java
        import re
        m = re.search(r"BenchmarkTest(\d+)", filepath)
        if m:
            flagged.add(m.group(1))

    tp = 0  # flagged + expected vulnerable
    fp = 0  # flagged + expected NOT vulnerable
    fn = 0  # NOT flagged + expected vulnerable
    tn = 0  # NOT flagged + expected NOT vulnerable

    for test_num, is_vuln in expected.items():
        if is_vuln:
            if test_num in flagged:
                tp += 1
            else:
                fn += 1
        else:
            if test_num in flagged:
                fp += 1
            else:
                tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total": total,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _compute_juliet_metrics(
    findings_raw: list[dict],
    corpus_dir: Path,
) -> dict[str, Any]:
    """Compute TP/FP for Juliet Test Suite based on good/bad file naming."""
    tp = 0
    fp = 0

    # Track which files were flagged
    flagged_files: set[str] = set()
    for f in findings_raw:
        flagged_files.add(f.get("file", ""))

    # Walk corpus to compute FN (bad files not flagged)
    bad_files = 0
    bad_flagged = 0
    good_files = 0
    good_flagged = 0

    for f in corpus_dir.rglob("*"):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext not in {".java", ".c", ".cpp", ".cs", ".h", ".hpp"}:
            continue

        expected = _parse_juliet_expected(f)
        if expected is None:
            continue

        rel_path = str(f.relative_to(corpus_dir))
        is_flagged = any(rel_path in ff for ff in flagged_files)

        if expected:  # should be flagged
            bad_files += 1
            if is_flagged:
                bad_flagged += 1
                tp += 1
        else:  # should NOT be flagged
            good_files += 1
            if is_flagged:
                good_flagged += 1
                fp += 1

    fn = bad_files - bad_flagged

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "bad_files_total": bad_files,
        "good_files_total": good_files,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _compute_vulnerable_app_metrics(
    findings_raw: list[dict],
    file_count: int,
    loc: int,
) -> dict[str, Any]:
    """For deliberately vulnerable apps, report finding counts by severity/CWE.

    These are known-vulnerable apps; we can't compute exact TP/FP without a
    ground-truth mapping, but high finding counts in relevant CWEs indicate
    good recall.
    """
    severity_counts: dict[str, int] = defaultdict(int)
    cwe_counts: dict[str, int] = defaultdict(int)
    cwe_639_count = 0  # IDOR-specific

    for f in findings_raw:
        sev = f.get("severity", "unknown")
        severity_counts[sev] += 1
        cwe = f.get("cwe", "unknown")
        cwe_counts[cwe] += 1
        if cwe == "CWE-639":
            cwe_639_count += 1

    return {
        "total_findings": len(findings_raw),
        "files_scanned": file_count,
        "loc": loc,
        "findings_per_kloc": round(len(findings_raw) / (loc / 1000), 2) if loc > 0 else 0,
        "severity_counts": dict(severity_counts),
        "cwe_counts": dict(cwe_counts),
        "cwe_639_idor_count": cwe_639_count,
    }


def _compute_clean_corpus_metrics(
    findings_raw: list[dict],
    file_count: int,
    loc: int,
) -> dict[str, Any]:
    """For clean corpora, report FP proxy metrics.

    Well-maintained production code should have very few findings.
    Findings here are likely false positives.
    """
    severity_counts: dict[str, int] = defaultdict(int)
    high_critical = 0

    for f in findings_raw:
        sev = f.get("severity", "unknown")
        severity_counts[sev] += 1
        if sev in ("HIGH", "CRITICAL"):
            high_critical += 1

    fp_per_1000 = round((len(findings_raw) / (loc / 1000)), 2) if loc > 0 else 0
    hc_per_1000 = round((high_critical / (loc / 1000)), 2) if loc > 0 else 0

    return {
        "total_findings": len(findings_raw),
        "high_critical_findings": high_critical,
        "files_scanned": file_count,
        "loc": loc,
        "fp_per_1000_files": round(len(findings_raw) / (file_count / 1000), 2) if file_count > 0 else 0,
        "fp_per_kloc": fp_per_1000,
        "hc_per_kloc": hc_per_1000,
        "severity_counts": dict(severity_counts),
    }


# ── Main benchmark driver ──────────────────────────────────────────────────

def benchmark_corpus(
    corpus_spec: dict[str, Any],
    cli: list[str],
    quick: bool = False,
) -> dict[str, Any]:
    """Run benchmark on a single corpus."""
    slug = corpus_spec["slug"]
    category = corpus_spec["category"]
    languages = corpus_spec.get("languages", [])
    corpus_dir = Path(corpus_spec["path"])

    if not corpus_dir.exists():
        return {"slug": slug, "error": f"Corpus directory not found: {corpus_dir}"}

    extensions = _get_lang_extensions(languages)
    file_count, loc = _count_files_and_loc(corpus_dir, extensions)

    start = time.perf_counter()

    # For quick mode, create a temp dir with 5 sample files
    scan_dir = corpus_dir
    if quick:
        sample_files: list[Path] = []
        for ext in extensions:
            sample_files.extend(list(corpus_dir.rglob(f"*{ext}"))[:3])
        if not sample_files:
            sample_files = list(corpus_dir.rglob("*.java"))[:5] or list(corpus_dir.rglob("*.py"))[:5]
        # Scan files individually
        all_findings: list[dict] = []
        for sf in sample_files[:5]:
            result = run_scan(sf, cli, timeout=60)
            if isinstance(result, dict) and "error" not in result:
                if isinstance(result, list):
                    all_findings.extend(result)
                elif isinstance(result, dict):
                    all_findings.extend(result.get("findings", result.get("results", [])))
        findings_raw = all_findings
        scan_file_count = min(5, len(sample_files))
    else:
        result = run_scan(scan_dir, cli, timeout=900)
        if isinstance(result, dict) and "error" in result:
            return {
                "slug": slug,
                "category": category,
                "file_count": file_count,
                "loc": loc,
                "error": result["error"],
                "scan_time_s": round(time.perf_counter() - start, 2),
            }
        findings_raw = result if isinstance(result, list) else result.get("findings", result.get("results", []))
        scan_file_count = file_count

    elapsed = time.perf_counter() - start

    base = {
        "slug": slug,
        "category": category,
        "languages": languages,
        "file_count": file_count,
        "loc": loc,
        "scan_time_s": round(elapsed, 2),
        "loc_per_second": round(loc / elapsed) if elapsed > 0 and loc > 0 else 0,
    }

    # Compute category-specific metrics
    if category == "benchmark":
        if "owasp" in slug.lower():
            metrics = _compute_owasp_benchmark_metrics(findings_raw, corpus_dir)
        elif "juliet" in slug.lower():
            metrics = _compute_juliet_metrics(findings_raw, corpus_dir)
        else:
            metrics = _compute_vulnerable_app_metrics(findings_raw, scan_file_count, loc)
    elif category == "vulnerable":
        metrics = _compute_vulnerable_app_metrics(findings_raw, scan_file_count, loc)
    else:  # clean
        metrics = _compute_clean_corpus_metrics(findings_raw, scan_file_count, loc)

    return {**base, **metrics}


def load_manifest() -> list[dict[str, Any]]:
    """Load the corpus manifest from .corpora/manifest.json."""
    if not MANIFEST_PATH.exists():
        print(f"Manifest not found at {MANIFEST_PATH}", file=sys.stderr)
        print("Run 'python scripts/fetch_corpora.py' first.", file=sys.stderr)
        return []
    try:
        data = json.loads(MANIFEST_PATH.read_text())
        return data.get("corpora", [])
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading manifest: {e}", file=sys.stderr)
        return []


def load_baseline() -> dict[str, Any] | None:
    """Load the most recent committed benchmark baseline."""
    if not RESULTS_DIR.exists():
        return None
    # Find the most recent versioned result
    results_files = sorted(RESULTS_DIR.glob("*.json"), reverse=True)
    for rf in results_files:
        try:
            return json.loads(rf.read_text())
        except (json.JSONDecodeError, OSError):
            continue
    return None


def compare_baseline(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Compare current benchmark against baseline, flag regressions."""
    current_corpora = {c["slug"]: c for c in current.get("corpora", [])}
    baseline_corpora = {c["slug"]: c for c in baseline.get("corpora", [])}

    regressions: list[str] = []
    improvements: list[str] = []

    for slug, cur in current_corpora.items():
        base = baseline_corpora.get(slug)
        if base is None:
            continue

        # Compare recall
        cur_recall = cur.get("recall")
        base_recall = base.get("recall")
        if cur_recall is not None and base_recall is not None:
            if cur_recall < base_recall - 0.001:  # small tolerance
                regressions.append(f"{slug}: recall {base_recall:.4f} → {cur_recall:.4f}")
            elif cur_recall > base_recall + 0.001:
                improvements.append(f"{slug}: recall {base_recall:.4f} → {cur_recall:.4f}")

        # Compare clean-corpus FP rate
        cur_fp = cur.get("fp_per_kloc")
        base_fp = base.get("fp_per_kloc")
        if cur_fp is not None and base_fp is not None:
            if cur_fp > base_fp + 0.01:
                regressions.append(f"{slug}: FP/kLOC {base_fp:.2f} → {cur_fp:.2f}")
            elif cur_fp < base_fp - 0.01:
                improvements.append(f"{slug}: FP/kLOC {base_fp:.2f} → {cur_fp:.2f}")

    return {
        "baseline_version": baseline.get("version", "unknown"),
        "regressions": regressions,
        "improvements": improvements,
        "has_regressions": len(regressions) > 0,
        "has_improvements": len(improvements) > 0,
    }


def get_engine_version(cli: list[str]) -> str:
    """Get the current Guardmarly version."""
    try:
        result = subprocess.run(
            [*cli, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(ROOT),
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


# ── CLI ────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guardmarly SAST benchmark harness",
    )
    parser.add_argument(
        "--corpus",
        type=str,
        default=None,
        help="Benchmark only a specific corpus (by slug)",
    )
    parser.add_argument(
        "--category",
        type=str,
        choices=["benchmark", "vulnerable", "clean"],
        default=None,
        help="Benchmark only corpora of a specific category",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare against the most recent committed baseline",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick mode: scan only 5 files per corpus",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Timeout per corpus in seconds (default: 900)",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Number of corpora to scan in parallel (default: 1)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (default: results/benchmarks/<version>.json)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = load_manifest()

    if not manifest:
        sys.exit(1)

    # Filter
    if args.corpus:
        selected = [c for c in manifest if c["slug"] == args.corpus]
        if not selected:
            print(f"Unknown corpus: {args.corpus}", file=sys.stderr)
            sys.exit(1)
    elif args.category:
        selected = [c for c in manifest if c["category"] == args.category]
    else:
        selected = manifest

    cli = _find_guardmarly_cli()
    version = get_engine_version(cli)
    print(f"Guardmarly version: {version}")
    print(f"CLI: {' '.join(cli)}")
    print(f"Corpora to benchmark: {len(selected)}")
    if args.quick:
        print("Mode: QUICK (5 files per corpus)")
    print()

    # Run benchmarks
    results: list[dict[str, Any]] = []
    start_time = time.perf_counter()

    if args.parallel > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {
                executor.submit(benchmark_corpus, c, cli, args.quick): c["slug"]
                for c in selected
            }
            for future in concurrent.futures.as_completed(futures):
                slug = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    _print_corpus_result(result)
                except Exception as e:
                    print(f"  [{slug}] ERROR: {e}", file=sys.stderr)
                    results.append({"slug": slug, "error": str(e)})
    else:
        for corpus in selected:
            print(f"[{corpus['slug']}] Scanning...")
            result = benchmark_corpus(corpus, cli, args.quick)
            results.append(result)
            _print_corpus_result(result)

    total_time = time.perf_counter() - start_time

    # Build output
    output: dict[str, Any] = {
        "version": version,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_time_s": round(total_time, 2),
        "corpora_count": len(results),
        "corpora": sorted(results, key=lambda r: r.get("slug", "")),
    }

    # Summaries
    benchmark_results = [r for r in results if r.get("category") == "benchmark" and "recall" in r]
    clean_results = [r for r in results if r.get("category") == "clean"]

    if benchmark_results:
        avg_precision = sum(r.get("precision", 0) for r in benchmark_results) / len(benchmark_results)
        avg_recall = sum(r.get("recall", 0) for r in benchmark_results) / len(benchmark_results)
        output["summary"] = {
            "avg_precision": round(avg_precision, 4),
            "avg_recall": round(avg_recall, 4),
            "benchmark_corpora_count": len(benchmark_results),
        }

    if clean_results:
        total_loc = sum(r.get("loc", 0) for r in clean_results)
        total_fp = sum(r.get("total_findings", 0) for r in clean_results)
        output["clean_summary"] = {
            "total_loc": total_loc,
            "total_findings": total_fp,
            "fp_per_kloc": round(total_fp / (total_loc / 1000), 2) if total_loc > 0 else 0,
            "corpora_count": len(clean_results),
        }

    # Compare against baseline if requested
    if args.compare:
        baseline = load_baseline()
        if baseline:
            comparison = compare_baseline(output, baseline)
            output["comparison"] = comparison
            print()
            print("── Baseline Comparison ──")
            if comparison["has_regressions"]:
                print("❌ REGRESSIONS:")
                for r in comparison["regressions"]:
                    print(f"  - {r}")
            if comparison["has_improvements"]:
                print("✅ IMPROVEMENTS:")
                for i in comparison["improvements"]:
                    print(f"  + {i}")
            if not comparison["has_regressions"] and not comparison["has_improvements"]:
                print("  No significant changes vs baseline.")
        else:
            print("No baseline found — skipping comparison.")

    # Write output
    output_path = Path(args.output) if args.output else RESULTS_DIR / f"{version}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2))
    print(f"\nResults written to {output_path}")

    # Exit code: 0 if no regressions, 1 if regressions found
    if args.compare and output.get("comparison", {}).get("has_regressions"):
        sys.exit(1)


def _print_corpus_result(result: dict[str, Any]) -> None:
    """Print a one-line summary for a corpus result."""
    slug = result.get("slug", "?")
    if "error" in result:
        print(f"  [{slug}] ERROR: {result['error']}")
        return

    cat = result.get("category", "?")
    loc = result.get("loc", 0)
    elapsed = result.get("scan_time_s", 0)

    if cat == "benchmark":
        precision = result.get("precision")
        recall = result.get("recall")
        if precision is not None and recall is not None:
            print(f"  [{slug}] P={precision:.2%} R={recall:.2%} | {loc} LOC | {elapsed:.1f}s")
        else:
            findings = result.get("total_findings", 0)
            print(f"  [{slug}] {findings} findings | {loc} LOC | {elapsed:.1f}s")
    elif cat == "clean":
        fp_per_k = result.get("fp_per_kloc", 0)
        findings = result.get("total_findings", 0)
        hc = result.get("high_critical_findings", 0)
        print(f"  [{slug}] {findings} findings ({hc} HIGH/CRIT) | {fp_per_k}/kLOC | {loc} LOC | {elapsed:.1f}s")
    else:
        findings = result.get("total_findings", 0)
        idor = result.get("cwe_639_idor_count", 0)
        print(f"  [{slug}] {findings} findings ({idor} IDOR) | {loc} LOC | {elapsed:.1f}s")


if __name__ == "__main__":
    main()
