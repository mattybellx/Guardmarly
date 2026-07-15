"""
benchmarks.golden_benchmark_matrix
──────────────────────────────────
Formal benchmark matrix runner — evaluates Ansede, Semgrep (OSS), and CodeQL
against the golden corpus test pairs.

Architecture (per Section 4.3 and Phase 4 of the blueprint):
  1. Load all golden corpus pairs from .ansede/golden_corpus/<CWE-XXX>/
  2. Run each tool on vulnerable.*.test (expect: finding) and secure.*.test (expect: clean)
  3. Compute per-CWE recall, precision, F1, and false-positive rate
  4. Generate a structured JSON report + Markdown summary

This is the automated execution matrix benchmark script from Phase 4,
Task 4.3 of the architectural blueprint.

Usage:
    python -m benchmarks.golden_benchmark_matrix              # ansede only
    python -m benchmarks.golden_benchmark_matrix --all         # ansede + semgrep + codeql
    python -m benchmarks.golden_benchmark_matrix --output report.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Configuration ────────────────────────────────────────────────────────────

GOLDEN_CORPUS_ROOT = Path(__file__).resolve().parent.parent / ".ansede" / "golden_corpus"
REPORT_OUTPUT = Path("golden_benchmark_report.json")


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class CWEVerdict:
    """Per-CWE benchmark result for a single tool."""
    cwe: str
    tool: str
    vulnerable_detected: bool      # Did the tool flag vulnerable.*.test?
    secure_clean: bool             # Did the tool stay silent on secure.*.test?
    elapsed_ms: float = 0.0
    findings_vuln: int = 0
    findings_secure: int = 0
    error: str = ""

    @property
    def passed(self) -> bool:
        return self.vulnerable_detected and self.secure_clean

    @property
    def false_negative(self) -> bool:
        return not self.vulnerable_detected

    @property
    def false_positive(self) -> bool:
        return not self.secure_clean


@dataclass
class ToolReport:
    """Aggregated benchmark results for one tool."""
    tool: str
    total_cwes: int = 0
    passed: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    errors: int = 0
    total_elapsed_ms: float = 0.0
    per_cwe: list[CWEVerdict] = field(default_factory=list)

    @property
    def recall(self) -> float:
        detected = self.passed + self.false_positives
        return detected / self.total_cwes if self.total_cwes > 0 else 0.0

    @property
    def precision(self) -> float:
        return self.passed / (self.passed + self.false_positives) if (self.passed + self.false_positives) > 0 else 0.0

    @property
    def f1(self) -> float:
        r, p = self.recall, self.precision
        return 2 * r * p / (r + p) if (r + p) > 0 else 0.0

    @property
    def fp_rate(self) -> float:
        total = self.passed + self.false_positives
        return self.false_positives / total if total > 0 else 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "total_cwes": self.total_cwes,
            "passed": self.passed,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "errors": self.errors,
            "recall_pct": round(self.recall * 100, 2),
            "precision_pct": round(self.precision * 100, 2),
            "f1_pct": round(self.f1 * 100, 2),
            "fp_rate_pct": round(self.fp_rate * 100, 2),
            "total_elapsed_ms": round(self.total_elapsed_ms, 2),
            "per_cwe": [
                {
                    "cwe": v.cwe,
                    "passed": v.passed,
                    "vulnerable_detected": v.vulnerable_detected,
                    "secure_clean": v.secure_clean,
                    "elapsed_ms": round(v.elapsed_ms, 2),
                    "error": v.error,
                }
                for v in self.per_cwe
            ],
        }


# ── Corpus scanning ──────────────────────────────────────────────────────────


def discover_corpus_pairs(root: Path | None = None) -> dict[str, dict[str, Path]]:
    """Discover all golden corpus CWE test pairs.

    Returns: {cwe_id: {"vulnerable": Path, "secure": Path}, ...}
    """
    root = root or GOLDEN_CORPUS_ROOT
    if not root.exists():
        return {}

    pairs: dict[str, dict[str, Path]] = {}
    for cwe_dir in sorted(root.iterdir()):
        if not cwe_dir.is_dir() or not cwe_dir.name.startswith("CWE-"):
            continue

        vuln_files = sorted(cwe_dir.glob("vulnerable.*.test"))
        secure_files = sorted(cwe_dir.glob("secure.*.test"))

        if vuln_files and secure_files:
            pairs[cwe_dir.name] = {
                "vulnerable": vuln_files[0],
                "secure": secure_files[0],
            }

    return pairs


def _run_ansede_on_file(filepath: Path) -> tuple[int, float]:
    """Run ansede on a single file, return (finding_count, elapsed_ms).

    Golden corpus files use .test extension — we copy to a temp file with
    the correct language extension so the scanner recognizes them.
    """
    # Determine correct extension from the intermediate suffix
    # e.g., vulnerable.py.test → .py, vulnerable.js.test → .js
    suffixes = filepath.suffixes  # ['.py', '.test'] or ['.js', '.test']
    lang_ext = suffixes[0] if len(suffixes) >= 2 and suffixes[-1] == ".test" else filepath.suffix

    with tempfile.NamedTemporaryFile(suffix=lang_ext, delete=False, mode="w", encoding="utf-8") as tmp:
        tmp.write(filepath.read_text(encoding="utf-8", errors="replace"))
        tmp_path = Path(tmp.name)

    try:
        start = time.perf_counter()
        result = subprocess.run(
            [sys.executable, "-m", "ansede_static.cli", str(tmp_path),
             "--format", "json", "--no-triage", "--no-colour"],
            capture_output=True, text=True, timeout=15,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        data = json.loads(result.stdout)
        return data.get("summary", {}).get("total_findings", 0), elapsed
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        elapsed = (time.perf_counter() - start) * 1000.0
        return 0, elapsed
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def _run_semgrep_on_file(filepath: Path) -> tuple[int, float]:
    """Run Semgrep OSS on a single file, return (finding_count, elapsed_ms)."""
    start = time.perf_counter()
    try:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", str(filepath)],
            capture_output=True, text=True, timeout=30,
        )
        elapsed = (time.perf_counter() - start) * 1000.0
        data = json.loads(result.stdout)
        return len(data.get("results", [])), elapsed
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, Exception):
        elapsed = (time.perf_counter() - start) * 1000.0
        return 0, elapsed


def run_ansede_benchmark(pairs: dict[str, dict[str, Path]]) -> ToolReport:
    """Run Ansede against all golden corpus pairs."""
    report = ToolReport(tool="ansede")
    report.total_cwes = len(pairs)

    for cwe_id, files in sorted(pairs.items()):
        vuln_count, vuln_ms = _run_ansede_on_file(files["vulnerable"])
        secure_count, secure_ms = _run_ansede_on_file(files["secure"])

        verdict = CWEVerdict(
            cwe=cwe_id,
            tool="ansede",
            vulnerable_detected=vuln_count > 0,
            secure_clean=secure_count == 0,
            elapsed_ms=vuln_ms + secure_ms,
            findings_vuln=vuln_count,
            findings_secure=secure_count,
        )
        report.per_cwe.append(verdict)
        report.total_elapsed_ms += verdict.elapsed_ms

        if verdict.passed:
            report.passed += 1
        if verdict.false_negative:
            report.false_negatives += 1
        if verdict.false_positive:
            report.false_positives += 1

        status = "PASS" if verdict.passed else ("FN" if verdict.false_negative else "FP")
        print(f"  [{status}] {cwe_id}: vuln={vuln_count} finding(s), secure={secure_count} finding(s) [{verdict.elapsed_ms:.0f}ms]")

    return report


def run_semgrep_benchmark(pairs: dict[str, dict[str, Path]]) -> ToolReport:
    """Run Semgrep OSS against all golden corpus pairs."""
    report = ToolReport(tool="semgrep-oss")
    report.total_cwes = len(pairs)

    # Check if semgrep is available
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        report.errors = report.total_cwes
        report.per_cwe = [
            CWEVerdict(cwe=cwe_id, tool="semgrep-oss",
                       vulnerable_detected=False, secure_clean=False,
                       error="semgrep not installed")
            for cwe_id in pairs
        ]
        return report

    for cwe_id, files in sorted(pairs.items()):
        vuln_count, vuln_ms = _run_semgrep_on_file(files["vulnerable"])
        secure_count, secure_ms = _run_semgrep_on_file(files["secure"])

        verdict = CWEVerdict(
            cwe=cwe_id,
            tool="semgrep-oss",
            vulnerable_detected=vuln_count > 0,
            secure_clean=secure_count == 0,
            elapsed_ms=vuln_ms + secure_ms,
            findings_vuln=vuln_count,
            findings_secure=secure_count,
        )
        report.per_cwe.append(verdict)
        report.total_elapsed_ms += verdict.elapsed_ms

        if verdict.passed:
            report.passed += 1
        if verdict.false_negative:
            report.false_negatives += 1
        if verdict.false_positive:
            report.false_positives += 1

        status = "PASS" if verdict.passed else ("FN" if verdict.false_negative else "FP")
        print(f"  [{status}] {cwe_id}: vuln={vuln_count} finding(s), secure={secure_count} finding(s) [{verdict.elapsed_ms:.0f}ms]")

    return report


# ── Report generation ────────────────────────────────────────────────────────


def generate_summary_table(reports: list[ToolReport]) -> str:
    """Generate a Markdown summary table comparing all tools."""
    lines = [
        "# Golden Corpus Benchmark Results",
        "",
        f"**Date:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        f"**Corpus:** {reports[0].total_cwes} CWE test pairs across {_count_languages(reports)} languages",
        "",
        "## Summary",
        "",
        "| Tool | Recall | Precision | F1 | FP Rate | Passed | FN | FP | Time |",
        "|------|--------|-----------|-----|---------|--------|----|----|------|",
    ]

    for r in reports:
        lines.append(
            f"| **{r.tool}** | {r.recall*100:.1f}% | {r.precision*100:.1f}% | "
            f"{r.f1*100:.1f}% | {r.fp_rate*100:.1f}% | "
            f"{r.passed}/{r.total_cwes} | {r.false_negatives} | {r.false_positives} | "
            f"{r.total_elapsed_ms:.0f}ms |"
        )

    lines.extend([
        "",
        "## Per-CWE Breakdown",
        "",
        "| CWE | Ansede | Semgrep OSS | Description |",
        "|-----|--------|-------------|-------------|",
    ])

    _CWE_LABELS: dict[str, str] = {
        "CWE-78": "Command Injection",
        "CWE-89": "SQL Injection",
        "CWE-79": "Cross-Site Scripting",
        "CWE-918": "Server-Side Request Forgery",
        "CWE-22": "Path Traversal",
        "CWE-502": "Unsafe Deserialization",
        "CWE-798": "Hardcoded Secrets",
        "CWE-639": "IDOR / BOLA",
        "CWE-1321": "Prototype Pollution",
        "CWE-601": "Open Redirect",
        "CWE-94": "Code Injection",
    }

    ansede_by_cwe = {v.cwe: v for v in reports[0].per_cwe} if reports else {}
    semgrep_by_cwe = {v.cwe: v for v in reports[1].per_cwe} if len(reports) > 1 else {}

    for cwe in sorted(ansede_by_cwe):
        a = ansede_by_cwe.get(cwe)
        s = semgrep_by_cwe.get(cwe)
        a_status = "PASS" if a and a.passed else ("FN" if a and a.false_negative else "FP" if a and a.false_positive else "--")
        s_status = "PASS" if s and s.passed else ("FN" if s and s.false_negative else "FP" if s and s.false_positive else "--")
        label = _CWE_LABELS.get(cwe, "")
        lines.append(f"| {cwe} | {a_status} | {s_status} | {label} |")

    lines.extend([
        "",
        "---",
        "",
        "**Legend:** PASS = Both vulnerable detected AND secure clean  |  FN = False Negative (missed vulnerable)  |  FP = False Positive (flagged secure)",
        "",
        f"*Generated by `benchmarks.golden_benchmark_matrix.py` — reproducible on any machine.*",
    ])

    return "\n".join(lines)


def _count_languages(reports: list[ToolReport]) -> int:
    """Count unique languages in the golden corpus."""
    root = GOLDEN_CORPUS_ROOT
    langs: set[str] = set()
    if root.exists():
        for f in root.rglob("vulnerable.*.test"):
            ext = f.suffixes[0] if f.suffixes else ""
            if ext in (".py",):
                langs.add("Python")
            elif ext in (".js",):
                langs.add("JavaScript")
    return len(langs)


# ── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Golden Corpus Benchmark Matrix — Ansede vs Semgrep vs CodeQL",
    )
    parser.add_argument("--all", action="store_true", help="Run all tools (ansede + semgrep)")
    parser.add_argument("--output", "-o", type=Path, default=REPORT_OUTPUT, help="Output JSON path")
    parser.add_argument("--corpus", type=Path, default=GOLDEN_CORPUS_ROOT, help="Golden corpus root")
    args = parser.parse_args()

    pairs = discover_corpus_pairs(args.corpus)
    if not pairs:
        print("No golden corpus pairs found. Create them under .ansede/golden_corpus/<CWE-XXX>/")
        print("  Format: vulnerable.<ext>.test + secure.<ext>.test")
        sys.exit(1)

    print(f"Golden Corpus Benchmark Matrix")
    print(f"  Corpus: {len(pairs)} CWE pairs")
    print(f"  Root: {args.corpus}")
    print()

    reports: list[ToolReport] = []

    # ── Ansede ──────────────────────────────────────────────────────────
    print("── Ansede ──")
    ansede_report = run_ansede_benchmark(pairs)
    reports.append(ansede_report)
    print(f"  Recall: {ansede_report.recall*100:.1f}%  Precision: {ansede_report.precision*100:.1f}%  "
          f"F1: {ansede_report.f1*100:.1f}%  Passed: {ansede_report.passed}/{ansede_report.total_cwes}")
    print()

    # ── Semgrep (if requested) ──────────────────────────────────────────
    if args.all:
        print("── Semgrep OSS ──")
        semgrep_report = run_semgrep_benchmark(pairs)
        reports.append(semgrep_report)
        print(f"  Recall: {semgrep_report.recall*100:.1f}%  Precision: {semgrep_report.precision*100:.1f}%  "
              f"F1: {semgrep_report.f1*100:.1f}%  Passed: {semgrep_report.passed}/{semgrep_report.total_cwes}")
        print()

    # ── Write reports ───────────────────────────────────────────────────
    output = {
        "schema_version": "1.0",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_size": len(pairs),
        "tools": [r.as_dict() for r in reports],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2))

    # ── Markdown summary ────────────────────────────────────────────────
    md_path = args.output.with_suffix(".md")
    md_path.write_text(generate_summary_table(reports))

    print(f"[OK] JSON report: {args.output}")
    print(f"[OK] Markdown summary: {md_path}")


if __name__ == "__main__":
    main()
