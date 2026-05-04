"""
benchmarks.real_world_compare
─────────────────────────────
Curated apples-to-apples comparison runner for ansede-static versus a shallow
Semgrep-style baseline on pinned real-world files.

This does not invoke Semgrep itself. Instead, it uses a deliberately shallow,
syntax-oriented baseline that approximates pattern-only behavior so we can
compare deeper Ansede analysis against a stable, zero-dependency reference.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import scan_file
from benchmarks.external_corpus import (  # noqa: E402
    _default_cache_dir,
    _iter_files,
    _resolve_source_root,
    load_manifest,
)
from benchmarks.web_wild_harness import _metrics, _severity_allows  # noqa: E402


_SEMGREP_STYLE_PATTERNS: tuple[tuple[str, str | None, re.Pattern[str]], ...] = (
    ("CWE-95", None, re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE)),
    ("CWE-78", None, re.compile(r"shell\s*=\s*True|child_process\.exec\s*\(|subprocess\.(?:run|call|Popen|check_output)\s*\([^\n]*shell\s*=\s*True", re.IGNORECASE)),
    ("CWE-89", None, re.compile(r"SELECT\s+.+(?:\+|\$\{|%s)|execute\s*\(\s*f[\"']|(?:cursor|db)\.execute\s*\([^\n]*(?:\+|%|format\()", re.IGNORECASE)),
    ("CWE-79", "javascript", re.compile(r"innerHTML\s*=|document\.write\s*\(", re.IGNORECASE)),
    ("CWE-22", None, re.compile(r"os\.path\.join\s*\(|\bopen\s*\([^\n]*(?:request\.|req\.|filename|path)|fs\.(?:readFile|writeFile|open)\s*\([^\n]*(?:req\.|request\.)", re.IGNORECASE)),
    ("CWE-918", None, re.compile(r"requests\.(?:get|post|put|delete|request)\s*\(\s*\w+|fetch\s*\(\s*\w+|axios\.(?:get|post|put|delete)\s*\(\s*\w+", re.IGNORECASE)),
    ("CWE-601", None, re.compile(r"(?:res\.)?redirect\s*\(\s*(?:req\.|request\.|\w+\s*\?)", re.IGNORECASE)),
    ("CWE-1333", "javascript", re.compile(r"/(?:[^/\\]|\\.)*(?:\([^)]*[+*][^)]*\)|\[[^\]]+\][+*])(?:[^/\\]|\\.)*[+*](?:[^/\\]|\\.)*/[gimsuy]*", re.IGNORECASE)),
)


def _scan_ansede(files: list[Path], *, severity_min: str, js_backend: str) -> tuple[set[str], list[dict[str, Any]]]:
    predicted: set[str] = set()
    findings: list[dict[str, Any]] = []
    for file_path in files:
        result = scan_file(file_path, js_backend=js_backend)
        for finding in result.sorted_findings():
            payload = finding.as_dict(language=result.language)
            if payload.get("cwe") and _severity_allows(payload, severity_min):
                predicted.add(str(payload["cwe"]))
                findings.append({
                    "file": str(file_path),
                    "rule_id": payload.get("rule_id", ""),
                    "cwe": payload.get("cwe", ""),
                    "severity": payload.get("severity", ""),
                    "title": payload.get("title", ""),
                    "line": payload.get("line"),
                })
    return predicted, findings



def _scan_semgrep_style(files: list[Path], *, language: str | None) -> tuple[set[str], list[dict[str, Any]]]:
    predicted: set[str] = set()
    matches: list[dict[str, Any]] = []
    for file_path in files:
        code = file_path.read_text(encoding="utf-8", errors="replace")
        for cwe, lang_filter, pattern in _SEMGREP_STYLE_PATTERNS:
            if lang_filter is not None and language is not None and lang_filter != language:
                continue
            hit = pattern.search(code)
            if not hit:
                continue
            predicted.add(cwe)
            line = code[: hit.start()].count("\n") + 1
            matches.append({
                "file": str(file_path),
                "cwe": cwe,
                "line": line,
                "pattern": pattern.pattern[:120],
            })
    return predicted, matches



def _score(predicted: set[str], expected: set[str]) -> dict[str, int]:
    if expected:
        return {
            "tp": len(predicted & expected),
            "fp": len(predicted - expected),
            "fn": len(expected - predicted),
        }
    return {"tp": 0, "fp": len(predicted), "fn": 0}



def run_real_world_compare(
    manifest_path: str | Path,
    *,
    cache_dir: str | Path | None = None,
    refresh: bool = False,
    offline: bool = False,
    severity_min: str = "high",
    js_backend: str = "auto",
    quiet: bool = False,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = load_manifest(manifest_file)
    resolved_cache_dir = Path(cache_dir).resolve() if cache_dir is not None else _default_cache_dir().resolve()

    per_engine_cases: dict[str, list[dict[str, Any]]] = defaultdict(list)
    per_engine_totals: dict[str, dict[str, int]] = {
        "ansede": {"tp": 0, "fp": 0, "fn": 0},
        "semgrep_style": {"tp": 0, "fp": 0, "fn": 0},
    }

    case_inputs: list[dict[str, Any]] = []

    for entry in manifest.entries:
        base_path, source_record = _resolve_source_root(
            entry,
            manifest_file.parent,
            cache_dir=resolved_cache_dir,
            refresh=refresh,
            offline=offline,
        )
        files = _iter_files(base_path, entry)
        expected = set(entry.expected_cwes)

        ansede_predicted, ansede_findings = _scan_ansede(files, severity_min=severity_min, js_backend=entry.js_backend or js_backend)
        semgrep_predicted, semgrep_matches = _scan_semgrep_style(files, language=entry.language)

        scope_key = tuple(sorted(str(file_path.resolve()) for file_path in files))
        case_inputs.append({
            "entry": entry,
            "source_record": source_record,
            "expected": expected,
            "scope_key": scope_key,
            "predictions": {
                "ansede": (ansede_predicted, ansede_findings),
                "semgrep_style": (semgrep_predicted, semgrep_matches),
            },
        })

    scope_expected: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for case in case_inputs:
        scope_expected[case["scope_key"]].update(case["expected"])

    for case in case_inputs:
        entry = case["entry"]
        expected = case["expected"]
        source_record = case["source_record"]
        sibling_expected = scope_expected[case["scope_key"]]

        for engine, (predicted, details) in case["predictions"].items():
            score = {
                "tp": len(predicted & expected),
                "fp": len(predicted - sibling_expected),
                "fn": len(expected - predicted),
            }
            per_engine_totals[engine]["tp"] += score["tp"]
            per_engine_totals[engine]["fp"] += score["fp"]
            per_engine_totals[engine]["fn"] += score["fn"]
            per_engine_cases[engine].append({
                "case_id": entry.case_id,
                "repo": source_record.get("repo", entry.source.repo),
                "resolved_ref": source_record.get("resolved_ref", ""),
                "path": entry.path,
                "targets": list(entry.targets),
                "expected_cwes": sorted(expected),
                "predicted_cwes": sorted(predicted),
                "shared_scope_expected_cwes": sorted(sibling_expected),
                **score,
                "details": details,
                "notes": entry.notes,
            })

    engines: dict[str, Any] = {}
    for engine, totals in per_engine_totals.items():
        engines[engine] = {
            "summary": {
                **totals,
                **_metrics(totals["tp"], totals["fp"], totals["fn"]),
                "total_cases": len(per_engine_cases[engine]),
            },
            "cases": per_engine_cases[engine],
        }

    ansede_summary = engines["ansede"]["summary"]
    semgrep_summary = engines["semgrep_style"]["summary"]
    delta = {
        "recall_delta": round(ansede_summary["recall"] - semgrep_summary["recall"], 2),
        "precision_delta": round(ansede_summary["precision"] - semgrep_summary["precision"], 2),
        "f1_delta": round(ansede_summary["f1"] - semgrep_summary["f1"], 2),
        "fp_rate_delta": round(ansede_summary["fp_rate"] - semgrep_summary["fp_rate"], 2),
    }

    report = {
        "kind": "ansede-real-world-compare",
        "version": 1,
        "manifest": str(manifest_file),
        "cache_dir": str(resolved_cache_dir),
        "severity_min": severity_min,
        "engines": engines,
        "delta": delta,
        "notes": [
            "`semgrep_style` is a built-in shallow pattern baseline, not the Semgrep product.",
            "This manifest is a curated pinned real-world slice intended for apples-to-apples comparison.",
        ],
    }

    if not quiet:
        print()
        print("┌" + "─" * 72 + "┐")
        print("│{:^72}│".format("ansede-static Real-World Comparison"))
        print("│{:^72}│".format("Ansede vs shallow Semgrep-style baseline"))
        print("└" + "─" * 72 + "┘")
        print()
        for engine in ("ansede", "semgrep_style"):
            summary = engines[engine]["summary"]
            print(
                f"  {engine:<14} recall={summary['recall']:.2f}% precision={summary['precision']:.2f}% "
                f"f1={summary['f1']:.2f}% fp_rate={summary['fp_rate']:.2f}% "
                f"tp={summary['tp']} fp={summary['fp']} fn={summary['fn']}"
            )
        print()
        print(
            f"  Delta (Ansede - baseline): recall {delta['recall_delta']:+.2f} | "
            f"precision {delta['precision_delta']:+.2f} | f1 {delta['f1_delta']:+.2f} | "
            f"fp_rate {delta['fp_rate_delta']:+.2f}"
        )
        print()

    return report



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Curated real-world comparison runner for ansede-static",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.real_world_compare --manifest benchmarks/real_world_manifest.json
              python -m benchmarks.real_world_compare --offline --quiet --json
            """
        ),
    )
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/real_world_manifest.json"), metavar="FILE",
                        help="Pinned real-world manifest for comparison")
    parser.add_argument("--cache-dir", type=Path, default=None, metavar="DIR",
                        help="Cache directory for git-backed sources")
    parser.add_argument("--refresh", action="store_true",
                        help="Refresh git-backed sources before evaluation")
    parser.add_argument("--offline", action="store_true",
                        help="Use only locally cached sources")
    parser.add_argument("--severity-min", choices=["critical", "high", "medium", "low", "info"], default="high",
                        help="Minimum Ansede severity used for predicted labels")
    parser.add_argument("--js-backend", choices=["auto", "classic", "structural"], default="auto",
                        help="Fallback JS backend if manifest entry does not specify one")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress the human-readable summary")
    parser.add_argument("--json", action="store_true",
                        help="Print the final report as JSON")
    parser.add_argument("--output", type=Path, default=None, metavar="FILE",
                        help="Optional file to write the JSON report to")
    args = parser.parse_args()

    if args.refresh and args.offline:
        parser.error("--refresh and --offline cannot be used together")

    report = run_real_world_compare(
        args.manifest,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        severity_min=args.severity_min,
        js_backend=args.js_backend,
        quiet=args.quiet,
    )

    if args.output is not None:
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.json or args.quiet:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
