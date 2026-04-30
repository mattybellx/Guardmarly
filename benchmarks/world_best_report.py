"""
benchmarks.world_best_report
────────────────────────────
Gold-release honesty protocol runner for ansede-static.

Runs:
  1) CVE baseline benchmark (recall/precision/f1/fp-rate)
  2) Web-wild harness benchmark (real-repo stratified sample)
  3) Consolidated world_best_report.json with gates:
       - true recall
       - noise quotient (findings per 1k LOC)
       - regression status

Zero-dependency; stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from benchmarks.cve_recall_runner import run_cve_recall
from benchmarks.web_wild_harness import RepoSpec, run_web_wild_harness
from ansede_static.engine.triage import deploy_candidate_suppressions_with_cve_guard


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _noise_quotient(samples: list[dict[str, Any]]) -> float:
    total_findings = sum(
        int(sample.get("finding_count_scored", sample.get("finding_count", 0)))
        for sample in samples
    )
    total_lines = sum(int(sample.get("lines_scanned", 0)) for sample in samples)
    return round(_safe_div(total_findings * 1000.0, total_lines), 2)


def _core_regression(cve_report_before: dict[str, Any], cve_report_after: dict[str, Any]) -> dict[str, Any]:
    before_cases = cve_report_before.get("cases", [])
    after_cases = cve_report_after.get("cases", [])
    failed_before = {case.get("cve_id", "") for case in before_cases if isinstance(case, dict) and not case.get("passed", False)}
    failed_after = {case.get("cve_id", "") for case in after_cases if isinstance(case, dict) and not case.get("passed", False)}
    newly_lost = sorted(failed_after - failed_before)
    return {
        "core_cases": len(after_cases),
        "failed_cases_before": sorted(failed_before),
        "failed_cases_after": sorted(failed_after),
        "newly_lost_cases": newly_lost,
        "lost_core_findings": len(newly_lost),
        "passed": len(newly_lost) == 0,
    }


def build_world_best_report(
    *,
    web_n_files: int,
    web_min_labeled: int,
    web_seed: int,
    web_cache_dir: Path,
    web_refresh: bool,
    web_offline: bool,
    web_max_file_bytes: int,
    web_severity_min: str,
    web_js_backend: str,
    suppression_output: Path,
    suppression_min_occurrences: int,
    suppression_max_enable: int,
    suppression_cve_budget: int,
    quiet: bool,
) -> dict[str, Any]:
    cve_report_pre = run_cve_recall(quiet=quiet)

    web_report_pre = run_web_wild_harness(
        repos=[
            RepoSpec(slug="OWASP/NodeGoat"),
            RepoSpec(slug="pallets/flask"),
            RepoSpec(slug="expressjs/express"),
            RepoSpec(slug="django/django"),
            RepoSpec(slug="tiangolo/fastapi"),
        ],
        n_files=max(1, web_n_files),
        min_labeled=max(0, web_min_labeled),
        seed=web_seed,
        cache_dir=web_cache_dir,
        refresh=web_refresh,
        offline=web_offline,
        max_file_bytes=max(1024, web_max_file_bytes),
        severity_min=web_severity_min,
        js_backend=web_js_backend,
        suppression_config=None,
        quiet=quiet,
    )

    cve_summary_pre = cve_report_pre.get("summary", {})
    samples_pre = web_report_pre.get("samples", [])

    web_report_path = suppression_output.with_name(f"{suppression_output.stem}_web_wild.json")
    web_report_path.parent.mkdir(parents=True, exist_ok=True)
    web_report_path.write_text(json.dumps(web_report_pre, indent=2), encoding="utf-8")

    suppression_rollout = deploy_candidate_suppressions_with_cve_guard(
        web_report_path,
        output_path=suppression_output,
        min_occurrences=suppression_min_occurrences,
        max_enable=suppression_max_enable,
        cve_regression_budget=suppression_cve_budget,
    )

    web_report_post = run_web_wild_harness(
        repos=[
            RepoSpec(slug="OWASP/NodeGoat"),
            RepoSpec(slug="pallets/flask"),
            RepoSpec(slug="expressjs/express"),
            RepoSpec(slug="django/django"),
            RepoSpec(slug="tiangolo/fastapi"),
        ],
        n_files=max(1, web_n_files),
        min_labeled=max(0, web_min_labeled),
        seed=web_seed,
        cache_dir=web_cache_dir,
        refresh=False,
        offline=web_offline,
        max_file_bytes=max(1024, web_max_file_bytes),
        severity_min=web_severity_min,
        js_backend=web_js_backend,
        suppression_config=suppression_output,
        quiet=quiet,
    )

    samples_post = web_report_post.get("samples", [])
    noise_quotient_pre = _noise_quotient(samples_pre if isinstance(samples_pre, list) else [])
    noise_quotient_post = _noise_quotient(samples_post if isinstance(samples_post, list) else [])
    cve_report_post = run_cve_recall(suppression_config=suppression_output, quiet=quiet)
    cve_summary_post = cve_report_post.get("summary", {})
    regression = _core_regression(cve_report_pre, cve_report_post)

    truth = {
        "true_recall_pct": float(cve_summary_post.get("recall", 0.0)),
        "fp_rate_pct": float(cve_summary_post.get("fp_rate", 0.0)),
        "precision_pct": float(cve_summary_post.get("precision", 0.0)),
        "f1_pct": float(cve_summary_post.get("f1", 0.0)),
    }

    gates = {
        "gold_cve_recall_gte_90": truth["true_recall_pct"] >= 90.0,
        "gold_cve_fp_rate_lte_10": truth["fp_rate_pct"] <= 10.0,
        "noise_quotient_lt_2": noise_quotient_post < 2.0,
        "no_regression_in_core_findings": regression["passed"],
    }

    return {
        "kind": "ansede-world-best-report",
        "version": 1,
        "cve": {
            "pre_suppression": cve_report_pre,
            "post_suppression": cve_report_post,
        },
        "web_wild": {
            "pre_suppression": web_report_pre,
            "post_suppression": web_report_post,
        },
        "honesty": {
            "true_recall": truth,
            "noise_quotient_findings_per_1k_loc": noise_quotient_post,
            "noise_quotient_pre_suppression": noise_quotient_pre,
            "cve_fp_rate_pre_suppression": float(cve_summary_pre.get("fp_rate", 0.0)),
            "regression_check": regression,
            "gates": gates,
            "gold_ready": all(gates.values()),
        },
        "suppression_rollout": suppression_rollout,
        "notes": [
            "Web-wild labels are weak supervision and under-approximate true vulnerability prevalence.",
            "CVE corpus is synthetic but deterministic and suitable for regression gates.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static world-best honesty protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.world_best_report --web-n-files 1000 --web-min-labeled 200 --output world_best_report.json
              python -m benchmarks.world_best_report --web-n-files 200 --quiet --json
            """
        ),
    )
    parser.add_argument("--web-n-files", type=int, default=1000, metavar="N",
                        help="Web-wild sample size")
    parser.add_argument("--web-min-labeled", type=int, default=200, metavar="N",
                        help="Minimum weak-labeled files in sample")
    parser.add_argument("--web-seed", type=int, default=1337,
                        help="Random seed")
    parser.add_argument("--web-cache-dir", type=Path, default=Path(Path.cwd() / "benchmarks" / "online_random_samples"), metavar="DIR",
                        help="Repo cache directory")
    parser.add_argument("--web-refresh", action="store_true",
                        help="Refresh online cache before run")
    parser.add_argument("--web-offline", action="store_true",
                        help="Use cache only")
    parser.add_argument("--web-max-file-bytes", type=int, default=256_000, metavar="BYTES",
                        help="Skip larger files")
    parser.add_argument("--web-severity-min", choices=["critical", "high", "medium", "low", "info"], default="high",
                        help="Minimum severity for predicted labels")
    parser.add_argument("--web-js-backend", choices=["auto", "classic", "structural"], default="auto",
                        help="JS backend")
    parser.add_argument("--suppression-output", type=Path, default=Path("suppression_candidates.json"), metavar="FILE",
                        help="Auto-suppression candidate output with CVE guard validation")
    parser.add_argument("--suppression-min-occurrences", type=int, default=3, metavar="N",
                        help="Minimum recurring web-wild occurrences before suppression candidacy")
    parser.add_argument("--suppression-max-enable", type=int, default=8, metavar="N",
                        help="Maximum candidate suppressions to auto-enable before CVE guard")
    parser.add_argument("--suppression-cve-budget", type=int, default=0, metavar="N",
                        help="Allowed failed CVE core cases for suppression rollout")
    parser.add_argument("--output", type=Path, default=Path("world_best_report.json"), metavar="FILE",
                        help="Output report path")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress human-readable benchmark summaries")
    parser.add_argument("--json", action="store_true",
                        help="Print report JSON to stdout")
    args = parser.parse_args()

    report = build_world_best_report(
        web_n_files=args.web_n_files,
        web_min_labeled=args.web_min_labeled,
        web_seed=args.web_seed,
        web_cache_dir=args.web_cache_dir.resolve(),
        web_refresh=args.web_refresh,
        web_offline=args.web_offline,
        web_max_file_bytes=args.web_max_file_bytes,
        web_severity_min=args.web_severity_min,
        web_js_backend=args.web_js_backend,
        suppression_output=args.suppression_output,
        suppression_min_occurrences=args.suppression_min_occurrences,
        suppression_max_enable=args.suppression_max_enable,
        suppression_cve_budget=args.suppression_cve_budget,
        quiet=args.quiet,
    )

    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.json or args.quiet:
        print(json.dumps(report, indent=2))
    else:
        summary = report["honesty"]
        print("\nWorld-best honesty report generated")
        print(f"  True Recall:   {summary['true_recall']['true_recall_pct']:.2f}%")
        print(f"  CVE FP-rate:   {summary['true_recall']['fp_rate_pct']:.2f}%")
        print(f"  Noise quotient:{summary['noise_quotient_findings_per_1k_loc']:.2f} findings / 1k LOC")
        print(f"  Gold ready:    {summary['gold_ready']}")
        print(f"  Output:        {args.output}")


if __name__ == "__main__":
    main()
