from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from benchmarks.web_wild_harness import (  # noqa: E402
    RepoSpec,
    SampledFile,
    _collect_repo_files,
    _default_cache_dir,
    _ensure_repo,
    _load_curated_labels,
    _metrics,
    _parse_repo_specs,
    _score_sample,
    _select_samples as _select_samples_from_harness,
)


def _format_duration(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    mins, secs = divmod(total, 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours:02d}:{mins:02d}:{secs:02d}"
    return f"{mins:02d}:{secs:02d}"


def _build_sample_pool(
    *,
    repos: list[RepoSpec],
    cache_dir: Path,
    refresh: bool,
    offline: bool,
    max_file_bytes: int,
    vendor_mode: str,
) -> tuple[list[dict[str, Any]], list[SampledFile]]:
    repo_meta: list[dict[str, Any]] = []
    candidates: list[SampledFile] = []
    for repo in repos:
        repo_root, meta = _ensure_repo(repo, cache_dir=cache_dir, refresh=refresh, offline=offline)
        repo_meta.append(meta)
        for file in _collect_repo_files(repo_root, max_file_bytes=max_file_bytes, vendor_mode=vendor_mode):
            candidates.append(
                SampledFile(
                    repo=repo.slug,
                    path=file,
                    relative_path=str(file.resolve().relative_to(repo_root.resolve())).replace("\\", "/"),
                )
            )
    candidates.sort(key=lambda item: (item.repo, item.relative_path))
    return repo_meta, candidates


def _select_samples(
    *,
    candidates: list[SampledFile],
    n_files: int,
    min_labeled: int,
    seed: int,
    label_mode: str,
    curated_labels: dict[tuple[str, str], Any],
    sampling_mode: str,
) -> tuple[list[SampledFile], int]:
    return _select_samples_from_harness(
        candidates=candidates,
        n_files=n_files,
        min_labeled=min_labeled,
        seed=seed,
        label_mode=label_mode,
        curated_labels=curated_labels,
        sampling_mode=sampling_mode,
    )


def _emit_progress(
    *,
    index: int,
    total: int,
    started_at: float,
    sample: SampledFile,
    result: dict[str, Any],
) -> None:
    elapsed = time.perf_counter() - started_at
    avg = elapsed / index if index else 0.0
    remaining = max(0, total - index)
    eta = avg * remaining
    status = "labeled" if result.get("expected_labels") else "unlabeled"
    print(
        f"[{index}/{total}] {sample.repo}:{sample.relative_path} | {status} | "
        f"exp={len(result.get('expected_labels', []))} pred={len(result.get('predicted_labels', []))} "
        f"tp={result.get('tp', 0)} fp={result.get('fp', 0)} fn={result.get('fn', 0)} | "
        f"elapsed={_format_duration(elapsed)} avg/file={avg:.2f}s eta={_format_duration(eta)}",
        flush=True,
    )


def _summarize(
    *,
    repo_meta: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    labeled_pool: int,
    args: argparse.Namespace,
    started_at: float,
) -> dict[str, Any]:
    tp = sum(int(item["tp"]) for item in reports)
    fp = sum(int(item["fp"]) for item in reports)
    fn = sum(int(item["fn"]) for item in reports)
    labeled_files = sum(1 for item in reports if item.get("expected_labels"))
    metrics = _metrics(tp, fp, fn)

    repo_counter = Counter(item["repo"] for item in reports)
    predicted_counter = Counter(
        cwe
        for item in reports
        for cwe in item.get("predicted_labels", [])
    )
    expected_counter = Counter(
        cwe
        for item in reports
        for cwe in item.get("expected_labels", [])
    )
    missed_counter = Counter(
        cwe
        for item in reports
        for cwe in set(item.get("expected_labels", [])) - set(item.get("predicted_labels", []))
    )
    unexpected_counter = Counter(
        cwe
        for item in reports
        for cwe in set(item.get("predicted_labels", [])) - set(item.get("expected_labels", []))
    )

    misses = [
        {
            "repo": item["repo"],
            "file": item["file"],
            "expected_only": sorted(set(item.get("expected_labels", [])) - set(item.get("predicted_labels", []))),
            "predicted_labels": item.get("predicted_labels", []),
        }
        for item in reports
        if set(item.get("expected_labels", [])) - set(item.get("predicted_labels", []))
    ]
    unexpected = [
        {
            "repo": item["repo"],
            "file": item["file"],
            "predicted_only": sorted(set(item.get("predicted_labels", [])) - set(item.get("expected_labels", []))),
            "expected_labels": item.get("expected_labels", []),
            "finding_count_scored": item.get("finding_count_scored", 0),
        }
        for item in reports
        if set(item.get("predicted_labels", [])) - set(item.get("expected_labels", []))
    ]

    return {
        "kind": "ansede-live-web-wild-report",
        "version": 1,
        "generated_at_epoch": time.time(),
        "elapsed_seconds": round(time.perf_counter() - started_at, 2),
        "config": {
            "repos": [repo.slug for repo in args.repos],
            "n_files": args.n_files,
            "min_labeled": args.min_labeled,
            "seed": args.seed,
            "cache_dir": str(args.cache_dir),
            "max_file_bytes": args.max_file_bytes,
            "sampling_mode": args.sampling_mode,
            "vendor_mode": args.vendor_mode,
            "label_mode": args.label_mode,
            "label_manifest": str(args.label_manifest) if args.label_manifest else None,
            "severity_min": args.severity_min,
            "js_backend": args.js_backend,
            "suppression_config": str(args.suppression_config) if args.suppression_config else None,
        },
        "repos": repo_meta,
        "summary": {
            "sampled_files": len(reports),
            "labeled_files": labeled_files,
            "labeled_candidate_pool": labeled_pool,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            **metrics,
        },
        "breakdown": {
            "files_by_repo": dict(repo_counter),
            "expected_labels": dict(expected_counter.most_common()),
            "predicted_labels": dict(predicted_counter.most_common()),
            "missed_labels": dict(missed_counter.most_common()),
            "unexpected_labels": dict(unexpected_counter.most_common()),
        },
        "misses": misses,
        "unexpected_predictions": unexpected,
        "samples": reports,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Live-progress web-wild benchmark runner for ansede-static")
    parser.add_argument("--repos", nargs="*", default=[
        "OWASP/NodeGoat",
        "pallets/flask",
        "expressjs/express",
        "django/django",
        "tiangolo/fastapi",
    ])
    parser.add_argument("--n-files", type=int, default=250)
    parser.add_argument("--min-labeled", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20260504)
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".ansede" / "web-wild-cache")
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--max-file-bytes", type=int, default=256_000)
    parser.add_argument("--sampling-mode", choices=["global", "balanced"], default="global")
    parser.add_argument("--vendor-mode", choices=["include", "exclude", "only"], default="include")
    parser.add_argument("--label-mode", choices=["weak", "curated", "hybrid"], default="weak")
    parser.add_argument("--label-manifest", type=Path, default=None)
    parser.add_argument("--severity-min", choices=["critical", "high", "medium", "low", "info"], default="high")
    parser.add_argument("--js-backend", choices=["auto", "classic", "structural"], default="auto")
    parser.add_argument("--suppression-config", type=Path, default=ROOT / "suppression_candidates.json")
    parser.add_argument("--output", type=Path, default=ROOT / "live_web_wild_report.json")
    args = parser.parse_args()

    if args.refresh and args.offline:
        raise SystemExit("--refresh and --offline cannot be used together")

    args.cache_dir = args.cache_dir.resolve()
    args.repos = _parse_repo_specs(args.repos)
    if args.cache_dir is None:
        args.cache_dir = _default_cache_dir().resolve()
    if args.label_manifest is None and args.label_mode in {"curated", "hybrid"}:
        args.label_manifest = ROOT / "benchmarks" / "real_world_manifest.json"
    curated_labels = _load_curated_labels(args.label_manifest)

    print("Preparing candidate pool...", flush=True)
    started_at = time.perf_counter()
    repo_meta, candidates = _build_sample_pool(
        repos=args.repos,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        max_file_bytes=max(1024, args.max_file_bytes),
        vendor_mode=args.vendor_mode,
    )
    print(f"Collected {len(candidates)} candidate files across {len(repo_meta)} repos.", flush=True)

    sampled, labeled_pool = _select_samples(
        candidates=candidates,
        n_files=max(1, args.n_files),
        min_labeled=max(0, args.min_labeled),
        seed=args.seed,
        label_mode=args.label_mode,
        curated_labels=curated_labels,
        sampling_mode=args.sampling_mode,
    )
    print(
        f"Sample selected: {len(sampled)} files (requested={args.n_files}, labeled_pool={labeled_pool}, min_labeled={args.min_labeled}).",
        flush=True,
    )

    reports: list[dict[str, Any]] = []
    total = len(sampled)
    for index, sample in enumerate(sampled, start=1):
        result = _score_sample(
            sample,
            severity_min=args.severity_min,
            js_backend=args.js_backend,
            suppression_config=args.suppression_config,
            label_mode=args.label_mode,
            curated_labels=curated_labels,
        )
        reports.append(result)
        _emit_progress(index=index, total=total, started_at=started_at, sample=sample, result=result)

    report = _summarize(
        repo_meta=repo_meta,
        reports=reports,
        labeled_pool=labeled_pool,
        args=args,
        started_at=started_at,
    )
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print("\nLive web-wild benchmark complete.", flush=True)
    print(
        "Summary: "
        f"sampled={summary['sampled_files']} labeled={summary['labeled_files']} "
        f"tp={summary['tp']} fp={summary['fp']} fn={summary['fn']} "
        f"recall={summary['recall']:.2f}% precision={summary['precision']:.2f}% "
        f"f1={summary['f1']:.2f}% fp_rate={summary['fp_rate']:.2f}% ",
        flush=True,
    )
    print(f"Elapsed: {_format_duration(report['elapsed_seconds'])}", flush=True)
    print(f"Report: {args.output}", flush=True)


if __name__ == "__main__":
    main()