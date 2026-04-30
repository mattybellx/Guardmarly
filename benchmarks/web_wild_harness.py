"""
benchmarks.web_wild_harness
───────────────────────────
Repeatable “web wild” online corpus harness.

Capabilities:
  1) Download/update selected online repositories (git, shallow clone cache)
  2) Deterministically sample N random source files with a fixed seed
  3) Infer weak expectation labels (CWE candidates) from independent regex heuristics
  4) Run ansede-static on sampled files
  5) Produce CI-friendly scorecard with recall/precision/F1/FP-rate gates

This is intentionally conservative: expectation labels are heuristic and should be
considered weak supervision, not ground-truth vulnerability annotations.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import _JS_EXTS, _PYTHON_EXTS, scan_file
from ansede_static.engine.triage import apply_active_suppressions


_DEFAULT_REPOS: tuple[str, ...] = (
    "OWASP/NodeGoat",
    "pallets/flask",
    "expressjs/express",
    "django/django",
    "tiangolo/fastapi",
)

_SKIP_PATH_SEGMENTS: frozenset[str] = frozenset({
    "tests", "test", "docs", "doc", "examples", "example", "tutorial",
    "migrations", "locale", "i18n", "fixtures", "__pycache__", "node_modules",
})

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass(frozen=True)
class RepoSpec:
    slug: str  # owner/repo
    ref: str = ""


@dataclass(frozen=True)
class SampledFile:
    repo: str
    path: Path
    relative_path: str


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def _metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    recall = _safe_div(tp, tp + fn)
    precision = _safe_div(tp, tp + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fp_rate = _safe_div(fp, tp + fp)
    return {
        "recall": round(recall * 100.0, 2),
        "precision": round(precision * 100.0, 2),
        "f1": round(f1 * 100.0, 2),
        "fp_rate": round(fp_rate * 100.0, 2),
    }


def _default_cache_dir() -> Path:
    return Path(tempfile.gettempdir()) / "ansede-web-wild-cache"


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is required for web_wild_harness") from exc
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(details or f"git {' '.join(args)} failed") from exc
    return completed.stdout.strip()


def _on_rmtree_error(func, path: str, exc_info: tuple[type[BaseException], BaseException, object]) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    func(path)


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, onerror=_on_rmtree_error)


def _cache_path_for_repo(cache_dir: Path, slug: str) -> Path:
    safe = slug.replace("/", "__").replace("\\", "__")
    return cache_dir / safe


def _ensure_repo(repo: RepoSpec, *, cache_dir: Path, refresh: bool, offline: bool) -> tuple[Path, dict[str, Any]]:
    local = _cache_path_for_repo(cache_dir, repo.slug)
    cache_hit = local.exists()

    if refresh and local.exists():
        _remove_tree(local)
        cache_hit = False

    if not local.exists():
        if offline:
            raise FileNotFoundError(f"offline mode: missing cache for {repo.slug}")
        cache_dir.mkdir(parents=True, exist_ok=True)
        url = f"https://github.com/{repo.slug}.git"
        _run_git(["clone", "--quiet", "--depth", "1", url, str(local)])

    if repo.ref:
        try:
            _run_git(["checkout", "--quiet", repo.ref], cwd=local)
        except RuntimeError:
            if offline:
                raise
            _run_git(["fetch", "--quiet", "--all", "--tags"], cwd=local)
            _run_git(["checkout", "--quiet", repo.ref], cwd=local)

    resolved_ref = _run_git(["rev-parse", "HEAD"], cwd=local)
    return local, {
        "repo": repo.slug,
        "cache_hit": cache_hit,
        "resolved_ref": resolved_ref,
        "cache_path": str(local.resolve()),
    }


def _is_candidate_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in _PYTHON_EXTS or suffix in _JS_EXTS


def _collect_repo_files(root: Path, *, max_file_bytes: int) -> list[Path]:
    files: list[Path] = []
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        if not _is_candidate_file(file):
            continue
        rel_parts = {part.lower() for part in file.relative_to(root).parts}
        if rel_parts & _SKIP_PATH_SEGMENTS:
            continue
        try:
            if file.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        files.append(file)
    return files


_LABEL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CWE-95", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE)),
    ("CWE-78", re.compile(r"shell\s*=\s*True|child_process\.exec\s*\(", re.IGNORECASE)),
    ("CWE-89", re.compile(r"SELECT\s+.+\+|SELECT\s+.+\$\{|execute\s*\(\s*f[\"']", re.IGNORECASE)),
    ("CWE-79", re.compile(r"innerHTML\s*=|document\.write\s*\(", re.IGNORECASE)),
    ("CWE-22", re.compile(r"os\.path\.join\s*\(|send_file\s*\(.*join", re.IGNORECASE)),
    ("CWE-918", re.compile(r"requests\.(?:get|post)\s*\(\s*\w+|fetch\s*\(\s*\w+", re.IGNORECASE)),
    ("CWE-601", re.compile(r"redirect\s*\(\s*(?:req\.|request\.)", re.IGNORECASE)),
    ("CWE-798", re.compile(r"AKIA[0-9A-Z]{16}|SECRET_KEY\s*=\s*[\"'][^\"']+[\"']", re.IGNORECASE)),
)


def _infer_expected_labels(code: str) -> tuple[set[str], list[str]]:
    labels: set[str] = set()
    reasons: list[str] = []
    for cwe, rx in _LABEL_PATTERNS:
        if rx.search(code):
            labels.add(cwe)
            reasons.append(f"{cwe}: pattern {rx.pattern[:40]}...")
    return labels, reasons


def _severity_allows(finding: dict[str, Any], threshold: str) -> bool:
    s = str(finding.get("severity", "info")).lower()
    return _SEVERITY_ORDER.get(s, 0) >= _SEVERITY_ORDER.get(threshold.lower(), 0)


def _score_sample(
    sample: SampledFile,
    *,
    severity_min: str,
    js_backend: str,
    suppression_config: Path | None,
) -> dict[str, Any]:
    code = sample.path.read_text(encoding="utf-8", errors="replace")
    expected_labels, label_reasons = _infer_expected_labels(code)

    result = scan_file(sample.path, js_backend=js_backend)
    if suppression_config is not None:
        result.findings = apply_active_suppressions(
            result.findings,
            file_path=str(sample.path),
            suppression_config_path=suppression_config,
        )
    findings_payload = [f.as_dict(language=result.language) for f in result.sorted_findings()]
    scored_findings = [f for f in findings_payload if f.get("cwe") and _severity_allows(f, severity_min)]
    predicted_labels = {
        str(f.get("cwe"))
        for f in scored_findings
    }

    if expected_labels:
        tp = len(predicted_labels & expected_labels)
        fn = len(expected_labels - predicted_labels)
        fp = len(predicted_labels - expected_labels)
    else:
        tp = 0
        fn = 0
        fp = len(predicted_labels)

    return {
        "repo": sample.repo,
        "file": sample.relative_path,
        "language": result.language,
        "lines_scanned": result.lines_scanned,
        "finding_count": len(findings_payload),
        "finding_count_scored": len(scored_findings),
        "expected_labels": sorted(expected_labels),
        "label_reasons": label_reasons,
        "predicted_labels": sorted(predicted_labels),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "findings": findings_payload,
    }


def run_web_wild_harness(
    *,
    repos: list[RepoSpec],
    n_files: int,
    seed: int,
    cache_dir: Path,
    refresh: bool,
    offline: bool,
    max_file_bytes: int,
    min_labeled: int,
    severity_min: str,
    js_backend: str,
    suppression_config: Path | None,
    quiet: bool,
) -> dict[str, Any]:
    repo_meta: list[dict[str, Any]] = []
    candidates: list[SampledFile] = []

    for repo in repos:
        repo_root, meta = _ensure_repo(repo, cache_dir=cache_dir, refresh=refresh, offline=offline)
        repo_meta.append(meta)
        files = _collect_repo_files(repo_root, max_file_bytes=max_file_bytes)
        for file in files:
            candidates.append(
                SampledFile(
                    repo=repo.slug,
                    path=file,
                    relative_path=str(file.resolve().relative_to(repo_root.resolve())),
                )
            )

    if not candidates:
        return {
            "repos": repo_meta,
            "samples": [],
            "summary": {
                "sampled_files": 0,
                "labeled_files": 0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
                **_metrics(0, 0, 0),
            },
        }

    candidates = sorted(candidates, key=lambda x: (x.repo, x.relative_path))
    rng = random.Random(seed)
    sample_count = min(n_files, len(candidates))

    # Stratified random sampling: retain randomness while ensuring enough
    # weak-labeled files for meaningful precision/recall scoring.
    labeled_candidates: list[SampledFile] = []
    unlabeled_candidates: list[SampledFile] = []
    for candidate in candidates:
        try:
            code = candidate.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unlabeled_candidates.append(candidate)
            continue
        expected, _ = _infer_expected_labels(code)
        if expected:
            labeled_candidates.append(candidate)
        else:
            unlabeled_candidates.append(candidate)

    target_labeled = min(max(0, min_labeled), sample_count, len(labeled_candidates))
    sampled: list[SampledFile] = []
    if target_labeled > 0:
        sampled.extend(rng.sample(labeled_candidates, target_labeled))

    remaining = sample_count - len(sampled)
    if remaining > 0:
        pool = [c for c in candidates if c not in sampled]
        sampled.extend(rng.sample(pool, min(remaining, len(pool))))

    sample_reports = [
        _score_sample(
            sample,
            severity_min=severity_min,
            js_backend=js_backend,
            suppression_config=suppression_config,
        )
        for sample in sampled
    ]

    tp = sum(item["tp"] for item in sample_reports)
    fp = sum(item["fp"] for item in sample_reports)
    fn = sum(item["fn"] for item in sample_reports)
    labeled_files = sum(1 for item in sample_reports if item["expected_labels"])

    summary = {
        "sampled_files": len(sample_reports),
        "labeled_files": labeled_files,
        "labeled_candidate_pool": len(labeled_candidates),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        **_metrics(tp, fp, fn),
    }

    report = {
        "seed": seed,
        "n_files": n_files,
        "cache_dir": str(cache_dir),
        "suppression_config": str(suppression_config) if suppression_config else None,
        "repos": repo_meta,
        "samples": sample_reports,
        "summary": summary,
    }

    if not quiet:
        print()
        print("┌" + "─" * 72 + "┐")
        print("│{:^72}│".format("ansede-static Web Wild Harness"))
        print("│{:^72}│".format("Deterministic random online sample scorecard"))
        print("└" + "─" * 72 + "┘")
        print()
        for item in sample_reports:
            icon = "✓" if item["tp"] > 0 or not item["expected_labels"] else "✗"
            print(
                f"  {icon}  {item['repo']:<22} {item['file'][:38]:<38} "
                f"exp={len(item['expected_labels'])} pred={len(item['predicted_labels'])} "
                f"tp={item['tp']} fp={item['fp']} fn={item['fn']}"
            )
        print()
        print(
            "  Metrics: "
            f"Recall {summary['recall']:.2f}% | "
            f"Precision {summary['precision']:.2f}% | "
            f"F1 {summary['f1']:.2f}% | "
            f"FP-rate {summary['fp_rate']:.2f}%"
        )
        print(
            f"  Sampled files: {summary['sampled_files']} "
            f"(labeled in sample: {summary['labeled_files']}, labeled pool: {summary['labeled_candidate_pool']})"
        )
        print()

    return report


def _fails_thresholds(
    report: dict[str, Any],
    *,
    fail_under_recall: float,
    fail_under_precision: float,
    fail_under_f1: float,
    max_fp_rate: float,
) -> bool:
    summary = report["summary"]
    failed = False
    if fail_under_recall and summary["recall"] < fail_under_recall:
        failed = True
    if fail_under_precision and summary["precision"] < fail_under_precision:
        failed = True
    if fail_under_f1 and summary["f1"] < fail_under_f1:
        failed = True
    if max_fp_rate and summary["fp_rate"] > max_fp_rate:
        failed = True
    return failed


def _parse_repo_specs(values: list[str]) -> list[RepoSpec]:
    specs: list[RepoSpec] = []
    for raw in values:
        token = raw.strip()
        if not token:
            continue
        if "@" in token:
            slug, ref = token.split("@", 1)
            specs.append(RepoSpec(slug=slug.strip(), ref=ref.strip()))
        else:
            specs.append(RepoSpec(slug=token))
    return specs


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static web wild online corpus harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.web_wild_harness --n-files 40 --seed 1337
              python -m benchmarks.web_wild_harness --repos OWASP/NodeGoat pallets/flask --n-files 20
              python -m benchmarks.web_wild_harness --fail-under-recall 75 --fail-under-precision 45 --max-fp-rate 55 -q
              python -m benchmarks.web_wild_harness --refresh --json
            """
        ),
    )
    parser.add_argument("--repos", nargs="*", default=list(_DEFAULT_REPOS), metavar="OWNER/REPO[@REF]",
                        help="Repositories to sample (default curated set)")
    parser.add_argument("--n-files", type=int, default=40, metavar="N",
                        help="Number of random files to sample")
    parser.add_argument("--seed", type=int, default=1337,
                        help="Random seed for deterministic sampling")
    parser.add_argument("--cache-dir", type=Path, default=None, metavar="DIR",
                        help="Repository cache directory")
    parser.add_argument("--refresh", action="store_true",
                        help="Refresh repository cache before sampling")
    parser.add_argument("--offline", action="store_true",
                        help="Use existing cache only (no network)")
    parser.add_argument("--max-file-bytes", type=int, default=256_000, metavar="BYTES",
                        help="Skip files larger than this size")
    parser.add_argument("--min-labeled", type=int, default=5, metavar="N",
                        help="Minimum number of weak-labeled files to include when available")
    parser.add_argument("--severity-min", choices=["critical", "high", "medium", "low", "info"], default="high",
                        help="Minimum finding severity used for predicted labels")
    parser.add_argument("--js-backend", choices=["auto", "classic", "structural"], default="auto",
                        help="JS backend selection")
    parser.add_argument("--suppression-config", type=Path, default=None, metavar="FILE",
                        help="Optional suppression config JSON (enabled generated_rules applied before scoring)")
    parser.add_argument("--fail-under-recall", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if recall falls below this percentage")
    parser.add_argument("--fail-under-precision", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if precision falls below this percentage")
    parser.add_argument("--fail-under-f1", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if F1 falls below this percentage")
    parser.add_argument("--max-fp-rate", type=float, default=0.0, metavar="PCT",
                        help="Exit 1 if FP rate exceeds this percentage")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress human-readable summary")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON report")
    args = parser.parse_args()

    if args.refresh and args.offline:
        parser.error("--refresh and --offline cannot be used together")

    specs = _parse_repo_specs(args.repos)
    cache_dir = (args.cache_dir or _default_cache_dir()).resolve()

    report = run_web_wild_harness(
        repos=specs,
        n_files=max(1, args.n_files),
        seed=args.seed,
        cache_dir=cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        max_file_bytes=max(1024, args.max_file_bytes),
        min_labeled=max(0, args.min_labeled),
        severity_min=args.severity_min,
        js_backend=args.js_backend,
        suppression_config=args.suppression_config,
        quiet=args.quiet,
    )

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if _fails_thresholds(
        report,
        fail_under_recall=args.fail_under_recall,
        fail_under_precision=args.fail_under_precision,
        fail_under_f1=args.fail_under_f1,
        max_fp_rate=args.max_fp_rate,
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
