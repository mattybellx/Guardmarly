"""
benchmarks.live_random_repo_sample
──────────────────────────────────
Live random-sample benchmark over small public GitHub repositories.

This runner measures exact operational metrics on unlabeled real-world repos:
- repository / file / LOC coverage
- wall-clock scan time and throughput
- raw vs cluster-adjusted finding density
- audit verdict distribution (TP / FP / LIKELY_FP / NEEDS_REVIEW / VENDOR_NOISE)

Important limitation:
Because the sampled repositories are not manually labeled ground truth corpora,
this script does NOT claim exact precision/recall. It reports exact live scan
and audit metrics for the current engine state.
"""
from __future__ import annotations

import argparse
import json
import logging
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import (  # noqa: E402
    _CSHARP_EXTS,
    _GO_EXTS,
    _JAVA_EXTS,
    _JS_EXTS,
    _PYTHON_EXTS,
    scan_file,
)
from ansede_static.engine.audit import audit_findings  # noqa: E402
from benchmarks.benchmark_metrics import cluster_adjusted_stats, noise_quotient  # noqa: E402

_log = logging.getLogger(__name__)

SUPPORTED_LANGUAGES: tuple[str, ...] = (
    "python",
    "javascript",
    "java",
    "csharp",
    "go",
)

DEFAULT_LANGUAGE_QUOTAS: dict[str, int] = {
    "python": 10,
    "javascript": 10,
    "java": 10,
    "csharp": 10,
    "go": 10,
}

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".next",
    ".nuxt",
    ".idea",
    ".vscode",
}

LANGUAGE_QUERY_TOKENS = {
    "python": "Python",
    "javascript": "JavaScript",
    "java": "Java",
    "csharp": "C%23",
    "go": "Go",
}

LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "python": _PYTHON_EXTS,
    "javascript": _JS_EXTS,
    "java": _JAVA_EXTS,
    "csharp": _CSHARP_EXTS,
    "go": _GO_EXTS,
}

HTML_SEARCH_EXCLUDED_OWNERS = {
    "about",
    "account",
    "apps",
    "collections",
    "events",
    "explore",
    "features",
    "issues",
    "login",
    "marketplace",
    "notifications",
    "orgs",
    "pulls",
    "search",
    "sessions",
    "settings",
    "signup",
    "site",
    "sponsors",
    "teams",
    "topics",
    "trending",
    "users",
}


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout.strip()


def _github_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ansede-static-live-benchmark",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _github_html(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ansede-static-live-benchmark",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", "replace")


def _search_small_repos_api(language: str, *, max_size_kb: int, per_page: int, page: int, sort: str) -> list[dict[str, Any]]:
    query = (
        f"language:{LANGUAGE_QUERY_TOKENS[language]} "
        f"size:1..{max_size_kb} archived:false fork:false mirror:false"
    )
    params = urllib.parse.urlencode(
        {
            "q": query,
            "sort": sort,
            "order": "desc",
            "per_page": per_page,
            "page": page,
        }
    )
    payload = _github_json(f"https://api.github.com/search/repositories?{params}")
    return list(payload.get("items", []))


def _search_small_repos_html(language: str, *, max_size_kb: int, pages: int, sort: str) -> list[dict[str, Any]]:
    query = (
        f"language:{LANGUAGE_QUERY_TOKENS[language]} "
        f"size:1..{max_size_kb} archived:false fork:false"
    )
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    pattern = re.compile(r'href="/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"')

    for page in range(1, pages + 1):
        params = urllib.parse.urlencode(
            {
                "type": "repositories",
                "q": query,
                "p": page,
                "s": sort,
            }
        )
        html = _github_html(f"https://github.com/search?{params}")
        for full_name in pattern.findall(html):
            owner, repo = full_name.split("/", 1)
            if owner.lower() in HTML_SEARCH_EXCLUDED_OWNERS:
                continue
            if repo.lower() in {"followers", "following", "repositories", "projects", "stars"}:
                continue
            if full_name in seen:
                continue
            seen.add(full_name)
            candidates.append(
                {
                    "full_name": full_name,
                    "clone_url": f"https://github.com/{full_name}.git",
                    "html_url": f"https://github.com/{full_name}",
                    "language": LANGUAGE_QUERY_TOKENS[language],
                    "size": None,
                    "stargazers_count": 0,
                    "default_branch": "",
                    "discovery_mode": "github-html-search",
                }
            )
    return candidates


def _search_small_repos(language: str, *, max_size_kb: int, candidate_goal: int, per_page: int, sort: str) -> list[dict[str, Any]]:
    try:
        pool = _search_small_repos_api(language, max_size_kb=max_size_kb, per_page=per_page, page=1, sort=sort)
        if pool:
            for item in pool:
                item.setdefault("discovery_mode", "github-api-search")
            return pool
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise
        _log.info("GitHub Search API rate-limited for %s; falling back to HTML search", language)
    pages = max(2, (candidate_goal + 9) // 10)
    return _search_small_repos_html(language, max_size_kb=max_size_kb, pages=pages, sort=sort)


def _supported_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    return any(
        suffix in ext_group
        for ext_group in (
            _PYTHON_EXTS,
            _JS_EXTS,
            _GO_EXTS,
            _JAVA_EXTS,
            _CSHARP_EXTS,
        )
    )


def _guess_language_from_suffix(path: Path) -> str | None:
    suffix = path.suffix.lower()
    for language, exts in LANGUAGE_EXTENSIONS.items():
        if suffix in exts:
            return language
    return None


def _iter_supported_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for child in repo_root.rglob("*"):
        if not child.is_file():
            continue
        if any(part in IGNORE_DIRS for part in child.parts):
            continue
        if _supported_file(child):
            files.append(child)
    return sorted(files)


def _repo_source_bytes(repo_root: Path) -> int:
    total = 0
    for child in repo_root.rglob("*"):
        if not child.is_file():
            continue
        if any(part in IGNORE_DIRS for part in child.parts):
            continue
        try:
            total += child.stat().st_size
        except OSError:
            continue
    return total


def _dominant_repo_language(repo_root: Path) -> str:
    counts: Counter[str] = Counter()
    for file_path in _iter_supported_files(repo_root):
        language = _guess_language_from_suffix(file_path)
        if language:
            counts[language] += 1
    if not counts:
        return "unknown"
    return counts.most_common(1)[0][0]


def _median(values: list[float]) -> float:
    return round(float(statistics.median(values)), 4) if values else 0.0


def _mean(values: list[float]) -> float:
    return round(float(statistics.fmean(values)), 4) if values else 0.0


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _discover_local_repo_candidates(local_roots: list[Path]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for root in local_roots:
        if not root.exists():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            name_key = child.name.lower()
            if name_key in seen_names:
                continue
            files = _iter_supported_files(child)
            if not files:
                continue
            seen_names.add(name_key)
            source_bytes = _repo_source_bytes(child)
            candidates.append(
                {
                    "full_name": child.name,
                    "clone_url": "",
                    "html_url": "",
                    "language": _dominant_repo_language(child),
                    "size": int(round(source_bytes / 1024.0)),
                    "stargazers_count": 0,
                    "default_branch": "",
                    "discovery_mode": "local-existing",
                    "dominant_language": _dominant_repo_language(child),
                    "local_path": str(child.resolve()),
                    "source_bytes": source_bytes,
                    "supported_file_count": len(files),
                }
            )
    return candidates


def _select_local_candidates(
    *,
    target_repos: int,
    seed: int,
    max_size_kb: int,
    local_roots: list[Path],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    pool = _discover_local_repo_candidates(local_roots)
    if len(pool) < target_repos:
        raise RuntimeError(f"Local repo pool too small: need {target_repos}, found {len(pool)}")

    max_size_bytes = max_size_kb * 1024
    under_cap = [item for item in pool if int(item.get("source_bytes", 0)) <= max_size_bytes]
    over_cap = [item for item in pool if int(item.get("source_bytes", 0)) > max_size_bytes]
    rng.shuffle(under_cap)
    rng.shuffle(over_cap)
    over_cap = sorted(over_cap, key=lambda item: (int(item.get("source_bytes", 0)), rng.random()))

    selected = under_cap[:target_repos]
    if len(selected) < target_repos:
        selected.extend(over_cap[: target_repos - len(selected)])
    if len(selected) < target_repos:
        raise RuntimeError(f"Could not satisfy local sample target of {target_repos}; got {len(selected)}")

    return selected, {
        "mode": "local-existing",
        "seed": seed,
        "max_size_kb": max_size_kb,
        "roots": [str(root) for root in local_roots],
        "candidate_count": len(pool),
        "under_cap_count": len(under_cap),
        "over_cap_count": len(over_cap),
        "selected_under_cap_count": sum(1 for item in selected if int(item.get("source_bytes", 0)) <= max_size_bytes),
        "selected": [str(item.get("full_name", "")) for item in selected],
    }


def _select_candidates(
    *,
    quotas: dict[str, int],
    seed: int,
    max_size_kb: int,
    per_page: int,
    sort: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rng = random.Random(seed)
    selected: list[dict[str, Any]] = []
    seen_full_names: set[str] = set()
    pool_meta: dict[str, Any] = {"languages": {}}

    for language, quota in quotas.items():
        pool = _search_small_repos(
            language,
            max_size_kb=max_size_kb,
            candidate_goal=max(quota * 3, 20),
            per_page=per_page,
            sort=sort,
        )
        rng.shuffle(pool)
        picked: list[dict[str, Any]] = []
        for item in pool:
            full_name = str(item.get("full_name", ""))
            if not full_name or full_name in seen_full_names:
                continue
            picked.append(item)
            seen_full_names.add(full_name)
            if len(picked) >= quota:
                break
        if len(picked) < quota:
            raise RuntimeError(f"Could not satisfy quota for {language}: needed {quota}, got {len(picked)}")
        selected.extend(picked)
        pool_meta["languages"][language] = {
            "quota": quota,
            "candidate_count": len(pool),
            "discovery_modes": sorted({str(item.get("discovery_mode", "github-api-search")) for item in pool}),
            "selected": [str(item.get("full_name", "")) for item in picked],
        }

    rng.shuffle(selected)
    pool_meta["seed"] = seed
    pool_meta["max_size_kb"] = max_size_kb
    pool_meta["per_page"] = per_page
    pool_meta["sort"] = sort
    return selected, pool_meta


def _clone_repo(repo: dict[str, Any], destination: Path) -> Path:
    local_path = str(repo.get("local_path", "") or "")
    if local_path:
        return Path(local_path)
    full_name = str(repo["full_name"])
    local_dir = destination / full_name.replace("/", "__")
    if local_dir.exists():
        shutil.rmtree(local_dir)
    _run_git(["clone", "--depth", "1", "--quiet", str(repo["clone_url"]), str(local_dir)])
    return local_dir


def _scan_repo(repo: dict[str, Any], repo_root: Path, *, js_backend: str) -> dict[str, Any]:
    files = _iter_supported_files(repo_root)
    repo_bytes = _repo_source_bytes(repo_root)
    started = time.perf_counter()
    results = [scan_file(file_path, js_backend=js_backend) for file_path in files]
    scan_seconds = round(time.perf_counter() - started, 4)

    all_findings = [finding for result in results for finding in result.findings]
    lines_scanned = sum(result.lines_scanned for result in results)
    audit_started = time.perf_counter()
    audit_report = audit_findings(results, verbose=False)
    audit_seconds = round(time.perf_counter() - audit_started, 4)

    verdict_counts = Counter(af.verdict.name for af in audit_report.findings)
    cwe_counts = Counter(finding.cwe or "?" for finding in all_findings)
    rule_counts = Counter(finding.rule_id or "?" for finding in all_findings)
    severity_counts = Counter(finding.severity.name for finding in all_findings)
    language_counts = Counter(
        language for language in (_guess_language_from_suffix(Path(result.file_path)) for result in results) if language
    )
    cluster_stats = cluster_adjusted_stats(all_findings, lines_scanned)

    return {
        "repo": str(repo["full_name"]),
        "html_url": str(repo.get("html_url", "")),
        "api_language": str(repo.get("language", "")),
        "api_size_kb": int(repo.get("size", 0) or 0),
        "stars": int(repo.get("stargazers_count", 0) or 0),
        "default_branch": str(repo.get("default_branch", "")),
        "source_bytes": repo_bytes,
        "source_kb": round(repo_bytes / 1024.0, 2),
        "files_scanned": len(files),
        "lines_scanned": lines_scanned,
        "scan_seconds": scan_seconds,
        "audit_seconds": audit_seconds,
        "total_seconds": round(scan_seconds + audit_seconds, 4),
        "findings_count": len(all_findings),
        "clustered_findings_count": int(cluster_stats["clustered_count"]),
        "cluster_reduction_pct": float(cluster_stats["reduction_pct"]),
        "raw_noise_quotient": float(cluster_stats["raw_noise_quotient"]),
        "cluster_adjusted_noise_quotient": float(cluster_stats["cluster_adjusted_noise_quotient"]),
        "findings_per_file": round(len(all_findings) / len(files), 4) if files else 0.0,
        "verdicts": _counter_dict(verdict_counts),
        "cwes": _counter_dict(cwe_counts),
        "rule_ids": _counter_dict(rule_counts),
        "severities": _counter_dict(severity_counts),
        "file_languages": _counter_dict(language_counts),
        "top_files": [str(path.relative_to(repo_root)).replace("\\", "/") for path in files[:10]],
    }


def run_live_random_repo_sample(
    *,
    target_repos: int = 50,
    seed: int = 20260526,
    max_size_kb: int = 2048,
    per_page: int = 100,
    sort: str = "updated",
    cache_dir: str | Path | None = None,
    js_backend: str = "auto",
    keep_repos: bool = False,
    local_roots: list[str | Path] | None = None,
) -> dict[str, Any]:
    quotas = dict(DEFAULT_LANGUAGE_QUOTAS)
    normalized_local_roots = [Path(root).resolve() for root in (local_roots or [])]
    if normalized_local_roots:
        candidate_repos, selection_meta = _select_local_candidates(
            target_repos=target_repos,
            seed=seed,
            max_size_kb=max_size_kb,
            local_roots=normalized_local_roots,
        )
    else:
        if sum(quotas.values()) != target_repos:
            raise ValueError(
                f"target_repos={target_repos} does not match built-in balanced quota total {sum(quotas.values())}"
            )
        candidate_repos, selection_meta = _select_candidates(
            quotas=quotas,
            seed=seed,
            max_size_kb=max_size_kb,
            per_page=per_page,
            sort=sort,
        )

    root_dir = Path(cache_dir).resolve() if cache_dir is not None else (Path(tempfile.gettempdir()) / "ansede-live-random-repos")
    root_dir.mkdir(parents=True, exist_ok=True)

    repo_reports: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    language_repo_counts: Counter[str] = Counter()
    started = time.perf_counter()

    for repo in candidate_repos:
        repo_name = str(repo.get("full_name", ""))
        intended_language = str(repo.get("dominant_language", "") or "")
        if not intended_language and selection_meta.get("mode") != "local-existing":
            intended_language = next(
                (language for language, names in ((lang, selection_meta["languages"][lang]["selected"]) for lang in quotas) if repo_name in names),
                "",
            )
        try:
            local_dir = _clone_repo(repo, root_dir)
            report = _scan_repo(repo, local_dir, js_backend=js_backend)
            report["sample_language"] = intended_language or str(report.get("api_language", "") or "unknown").lower()
            repo_reports.append(report)
            language_repo_counts[report["sample_language"]] += 1
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            UnicodeError,
            ValueError,
            subprocess.CalledProcessError,
            urllib.error.URLError,
            urllib.error.HTTPError,
        ) as exc:
            _log.warning("Skipping repo %s after benchmark error: %s", repo_name, exc)
            failures.append({"repo": repo_name, "error": str(exc)})
        finally:
            if not keep_repos and not repo.get("local_path"):
                local_path = root_dir / repo_name.replace("/", "__")
                if local_path.exists():
                    shutil.rmtree(local_path, ignore_errors=True)

    elapsed = round(time.perf_counter() - started, 4)

    total_files = sum(int(repo["files_scanned"]) for repo in repo_reports)
    total_lines = sum(int(repo["lines_scanned"]) for repo in repo_reports)
    total_findings = sum(int(repo["findings_count"]) for repo in repo_reports)
    total_clustered = sum(int(repo["clustered_findings_count"]) for repo in repo_reports)
    total_source_bytes = sum(int(repo["source_bytes"]) for repo in repo_reports)
    total_scan_seconds = round(sum(float(repo["scan_seconds"]) for repo in repo_reports), 4)
    total_audit_seconds = round(sum(float(repo["audit_seconds"]) for repo in repo_reports), 4)

    repo_times = [float(repo["total_seconds"]) for repo in repo_reports]
    repo_scan_times = [float(repo["scan_seconds"]) for repo in repo_reports]
    source_kb_values = [float(repo["source_kb"]) for repo in repo_reports]

    verdicts = Counter()
    cwes = Counter()
    severities = Counter()
    rules = Counter()
    api_languages = Counter()
    file_languages = Counter()
    repos_with_findings = 0
    repos_with_tp = 0
    repos_with_review = 0

    for repo in repo_reports:
        if int(repo["findings_count"]):
            repos_with_findings += 1
        if int(repo["verdicts"].get("TP", 0)):
            repos_with_tp += 1
        if int(repo["verdicts"].get("NEEDS_REVIEW", 0)):
            repos_with_review += 1
        verdicts.update(repo["verdicts"])
        cwes.update(repo["cwes"])
        severities.update(repo["severities"])
        rules.update(repo["rule_ids"])
        api_languages.update([str(repo.get("api_language", "") or "unknown")])
        file_languages.update(repo["file_languages"])

    summary = {
        "repos_requested": target_repos,
        "repos_scanned": len(repo_reports),
        "repos_failed": len(failures),
        "files_scanned": total_files,
        "lines_scanned": total_lines,
        "source_megabytes": round(total_source_bytes / (1024.0 * 1024.0), 4),
        "total_findings": total_findings,
        "total_clustered_findings": total_clustered,
        "repos_with_findings": repos_with_findings,
        "repos_with_findings_pct": round((repos_with_findings / len(repo_reports) * 100.0), 2) if repo_reports else 0.0,
        "repos_with_tp": repos_with_tp,
        "repos_with_tp_pct": round((repos_with_tp / len(repo_reports) * 100.0), 2) if repo_reports else 0.0,
        "repos_with_needs_review": repos_with_review,
        "repos_with_needs_review_pct": round((repos_with_review / len(repo_reports) * 100.0), 2) if repo_reports else 0.0,
        "raw_noise_quotient": noise_quotient(total_findings, total_lines),
        "cluster_adjusted_noise_quotient": noise_quotient(total_clustered, total_lines),
        "cluster_reduction_pct": round(((total_findings - total_clustered) / total_findings * 100.0), 2) if total_findings else 0.0,
        "wall_clock_seconds": elapsed,
        "pure_scan_seconds": total_scan_seconds,
        "pure_audit_seconds": total_audit_seconds,
        "repos_per_minute": round((len(repo_reports) / elapsed) * 60.0, 4) if elapsed else 0.0,
        "files_per_second": round(total_files / elapsed, 4) if elapsed else 0.0,
        "kloc_per_second": round((total_lines / 1000.0) / elapsed, 4) if elapsed else 0.0,
        "median_repo_seconds": _median(repo_times),
        "mean_repo_seconds": _mean(repo_times),
        "median_scan_seconds": _median(repo_scan_times),
        "mean_scan_seconds": _mean(repo_scan_times),
        "median_source_kb": _median(source_kb_values),
        "mean_source_kb": _mean(source_kb_values),
    }

    per_language: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "repos": 0,
        "files_scanned": 0,
        "lines_scanned": 0,
        "findings": 0,
        "clustered_findings": 0,
        "scan_seconds": 0.0,
        "audit_seconds": 0.0,
        "tps": 0,
        "needs_review": 0,
    })

    for repo in repo_reports:
        bucket = per_language[str(repo["sample_language"])]
        bucket["repos"] += 1
        bucket["files_scanned"] += int(repo["files_scanned"])
        bucket["lines_scanned"] += int(repo["lines_scanned"])
        bucket["findings"] += int(repo["findings_count"])
        bucket["clustered_findings"] += int(repo["clustered_findings_count"])
        bucket["scan_seconds"] += float(repo["scan_seconds"])
        bucket["audit_seconds"] += float(repo["audit_seconds"])
        bucket["tps"] += int(repo["verdicts"].get("TP", 0))
        bucket["needs_review"] += int(repo["verdicts"].get("NEEDS_REVIEW", 0))

    per_language_summary = {
        language: {
            **values,
            "scan_seconds": round(values["scan_seconds"], 4),
            "audit_seconds": round(values["audit_seconds"], 4),
            "raw_noise_quotient": noise_quotient(values["findings"], values["lines_scanned"]),
            "cluster_adjusted_noise_quotient": noise_quotient(values["clustered_findings"], values["lines_scanned"]),
        }
        for language, values in sorted(per_language.items())
    }

    report = {
        "kind": "ansede-live-random-small-repo-sample",
        "version": 1,
        "generated_at_epoch": int(time.time()),
        "sample_method": {
            "description": (
                "Random sample over real repositories with a fixed seed. "
                "When `local_roots` are provided, selection prefers already-cloned repos at or under the requested size cap and backfills with the next-smallest repos as needed. "
                "Otherwise, selection uses GitHub public search candidates."
            ),
            "selection": selection_meta,
            "quotas": (quotas if not normalized_local_roots else None),
            "truth_note": (
                "Precision/recall are not exact on this unlabeled corpus. This report provides exact live operational metrics and exact auto-audit distributions only."
            ),
        },
        "summary": summary,
        "by_verdict": _counter_dict(verdicts),
        "by_cwe": _counter_dict(cwes),
        "by_severity": _counter_dict(severities),
        "by_rule_id": _counter_dict(rules),
        "api_languages": _counter_dict(api_languages),
        "file_languages": _counter_dict(file_languages),
        "per_language": per_language_summary,
        "top_repos_by_findings": sorted(
            (
                {
                    "repo": repo["repo"],
                    "sample_language": repo["sample_language"],
                    "findings": repo["findings_count"],
                    "clustered_findings": repo["clustered_findings_count"],
                    "lines_scanned": repo["lines_scanned"],
                    "scan_seconds": repo["scan_seconds"],
                }
                for repo in repo_reports
            ),
            key=lambda item: (-int(item["findings"]), item["repo"]),
        )[:15],
        "slowest_repos": sorted(
            (
                {
                    "repo": repo["repo"],
                    "sample_language": repo["sample_language"],
                    "total_seconds": repo["total_seconds"],
                    "files_scanned": repo["files_scanned"],
                    "lines_scanned": repo["lines_scanned"],
                }
                for repo in repo_reports
            ),
            key=lambda item: (-float(item["total_seconds"]), item["repo"]),
        )[:15],
        "repos": repo_reports,
        "failures": failures,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a live random benchmark over 50 small public GitHub repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.live_random_repo_sample --output tmp/live_random_50.json
              python -m benchmarks.live_random_repo_sample --seed 20260526 --keep-repos
            """
        ),
    )
    parser.add_argument("--target-repos", type=int, default=50, help="Total repos to scan (must match built-in balanced quota total)")
    parser.add_argument("--seed", type=int, default=20260526, help="Random seed for repo selection")
    parser.add_argument("--max-size-kb", type=int, default=2048, help="Maximum GitHub-reported repository size in KB")
    parser.add_argument("--per-page", type=int, default=100, help="Candidate pool size per language from GitHub Search")
    parser.add_argument("--sort", choices=["updated", "stars"], default="updated", help="GitHub Search sort key")
    parser.add_argument("--cache-dir", type=Path, default=Path("tmp/live-random-repos"), help="Directory used for shallow clone checkouts")
    parser.add_argument("--js-backend", choices=["auto", "classic", "structural", "pratt"], default="auto", help="JavaScript backend to use while scanning")
    parser.add_argument("--keep-repos", action="store_true", help="Keep shallow clone checkouts after the run")
    parser.add_argument("--local-root", action="append", default=[], help="Existing local repo root to sample from instead of GitHub discovery (can be repeated)")
    parser.add_argument("--output", type=Path, default=None, help="Optional JSON report output path")
    args = parser.parse_args()

    report = run_live_random_repo_sample(
        target_repos=args.target_repos,
        seed=args.seed,
        max_size_kb=args.max_size_kb,
        per_page=args.per_page,
        sort=args.sort,
        cache_dir=args.cache_dir,
        js_backend=args.js_backend,
        keep_repos=args.keep_repos,
        local_roots=args.local_root,
    )

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
