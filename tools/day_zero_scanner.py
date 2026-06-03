#!/usr/bin/env python3
"""Scan popular GitHub repos for potential zero-day vulnerabilities.

This runner supports two useful campaign modes:

* ``deep`` — full-repo scanning for slower, exhaustive sweeps.
* ``hotspot`` — sparse, budgeted triage of the most security-relevant files.

The old implementation scanned each repository serially, only persisted results at
the very end, and used a hard 300s whole-repo timeout. That made long campaigns
fragile and hard to learn from. This version is intentionally more operational:

* per-repo progress is persisted after every completed target
* manifest metadata is updated incrementally without falsely marking timeouts as done
* hotspot mode uses sparse clone + path scoring so large public repos can be triaged quickly
* ansede CLI is invoked with file-level parallelism enabled
* partial/final JSON and SARIF artifacts are always written to disk

Usage examples:

    python tools/day_zero_scanner.py --batch 20
    python tools/day_zero_scanner.py --batch 100 --mode hotspot --repo-workers 6 --workers 4
    python tools/day_zero_scanner.py --batch 20 --mode deep --scan-timeout 900

Follows responsible disclosure practices:
  - findings are logged locally only
  - no automated filing of issues
  - each run stores enough metadata to reproduce or retry the campaign later
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
CAMPAIGN_FILE = REPO_ROOT / "benchmarks" / "campaign_targets_top100.json"
OUTPUT_DIR = REPO_ROOT / "tmp" / "scans"

SUPPORTED_EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".rb": "ruby",
    ".rake": "ruby",
    ".php": "php",
    ".phtml": "php",
}

HOTSPOT_KEYWORDS = {
    "auth": 30,
    "login": 28,
    "session": 26,
    "token": 26,
    "jwt": 26,
    "oauth": 26,
    "permission": 24,
    "admin": 24,
    "user": 14,
    "account": 16,
    "api": 20,
    "route": 22,
    "router": 22,
    "controller": 22,
    "handler": 20,
    "middleware": 20,
    "guard": 20,
    "policy": 18,
    "graphql": 18,
    "webhook": 20,
    "payment": 20,
    "billing": 20,
    "checkout": 18,
    "upload": 18,
    "download": 18,
    "file": 14,
    "path": 14,
    "template": 16,
    "render": 16,
    "view": 16,
    "query": 12,
    "sql": 16,
    "db": 12,
    "secret": 24,
    "crypto": 20,
    "launch": 18,
    "server": 14,
    "app": 10,
    "config": 8,
    "cli": 8,
}

TEST_LIKE_PARTS = {
    "test",
    "tests",
    "spec",
    "specs",
    "fixture",
    "fixtures",
    "example",
    "examples",
    "demo",
    "docs",
    "benchmark",
    "benchmarks",
    "vendor",
    "dist",
    "build",
    "coverage",
}

EXTENSION_BONUS = {
    ".py": 8,
    ".js": 8,
    ".ts": 8,
    ".tsx": 7,
    ".go": 6,
    ".java": 6,
    ".cs": 6,
    ".rb": 6,
    ".php": 6,
}

HIGH_SIGNAL_CWE_WEIGHTS = {
    "CWE-287": 30,
    "CWE-306": 30,
    "CWE-862": 28,
    "CWE-22": 24,
    "CWE-94": 24,
    "CWE-78": 24,
    "CWE-89": 24,
    "CWE-918": 22,
    "CWE-434": 20,
    "CWE-611": 18,
    "CWE-643": 18,
    "CWE-352": 12,
    "CWE-200": 10,
}

NOISY_CWE_PENALTIES = {
    "CWE-117": 18,
}

TITLE_SIGNAL_WEIGHTS = {
    "missing auth": 16,
    "authentication": 14,
    "admin": 10,
    "route": 8,
    "path traversal": 12,
    "file upload": 10,
    "upload": 6,
    "token": 6,
    "oauth": 6,
    "secret": 8,
    "csrf": 4,
}

VERIFICATION_CONTEXT_FILES = {
    "__init__.py",
    "index.js",
    "index.ts",
    "index.tsx",
    "routes.py",
    "router.py",
    "router.ts",
    "routes.ts",
    "models.py",
    "schemas.py",
    "serializers.py",
    "auth.py",
    "auths.py",
    "config.py",
    "settings.py",
}

VERIFICATION_ADJACENCY_KEYWORDS = {
    "auth": 28,
    "login": 24,
    "session": 22,
    "token": 22,
    "oauth": 22,
    "permission": 20,
    "admin": 18,
    "route": 24,
    "router": 24,
    "controller": 20,
    "handler": 18,
    "middleware": 18,
    "guard": 18,
    "policy": 16,
    "config": 24,
    "setting": 22,
    "model": 20,
    "schema": 18,
    "serializer": 18,
    "user": 12,
    "account": 12,
}


@dataclass(frozen=True)
class CampaignSettings:
    mode: str
    workers: int
    repo_workers: int
    scan_timeout: int
    clone_timeout: int
    timeout_per_file: int
    max_hotspot_files: int
    include_tests: bool
    js_backend: str
    campaign_budget_seconds: int | None
    verify_top_repos: int
    verify_min_signal_score: int
    verify_scan_timeout: int


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _coerce_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _load_campaign_data() -> dict[str, Any]:
    if not CAMPAIGN_FILE.is_file():
        print(f"ERROR: campaign file not found at {CAMPAIGN_FILE}")
        sys.exit(1)
    return json.loads(CAMPAIGN_FILE.read_text(encoding="utf-8"))


def _select_targets(campaign_data: dict[str, Any], batch_size: int) -> list[dict[str, Any]]:
    entries = campaign_data.get("entries", [])
    queued = [
        entry
        for entry in entries
        if entry.get("status") == "queued" and entry.get("priority") == "high"
    ]
    return queued[:batch_size]


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _safe_text(value: object, *, limit: int = 400) -> str:
    return str(value).replace("\r", " ").replace("\n", " ")[:limit]


def _emit_status(value: object) -> None:
    print(_safe_text(value))


def _remaining_budget_seconds(deadline: float | None) -> int | None:
    if deadline is None:
        return None
    return max(0, int(deadline - time.perf_counter()))


def _timeout_with_budget(requested: int, deadline: float | None, *, minimum: int = 1) -> int:
    if deadline is None:
        return requested
    remaining = _remaining_budget_seconds(deadline)
    if remaining is None or remaining <= 0:
        return 0
    return max(minimum, min(requested, remaining))


def _is_budget_error(error: str | None) -> bool:
    return bool(error and error.startswith("campaign budget exhausted"))


def _run_command(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _clone_attempts(repo_url: str, dest: Path, mode: str) -> list[tuple[str, list[str]]]:
    attempts: list[tuple[str, list[str]]] = []
    if mode == "hotspot":
        attempts.append((
            "sparse",
            ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", repo_url, str(dest)],
        ))
    attempts.append(("full", ["git", "clone", "--depth", "1", repo_url, str(dest)]))
    return attempts


def _checkout_ref(repo_path: Path, ref: str, clone_timeout: int, deadline: float | None = None) -> str | None:
    try:
        fetch_timeout = _timeout_with_budget(max(30, clone_timeout // 2), deadline)
        if fetch_timeout <= 0:
            return "campaign budget exhausted before git fetch"
        fetch_proc = _run_command(
            ["git", "-C", str(repo_path), "fetch", "--depth", "1", "origin", ref],
            timeout=fetch_timeout,
        )
        if fetch_proc.returncode != 0:
            err = (fetch_proc.stderr or fetch_proc.stdout or "").strip()
            return err[:400] or "git fetch failed"
        checkout_timeout = _timeout_with_budget(max(20, clone_timeout // 3), deadline)
        if checkout_timeout <= 0:
            return "campaign budget exhausted before git checkout"
        checkout_proc = _run_command(
            ["git", "-C", str(repo_path), "checkout", ref],
            timeout=checkout_timeout,
        )
        if checkout_proc.returncode != 0:
            err = (checkout_proc.stderr or checkout_proc.stdout or "").strip()
            return err[:400] or "git checkout failed"
        return None
    except (subprocess.TimeoutExpired, OSError) as exc:
        return str(exc)


def _clone_repo(
    entry: dict[str, Any],
    clone_dir: Path,
    settings: CampaignSettings,
    deadline: float | None = None,
) -> tuple[Path | None, str, str | None]:
    """Clone a single repo and return (path, strategy, error)."""
    repo_url = entry.get("url") or entry.get("repo", "")
    ref = entry.get("ref") or "HEAD"
    repo_name = repo_url.rstrip("/").split("/")[-1]
    dest = clone_dir / f"{entry['id']}_{repo_name}"
    if dest.is_dir():
        return dest, "existing", None

    last_error: str | None = None
    chosen_strategy = "full"
    for strategy, cmd in _clone_attempts(repo_url, dest, settings.mode):
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        try:
            clone_timeout = _timeout_with_budget(settings.clone_timeout, deadline)
            if clone_timeout <= 0:
                return None, chosen_strategy, "campaign budget exhausted before clone"
            proc = _run_command(cmd, timeout=clone_timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            last_error = str(exc)
            continue
        if proc.returncode == 0:
            chosen_strategy = strategy
            break
        stderr = (proc.stderr or proc.stdout or "").strip()
        last_error = stderr[:400] or f"git clone failed with exit {proc.returncode}"
    else:
        return None, chosen_strategy, last_error

    if ref and ref not in {"HEAD", "<pin_sha>"}:
        checkout_error = _checkout_ref(dest, ref, settings.clone_timeout, deadline)
        if checkout_error:
            return None, chosen_strategy, checkout_error

    return dest, chosen_strategy, None


def _git_tracked_files(repo_path: Path) -> list[str]:
    try:
        proc = _run_command(
            ["git", "-C", str(repo_path), "ls-tree", "-r", "--name-only", "HEAD"],
            timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        proc = None

    if proc is not None and proc.returncode == 0 and proc.stdout.strip():
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]

    paths: list[str] = []
    for file_path in repo_path.rglob("*"):
        if file_path.is_file():
            paths.append(file_path.relative_to(repo_path).as_posix())
    return paths


def _is_supported_source(rel_path: str) -> bool:
    return Path(rel_path).suffix.lower() in SUPPORTED_EXTENSION_TO_LANGUAGE


def _supported_source_files(repo_path: Path) -> list[str]:
    return [path for path in _git_tracked_files(repo_path) if _is_supported_source(path)]


def _path_is_test_like(rel_path: str) -> bool:
    lower = rel_path.lower().replace("\\", "/")
    parts = [part for part in lower.split("/") if part]
    stem = Path(lower).stem
    return (
        any(part in TEST_LIKE_PARTS for part in parts)
        or stem.startswith("test_")
        or stem.endswith("_test")
        or lower.endswith(".spec.js")
        or lower.endswith(".spec.ts")
        or lower.endswith(".test.js")
        or lower.endswith(".test.ts")
    )


def _score_hotspot_path(rel_path: str) -> int:
    lower = rel_path.lower().replace("\\", "/")
    score = 0
    for keyword, weight in HOTSPOT_KEYWORDS.items():
        if keyword in lower:
            score += weight

    suffix = Path(lower).suffix.lower()
    score += EXTENSION_BONUS.get(suffix, 0)

    if _path_is_test_like(lower):
        score -= 35
    if lower.count("/") <= 2:
        score += 4
    if lower.endswith(("app.py", "server.py", "server.js", "main.py", "main.ts", "routes.py", "routes.ts")):
        score += 12
    return score


def _select_hotspot_paths(
    source_paths: list[str],
    *,
    max_files: int,
    include_tests: bool,
) -> list[str]:
    non_test = [path for path in source_paths if include_tests or not _path_is_test_like(path)]
    candidate_pool = non_test if non_test else source_paths
    ranked = sorted(
        candidate_pool,
        key=lambda rel: (-_score_hotspot_path(rel), len(rel), rel),
    )

    selected: list[str] = []
    seen: set[str] = set()
    for rel_path in ranked:
        if rel_path in seen:
            continue
        selected.append(rel_path)
        seen.add(rel_path)
        if len(selected) >= max_files:
            return selected

    if len(selected) < max_files:
        fallback_ranked = sorted(source_paths, key=lambda rel: (-_score_hotspot_path(rel), len(rel), rel))
        for rel_path in fallback_ranked:
            if rel_path in seen:
                continue
            selected.append(rel_path)
            seen.add(rel_path)
            if len(selected) >= max_files:
                break
    return selected


def _materialize_hotspot_paths(
    repo_path: Path,
    selected_paths: list[str],
    deadline: float | None = None,
) -> tuple[bool, str | None]:
    if not selected_paths:
        return False, "no hotspot paths selected"
    try:
        materialize_timeout = _timeout_with_budget(60, deadline)
        if materialize_timeout <= 0:
            return False, "campaign budget exhausted before sparse materialization"
        proc = _run_command(
            ["git", "-C", str(repo_path), "sparse-checkout", "set", "--no-cone", *selected_paths],
            timeout=materialize_timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, err[:400] or "sparse-checkout failed"
    return True, None


def _detect_dominant_language(paths: Iterable[str]) -> str | None:
    counts: Counter[str] = Counter()
    for rel_path in paths:
        lang = SUPPORTED_EXTENSION_TO_LANGUAGE.get(Path(rel_path).suffix.lower())
        if lang:
            counts[lang] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def _normalize_rel_path(rel_path: str) -> str:
    return rel_path.replace("\\", "/").lstrip("./").lower()


def _match_finding_to_selected_path(file_path: str, selected_paths: Iterable[str]) -> str | None:
    normalized_file = _normalize_rel_path(file_path)
    matches = [path for path in selected_paths if normalized_file.endswith(_normalize_rel_path(path))]
    if not matches:
        return None
    return max(matches, key=len)


def _round_ratio(numerator: float, denominator: float) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _verification_context_score(rel_path: str) -> int:
    normalized = _normalize_rel_path(rel_path)
    path_obj = Path(normalized)
    basename = path_obj.name
    score = 0
    if basename in VERIFICATION_CONTEXT_FILES:
        score += 60
    for keyword, weight in VERIFICATION_ADJACENCY_KEYWORDS.items():
        if keyword in normalized:
            score += weight
    if len(path_obj.parts) <= 4:
        score += 6
    return score


def _select_verification_focus_paths(result: dict[str, Any], *, limit: int = 12) -> list[str]:
    selected_paths = [str(path) for path in result.get("selected_paths", []) if path]
    if not selected_paths:
        return []

    path_scores: Counter[str] = Counter()
    for finding in result.get("high_critical_findings", []):
        matched = _match_finding_to_selected_path(str(finding.get("file", "")), selected_paths)
        if matched:
            path_scores[matched] += _finding_priority_score(finding)

    ranked = sorted(
        selected_paths,
        key=lambda rel: (
            -(path_scores.get(rel, 0) + (_verification_context_score(rel) * 3)),
            -path_scores.get(rel, 0),
            -_verification_context_score(rel),
            -_score_hotspot_path(rel),
            len(rel),
            rel,
        ),
    )
    return ranked[: min(limit, len(ranked))]


def _add_unique_path(selected: list[str], seen: set[str], path: str, *, max_files: int) -> None:
    if path not in seen and len(selected) < max_files:
        selected.append(path)
        seen.add(path)


def _verification_siblings_for_focus(
    focus_path: str,
    files_by_dir: dict[str, list[str]],
) -> list[str]:
    parent = Path(focus_path).parent.as_posix()
    return sorted(
        files_by_dir.get(parent, []),
        key=lambda rel: (
            -_verification_context_score(rel),
            -_score_hotspot_path(rel),
            len(rel),
            rel,
        ),
    )


def _extend_with_focus_context(
    selected: list[str],
    seen: set[str],
    focus_paths: list[str],
    files_by_dir: dict[str, list[str]],
    *,
    max_files: int,
    siblings_per_focus: int,
) -> None:
    for focus_path in focus_paths:
        if len(selected) >= max_files:
            return
        sibling_count = 0
        for sibling in _verification_siblings_for_focus(focus_path, files_by_dir):
            if sibling == focus_path or sibling in seen:
                continue
            _add_unique_path(selected, seen, sibling, max_files=max_files)
            sibling_count += 1
            if sibling_count >= siblings_per_focus or len(selected) >= max_files:
                break


def _extend_with_fallback_paths(
    selected: list[str],
    seen: set[str],
    supported_files: list[str],
    *,
    max_files: int,
) -> None:
    fallback_ranked = sorted(
        supported_files,
        key=lambda rel: (-_score_hotspot_path(rel), len(rel), rel),
    )
    for rel_path in fallback_ranked:
        _add_unique_path(selected, seen, rel_path, max_files=max_files)
        if len(selected) >= max_files:
            return


def _expand_verification_paths(
    supported_files: list[str],
    focus_paths: list[str],
    *,
    max_files: int,
    siblings_per_focus: int = 3,
) -> list[str]:
    if not supported_files:
        return []

    normalized_supported = {_normalize_rel_path(path): path for path in supported_files}
    files_by_dir: dict[str, list[str]] = {}
    for path in supported_files:
        parent = Path(path).parent.as_posix()
        files_by_dir.setdefault(parent, []).append(path)

    selected: list[str] = []
    seen: set[str] = set()

    actual_focus_paths: list[str] = []
    for focus_path in focus_paths:
        actual = normalized_supported.get(_normalize_rel_path(focus_path))
        if actual:
            actual_focus_paths.append(actual)
            _add_unique_path(selected, seen, actual, max_files=max_files)

    _extend_with_focus_context(
        selected,
        seen,
        actual_focus_paths,
        files_by_dir,
        max_files=max_files,
        siblings_per_focus=siblings_per_focus,
    )

    if len(selected) < max_files:
        _extend_with_fallback_paths(
            selected,
            seen,
            supported_files,
            max_files=max_files,
        )

    return selected


def _build_scan_command(scan_inputs: list[Path], settings: CampaignSettings) -> list[str]:
    return [
        sys.executable,
        "-m",
        "ansede_static.cli",
        *[str(path) for path in scan_inputs],
        "--format",
        "json",
        "--fail-on",
        "never",
        "--js-backend",
        settings.js_backend,
        "--parallel",
        "--workers",
        str(settings.workers),
        "--timeout-per-file",
        str(settings.timeout_per_file),
        "--exclude",
        "node_modules",
        "--exclude",
        ".venv",
        "--exclude",
        "__pycache__",
        "--exclude",
        "vendor",
        "--exclude",
        "dist",
        "--exclude",
        "build",
    ]


def _extract_findings(scan_json: dict[str, Any]) -> tuple[dict[str, int], list[dict[str, Any]]]:
    findings_by_severity: dict[str, int] = {}
    high_critical: list[dict[str, Any]] = []
    for result in scan_json.get("results", []):
        for finding in result.get("findings", []):
            severity = finding.get("severity", "info")
            findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            if severity in {"critical", "high"}:
                high_critical.append(
                    {
                        "rule_id": finding.get("rule_id"),
                        "cwe": finding.get("cwe"),
                        "severity": severity,
                        "title": finding.get("title"),
                        "file": finding.get("file", result.get("file_path", "")),
                        "line": finding.get("line"),
                        "confidence": finding.get("confidence"),
                        "analysis_kind": finding.get("analysis_kind"),
                        "confidence_label": finding.get("confidence_label"),
                    }
                )
    return findings_by_severity, high_critical


def _filter_likely_real(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    likely_real: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("confidence_label") == "structural" and _coerce_float(finding.get("confidence")) >= 0.9:
            likely_real.append(finding)
    return likely_real


def _finding_priority_score(finding: dict[str, Any]) -> int:
    severity = str(finding.get("severity", "")).lower()
    severity_weight = 60 if severity == "critical" else 36 if severity == "high" else 0
    cwe = str(finding.get("cwe") or "")
    cwe_weight = HIGH_SIGNAL_CWE_WEIGHTS.get(cwe, 0) - NOISY_CWE_PENALTIES.get(cwe, 0)
    confidence_bonus = round(_coerce_float(finding.get("confidence")) * 20)
    confidence_label = str(finding.get("confidence_label") or "").lower()
    analysis_kind = str(finding.get("analysis_kind") or "").lower()
    structural_bonus = 45 if confidence_label == "structural" else 0
    cluster_bonus = 16 if analysis_kind == "incident-cluster" else 0
    title = str(finding.get("title") or "").lower()
    title_bonus = sum(weight for keyword, weight in TITLE_SIGNAL_WEIGHTS.items() if keyword in title)
    return severity_weight + cwe_weight + confidence_bonus + structural_bonus + cluster_bonus + title_bonus


def _build_priority_candidates(findings_log: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        ({**finding, "priority_score": _finding_priority_score(finding)} for finding in findings_log),
        key=lambda finding: (
            -int(finding["priority_score"]),
            str(finding.get("repo_id", "")),
            str(finding.get("file", "")),
            int(finding.get("line") or 0),
        ),
    )
    return ranked[:limit]


def _repo_signal_summary(result: dict[str, Any]) -> dict[str, Any]:
    high_critical = list(result.get("high_critical_findings", []))
    likely_real = list(result.get("likely_real_high_critical", []))
    top_scores = sorted((_finding_priority_score(finding) for finding in high_critical), reverse=True)[:5]
    signal_score = len(likely_real) * 100 + sum(top_scores)
    return {
        "repo": result.get("repo"),
        "repo_id": result.get("repo_id"),
        "status": result.get("status"),
        "signal_score": signal_score,
        "high_critical": len(high_critical),
        "likely_real_high_critical": len(likely_real),
        "total_findings": int(result.get("total_findings", 0)),
    }


def _select_verification_candidates(
    results: list[dict[str, Any]],
    *,
    limit: int,
    min_signal_score: int,
) -> list[dict[str, Any]]:
    ranked = sorted(
        (
            summary
            for summary in (_repo_signal_summary(result) for result in results)
            if summary["status"] == "scanned"
            and summary["high_critical"] > 0
            and (
                summary["signal_score"] >= min_signal_score
                or summary["likely_real_high_critical"] > 0
            )
        ),
        key=lambda item: (
            -int(item["signal_score"]),
            -int(item["likely_real_high_critical"]),
            -int(item["high_critical"]),
            str(item.get("repo_id", "")),
        ),
    )
    return ranked[:limit]


def _verification_settings(base: CampaignSettings) -> CampaignSettings:
    return CampaignSettings(
        mode="deep",
        workers=base.workers,
        repo_workers=1,
        scan_timeout=max(30, base.verify_scan_timeout),
        clone_timeout=max(60, base.clone_timeout),
        timeout_per_file=max(10, base.timeout_per_file),
        max_hotspot_files=max(base.max_hotspot_files * 3, 72),
        include_tests=base.include_tests,
        js_backend=base.js_backend,
        campaign_budget_seconds=base.campaign_budget_seconds,
        verify_top_repos=0,
        verify_min_signal_score=base.verify_min_signal_score,
        verify_scan_timeout=base.verify_scan_timeout,
    )


def _collect_finding_log(results: list[dict[str, Any]], finding_key: str) -> list[dict[str, Any]]:
    return [
        {
            **finding,
            "repo": result.get("repo"),
            "repo_id": result.get("repo_id"),
            "pass_name": result.get("pass_name", "triage"),
        }
        for result in results
        for finding in result.get(finding_key, [])
    ]


def _build_verification_comparisons(
    triage_results: list[dict[str, Any]],
    verification_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    triage_by_repo = {str(result.get("repo_id")): result for result in triage_results}
    comparisons: list[dict[str, Any]] = []
    for verification in verification_results:
        repo_id = str(verification.get("repo_id", ""))
        triage = triage_by_repo.get(repo_id)
        if triage is None:
            continue
        comparisons.append(
            {
                "repo": verification.get("repo"),
                "repo_id": repo_id,
                "triage_signal_score": _repo_signal_summary(triage)["signal_score"],
                "verification_signal_score": _repo_signal_summary(verification)["signal_score"],
                "triage_high_critical": len(triage.get("high_critical_findings", [])),
                "verification_high_critical": len(verification.get("high_critical_findings", [])),
                "triage_likely_real_high_critical": len(triage.get("likely_real_high_critical", [])),
                "verification_likely_real_high_critical": len(verification.get("likely_real_high_critical", [])),
                "triage_selected_file_count": int(triage.get("selected_file_count", 0) or 0),
                "verification_selected_file_count": int(verification.get("selected_file_count", 0) or 0),
                "extra_verification_files": max(
                    0,
                    int(verification.get("selected_file_count", 0) or 0)
                    - int(triage.get("selected_file_count", 0) or 0),
                ),
                "retained_signal_score": min(
                    _repo_signal_summary(triage)["signal_score"],
                    _repo_signal_summary(verification)["signal_score"],
                ),
                "signal_retention_ratio": _round_ratio(
                    _repo_signal_summary(verification)["signal_score"],
                    _repo_signal_summary(triage)["signal_score"],
                ),
                "signal_retained_per_extra_file": _round_ratio(
                    min(
                        _repo_signal_summary(triage)["signal_score"],
                        _repo_signal_summary(verification)["signal_score"],
                    ),
                    max(
                        0,
                        int(verification.get("selected_file_count", 0) or 0)
                        - int(triage.get("selected_file_count", 0) or 0),
                    ),
                ),
                "verification_lift_rate": _round_ratio(
                    len(verification.get("high_critical_findings", []))
                    - len(triage.get("high_critical_findings", [])),
                    len(triage.get("high_critical_findings", [])),
                ),
                "verification_status": verification.get("status"),
            }
        )
    return sorted(
        comparisons,
        key=lambda item: (-int(item["verification_signal_score"]), str(item.get("repo_id", ""))),
    )


def _build_verification_efficiency_metrics(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    triage_files = sum(int(item.get("triage_selected_file_count", 0) or 0) for item in comparisons)
    verification_files = sum(int(item.get("verification_selected_file_count", 0) or 0) for item in comparisons)
    extra_files = sum(int(item.get("extra_verification_files", 0) or 0) for item in comparisons)
    retained_signal = sum(int(item.get("retained_signal_score", 0) or 0) for item in comparisons)
    triage_high_critical = sum(int(item.get("triage_high_critical", 0) or 0) for item in comparisons)
    verification_high_critical = sum(int(item.get("verification_high_critical", 0) or 0) for item in comparisons)
    triage_signal = sum(int(item.get("triage_signal_score", 0) or 0) for item in comparisons)
    verification_signal = sum(int(item.get("verification_signal_score", 0) or 0) for item in comparisons)
    return {
        "compared_repo_count": len(comparisons),
        "triage_files_scanned": triage_files,
        "verification_files_scanned": verification_files,
        "extra_verification_files_scanned": extra_files,
        "signal_retained_per_extra_file": _round_ratio(retained_signal, extra_files),
        "signal_retention_ratio": _round_ratio(verification_signal, triage_signal),
        "verification_lift_rate": _round_ratio(
            verification_high_critical - triage_high_critical,
            triage_high_critical,
        ),
    }


def _empty_target_result(
    repo_url: str,
    repo_id: str,
    settings: CampaignSettings,
    started: float,
    status: str,
    **extra: Any,
) -> dict[str, Any]:
    result = {
        "repo": repo_url,
        "repo_id": repo_id,
        "status": status,
        "mode": settings.mode,
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "high_critical_findings": [],
        "likely_real_high_critical": [],
    }
    result.update(extra)
    return result


def _prepare_scan_scope(
    entry: dict[str, Any],
    repo_url: str,
    repo_id: str,
    repo_path: Path,
    clone_strategy: str,
    settings: CampaignSettings,
    started: float,
    deadline: float | None,
) -> tuple[list[str], list[str], list[Path], dict[str, Any] | None]:
    supported_files = _supported_source_files(repo_path)
    if not supported_files:
        return [], [], [], _empty_target_result(
            repo_url,
            repo_id,
            settings,
            started,
            "no-supported-language",
            clone_strategy=clone_strategy,
        )

    override_paths = [str(path) for path in entry.get("_scan_paths_override", []) if path]
    if override_paths:
        selected_paths = _expand_verification_paths(
            supported_files,
            override_paths,
            max_files=max(1, settings.max_hotspot_files),
        )
        if not selected_paths:
            return supported_files, [], [], _empty_target_result(
                repo_url,
                repo_id,
                settings,
                started,
                "no-verification-focus",
                clone_strategy=clone_strategy,
                supported_file_count=len(supported_files),
            )
        if clone_strategy == "sparse":
            ok, materialize_error = _materialize_hotspot_paths(repo_path, selected_paths, deadline)
            if not ok:
                status = "campaign-budget-expired" if _is_budget_error(materialize_error) else "materialize-failed"
                return supported_files, selected_paths, [], _empty_target_result(
                    repo_url,
                    repo_id,
                    settings,
                    started,
                    status,
                    clone_strategy=clone_strategy,
                    supported_file_count=len(supported_files),
                    selected_file_count=len(selected_paths),
                    selected_paths=selected_paths,
                    error=materialize_error,
                )
        scan_inputs = [repo_path / rel_path for rel_path in selected_paths]
        return supported_files, selected_paths, scan_inputs, None

    selected_paths = supported_files
    if settings.mode == "hotspot":
        selected_paths = _select_hotspot_paths(
            supported_files,
            max_files=settings.max_hotspot_files,
            include_tests=settings.include_tests,
        )
        if not selected_paths:
            return supported_files, [], [], _empty_target_result(
                repo_url,
                repo_id,
                settings,
                started,
                "no-hotspots-selected",
                clone_strategy=clone_strategy,
                supported_file_count=len(supported_files),
            )
        if clone_strategy == "sparse":
            ok, materialize_error = _materialize_hotspot_paths(repo_path, selected_paths, deadline)
            if not ok:
                status = "campaign-budget-expired" if _is_budget_error(materialize_error) else "materialize-failed"
                return supported_files, selected_paths, [], _empty_target_result(
                    repo_url,
                    repo_id,
                    settings,
                    started,
                    status,
                    clone_strategy=clone_strategy,
                    supported_file_count=len(supported_files),
                    selected_file_count=len(selected_paths),
                    selected_paths=selected_paths,
                    error=materialize_error,
                )
        scan_inputs = [repo_path / rel_path for rel_path in selected_paths]
        return supported_files, selected_paths, scan_inputs, None

    return supported_files, selected_paths, [repo_path], None


def _scan_target(
    repo_url: str,
    repo_id: str,
    clone_strategy: str,
    settings: CampaignSettings,
    started: float,
    deadline: float | None,
    supported_files: list[str],
    selected_paths: list[str],
    scan_inputs: list[Path],
) -> dict[str, Any]:
    dominant_language = _detect_dominant_language(selected_paths if settings.mode == "hotspot" else supported_files)
    scan_timeout = _timeout_with_budget(settings.scan_timeout, deadline)
    if scan_timeout <= 0:
        return _empty_target_result(
            repo_url,
            repo_id,
            settings,
            started,
            "campaign-budget-expired",
            clone_strategy=clone_strategy,
            language=dominant_language,
            supported_file_count=len(supported_files),
            selected_file_count=len(selected_paths),
            coverage_ratio=round(len(selected_paths) / max(1, len(supported_files)), 4),
            selected_paths=selected_paths[:25],
        )

    cmd = _build_scan_command(scan_inputs, settings)
    budget_limited_scan = deadline is not None and scan_timeout < settings.scan_timeout
    try:
        proc = _run_command(cmd, cwd=REPO_ROOT, timeout=scan_timeout)
    except subprocess.TimeoutExpired:
        status = "campaign-budget-expired" if budget_limited_scan else "scan-timeout"
        return _empty_target_result(
            repo_url,
            repo_id,
            settings,
            started,
            status,
            clone_strategy=clone_strategy,
            language=dominant_language,
            supported_file_count=len(supported_files),
            selected_file_count=len(selected_paths),
            coverage_ratio=round(len(selected_paths) / max(1, len(supported_files)), 4),
            selected_paths=selected_paths[:25],
        )
    except OSError as exc:
        return _empty_target_result(
            repo_url,
            repo_id,
            settings,
            started,
            "scan-launch-failed",
            clone_strategy=clone_strategy,
            language=dominant_language,
            error=str(exc),
            supported_file_count=len(supported_files),
            selected_file_count=len(selected_paths),
        )

    elapsed = time.perf_counter() - started
    try:
        scan_json = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {
            **_empty_target_result(
                repo_url,
                repo_id,
                settings,
                started,
                "json-parse-failed",
                clone_strategy=clone_strategy,
                language=dominant_language,
                supported_file_count=len(supported_files),
                selected_file_count=len(selected_paths),
            ),
            "elapsed_seconds": round(elapsed, 1),
            "scan_exit_code": proc.returncode,
            "stdout_bytes": len(proc.stdout),
            "stderr_tail": (proc.stderr or "")[-400:],
        }

    findings_by_severity, high_critical = _extract_findings(scan_json)
    likely_real = _filter_likely_real(high_critical)
    return {
        "repo": repo_url,
        "repo_id": repo_id,
        "status": "scanned",
        "mode": settings.mode,
        "clone_strategy": clone_strategy,
        "language": dominant_language,
        "elapsed_seconds": round(elapsed, 1),
        "scan_exit_code": proc.returncode,
        "total_findings": sum(findings_by_severity.values()),
        "findings_by_severity": findings_by_severity,
        "high_critical_findings": high_critical,
        "likely_real_high_critical": likely_real,
        "supported_file_count": len(supported_files),
        "selected_file_count": len(selected_paths),
        "coverage_ratio": round(len(selected_paths) / max(1, len(supported_files)), 4),
        "selected_paths": selected_paths[:25],
    }


def _process_target(
    entry: dict[str, Any],
    clone_root: Path,
    settings: CampaignSettings,
    deadline: float | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    repo_url = entry.get("url") or entry.get("repo", "")
    repo_id = entry.get("id") or repo_url.rstrip("/").split("/")[-1]

    if deadline is not None and _remaining_budget_seconds(deadline) <= 0:
        return _empty_target_result(repo_url, repo_id, settings, started, "campaign-budget-expired")

    repo_path, clone_strategy, clone_error = _clone_repo(entry, clone_root, settings, deadline)
    if repo_path is None:
        status = "campaign-budget-expired" if _is_budget_error(clone_error) else "clone-failed"
        return _empty_target_result(
            repo_url,
            repo_id,
            settings,
            started,
            status,
            clone_strategy=clone_strategy,
            error=clone_error,
        )

    supported_files, selected_paths, scan_inputs, prep_error = _prepare_scan_scope(
        entry,
        repo_url,
        repo_id,
        repo_path,
        clone_strategy,
        settings,
        started,
        deadline,
    )
    if prep_error is not None:
        return prep_error

    return _scan_target(
        repo_url,
        repo_id,
        clone_strategy,
        settings,
        started,
        deadline,
        supported_files,
        selected_paths,
        scan_inputs,
    )


def _record_target_result(campaign_data: dict[str, Any], result: dict[str, Any]) -> None:
    repo_id = result.get("repo_id")
    if not repo_id:
        return
    pass_name = str(result.get("pass_name", "triage"))
    for entry in campaign_data.get("entries", []):
        if entry.get("id") != repo_id:
            continue
        now = _now_utc()
        if pass_name == "verification":
            entry["last_verification_at"] = now
            entry["last_verification_status"] = result.get("status")
            entry["last_verification_elapsed_seconds"] = result.get("elapsed_seconds")
            entry["last_verification_mode"] = result.get("mode")
            entry["last_verification_total_findings"] = result.get("total_findings", 0)
            entry["last_verification_likely_real_high_critical"] = len(result.get("likely_real_high_critical", []))
        else:
            entry["last_attempted_at"] = now
            entry["last_campaign_status"] = result.get("status")
            entry["last_elapsed_seconds"] = result.get("elapsed_seconds")
            entry["last_mode"] = result.get("mode")
            entry["last_total_findings"] = result.get("total_findings", 0)
            entry["last_supported_file_count"] = result.get("supported_file_count", 0)
            entry["last_selected_file_count"] = result.get("selected_file_count", 0)
            entry["last_likely_real_high_critical"] = len(result.get("likely_real_high_critical", []))
            if result.get("status") == "scanned":
                entry["status"] = "scanned"
                entry["scanned_at"] = now
        break


def _build_report(
    *,
    run_id: str,
    requested_batch: int,
    targets: list[dict[str, Any]],
    settings: CampaignSettings,
    results: list[dict[str, Any]],
    unstarted_targets: list[dict[str, Any]] | None = None,
    verification_candidates: list[dict[str, Any]] | None = None,
    verification_results: list[dict[str, Any]] | None = None,
    verification_unstarted_targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    unstarted_targets = unstarted_targets or []
    verification_candidates = verification_candidates or []
    verification_results = verification_results or []
    verification_unstarted_targets = verification_unstarted_targets or []
    status_counts = Counter(str(result.get("status", "unknown")) for result in results)
    verification_status_counts = Counter(str(result.get("status", "unknown")) for result in verification_results)
    findings_log = _collect_finding_log(results, "high_critical_findings")
    likely_real_log = _collect_finding_log(results, "likely_real_high_critical")
    verification_findings_log = _collect_finding_log(verification_results, "high_critical_findings")
    verification_likely_real_log = _collect_finding_log(verification_results, "likely_real_high_critical")
    top_cwes = Counter(
        str(finding.get("cwe"))
        for finding in findings_log
        if finding.get("cwe")
    ).most_common(10)
    priority_candidates = _build_priority_candidates(findings_log)
    top_signal_cwes = Counter(
        str(finding.get("cwe"))
        for finding in priority_candidates
        if finding.get("cwe")
    ).most_common(10)
    top_repos_by_signal = sorted(
        (_repo_signal_summary(result) for result in results),
        key=lambda item: (-int(item["signal_score"]), str(item.get("repo_id", ""))),
    )[:10]
    verification_top_cwes = Counter(
        str(finding.get("cwe"))
        for finding in verification_findings_log
        if finding.get("cwe")
    ).most_common(10)
    verification_priority_candidates = _build_priority_candidates(verification_findings_log)
    verification_top_repos_by_signal = sorted(
        (_repo_signal_summary(result) for result in verification_results),
        key=lambda item: (-int(item["signal_score"]), str(item.get("repo_id", ""))),
    )[:10]
    verification_comparisons = _build_verification_comparisons(results, verification_results)
    return {
        "timestamp": _now_utc(),
        "run_id": run_id,
        "requested_batch": requested_batch,
        "target_count": len(targets),
        "mode": settings.mode,
        "workers": settings.workers,
        "repo_workers": settings.repo_workers,
        "scan_timeout": settings.scan_timeout,
        "timeout_per_file": settings.timeout_per_file,
        "max_hotspot_files": settings.max_hotspot_files,
        "campaign_budget_seconds": settings.campaign_budget_seconds,
        "results": results,
        "unstarted_targets": [
            {"repo": target.get("url") or target.get("repo", ""), "repo_id": target.get("id")}
            for target in unstarted_targets
        ],
        "verification_candidates": verification_candidates,
        "verification_results": verification_results,
        "verification_unstarted_targets": [
            {"repo": target.get("url") or target.get("repo", ""), "repo_id": target.get("id")}
            for target in verification_unstarted_targets
        ],
        "high_critical_log": findings_log,
        "likely_real_log": likely_real_log,
        "verification_high_critical_log": verification_findings_log,
        "verification_likely_real_log": verification_likely_real_log,
        "summary": {
            "completed_targets": len(results),
            "attempted_targets": len(results),
            "unstarted_target_count": len(unstarted_targets),
            "budget_exhausted": bool(settings.campaign_budget_seconds and unstarted_targets),
            "status_counts": dict(status_counts),
            "total_findings": sum(int(result.get("total_findings", 0)) for result in results),
            "total_high_critical": len(findings_log),
            "total_likely_real_high_critical": len(likely_real_log),
            "top_cwes": [{"cwe": cwe, "count": count} for cwe, count in top_cwes],
            "top_signal_cwes": [{"cwe": cwe, "count": count} for cwe, count in top_signal_cwes],
            "top_repos_by_signal": top_repos_by_signal,
            "priority_candidates": priority_candidates,
            "verification_candidate_count": len(verification_candidates),
            "verification_attempted_targets": len(verification_results),
            "verification_unstarted_target_count": len(verification_unstarted_targets),
            "verification_status_counts": dict(verification_status_counts),
            "verification_total_high_critical": len(verification_findings_log),
            "verification_total_likely_real_high_critical": len(verification_likely_real_log),
            "verification_top_cwes": [
                {"cwe": cwe, "count": count} for cwe, count in verification_top_cwes
            ],
            "verification_top_repos_by_signal": verification_top_repos_by_signal,
            "verification_priority_candidates": verification_priority_candidates,
            "verification_comparisons": verification_comparisons,
            "verification_efficiency": _build_verification_efficiency_metrics(verification_comparisons),
        },
    }


def _persist_report(output_dir: Path, report: dict[str, Any], *, final: bool) -> tuple[Path, Path | None]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = report["run_id"]
    json_name = f"zd_scan_{run_id}.json" if final else f"zd_scan_{run_id}.partial.json"
    report_path = output_dir / json_name
    _write_json(report_path, report)
    latest_name = "zd_scan_latest.json" if final else "zd_scan_latest.partial.json"
    _write_json(output_dir / latest_name, report)

    sarif_path: Path | None = None
    findings = report.get("verification_high_critical_log") or report.get("high_critical_log", [])
    if final and findings:
        sarif_path = output_dir / f"zd_scan_{run_id}.sarif"
        _write_sarif(findings, sarif_path)
    return report_path, sarif_path


def _write_sarif(findings: list[dict[str, Any]], path: Path) -> None:
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ansede-static",
                    "version": "2.3.0-dev",
                    "informationUri": "https://pypi.org/project/ansede-static/",
                }
            },
            "results": [
                {
                    "ruleId": finding.get("rule_id", "unknown"),
                    "level": "error" if finding.get("severity") == "critical" else "warning",
                    "message": {"text": finding.get("title", "")},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.get("file", "unknown"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": finding.get("line", 1)},
                        }
                    }],
                    "properties": {
                        "cwe": finding.get("cwe"),
                        "confidence": finding.get("confidence"),
                        "confidenceLabel": finding.get("confidence_label"),
                        "analysisKind": finding.get("analysis_kind"),
                        "repo": finding.get("repo"),
                        "repoId": finding.get("repo_id"),
                    },
                }
                for finding in findings
            ],
        }],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _print_result_line(index: int, total: int, result: dict[str, Any], *, pass_name: str = "triage") -> None:
    repo_id = result.get("repo_id", "repo")
    status = result.get("status", "unknown")
    elapsed = result.get("elapsed_seconds", 0)
    selected = result.get("selected_file_count")
    supported = result.get("supported_file_count")
    high_crit = len(result.get("high_critical_findings", []))
    likely_real = len(result.get("likely_real_high_critical", []))
    coverage = result.get("coverage_ratio")
    coverage_str = ""
    if selected is not None and supported:
        coverage_str = f", scope={selected}/{supported}"
        if coverage is not None:
            coverage_str += f" ({coverage:.1%})"
    _emit_status(
        f"[{pass_name} {index}/{total}] {repo_id} -> {status} in {elapsed}s"
        f"{coverage_str}, high/crit={high_crit}, likely-real={likely_real}"
    )


def _build_settings(args: argparse.Namespace) -> CampaignSettings:
    cpu_count = os.cpu_count() or 4
    workers = args.workers or min(4, cpu_count)
    if args.repo_workers is not None:
        repo_workers = args.repo_workers
    elif args.mode == "hotspot":
        repo_workers = max(2, min(6, cpu_count // 2 or 2))
    else:
        repo_workers = 1

    if args.scan_timeout is not None:
        scan_timeout = args.scan_timeout
    elif args.mode == "hotspot":
        scan_timeout = 90
    else:
        scan_timeout = 900

    clone_timeout = args.clone_timeout or (90 if args.mode == "hotspot" else 180)
    timeout_per_file = args.timeout_per_file or (15 if args.mode == "hotspot" else 30)
    max_hotspot_files = args.max_hotspot_files or 24
    verify_top_repos = args.verify_top_repos if args.verify_top_repos is not None else (1 if args.mode == "hotspot" else 0)
    verify_scan_timeout = args.verify_scan_timeout or max(120, scan_timeout)
    return CampaignSettings(
        mode=args.mode,
        workers=max(1, workers),
        repo_workers=max(1, repo_workers),
        scan_timeout=max(30, scan_timeout),
        clone_timeout=max(30, clone_timeout),
        timeout_per_file=max(5, timeout_per_file),
        max_hotspot_files=max(1, max_hotspot_files),
        include_tests=bool(args.include_tests),
        js_backend=args.js_backend,
        campaign_budget_seconds=max(1, args.campaign_budget_seconds) if args.campaign_budget_seconds else None,
        verify_top_repos=max(0, verify_top_repos),
        verify_min_signal_score=max(0, args.verify_min_signal_score),
        verify_scan_timeout=max(30, verify_scan_timeout),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Zero-day scanner for popular GitHub repos")
    parser.add_argument("--batch", type=int, default=5, help="Number of repos to scan (default: 5)")
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR, help="Output directory")
    parser.add_argument("--mode", choices=["hotspot", "deep"], default="hotspot", help="Campaign mode: hotspot triage (default) or deep full-repo scan")
    parser.add_argument("--workers", type=int, default=None, help="CLI file-analysis worker count (defaults to 4 or CPU-aware fallback)")
    parser.add_argument("--repo-workers", type=int, default=None, help="Number of repositories to process concurrently")
    parser.add_argument("--scan-timeout", type=int, default=None, help="Whole-repo scan timeout in seconds")
    parser.add_argument("--clone-timeout", type=int, default=None, help="Clone timeout in seconds")
    parser.add_argument("--timeout-per-file", type=int, default=None, help="ansede per-file timeout in seconds")
    parser.add_argument("--max-hotspot-files", type=int, default=None, help="Maximum files to scan per repo in hotspot mode")
    parser.add_argument("--campaign-budget-seconds", type=int, default=None, help="Total wall-clock campaign budget; stop scheduling new repos when exhausted")
    parser.add_argument("--verify-top-repos", type=int, default=None, help="Deep-verify the strongest hotspot repos (default: 1 in hotspot mode, 0 in deep mode)")
    parser.add_argument("--verify-min-signal-score", type=int, default=100, help="Minimum triage signal score required for deep verification")
    parser.add_argument("--verify-scan-timeout", type=int, default=None, help="Whole-repo timeout for deep verification pass")
    parser.add_argument("--include-tests", action="store_true", help="Allow tests/examples into hotspot selection when relevant")
    parser.add_argument("--js-backend", choices=["auto", "classic", "structural"], default="classic", help="JS backend to use while scanning")
    parser.add_argument("--json", action="store_true", help="Print the final report JSON to stdout")
    return parser


def _submit_ready_targets(
    executor: ThreadPoolExecutor,
    future_to_entry: dict[Any, dict[str, Any]],
    targets: list[dict[str, Any]],
    next_target_index: int,
    clone_root: Path,
    settings: CampaignSettings,
    deadline: float | None,
) -> int:
    while len(future_to_entry) < settings.repo_workers and next_target_index < len(targets):
        if deadline is not None and _remaining_budget_seconds(deadline) <= 0:
            break
        entry = targets[next_target_index]
        next_target_index += 1
        future = executor.submit(_process_target, entry, clone_root, settings, deadline)
        future_to_entry[future] = entry
    return next_target_index


def _run_pass(
    campaign_data: dict[str, Any],
    targets: list[dict[str, Any]],
    settings: CampaignSettings,
    *,
    output_dir: Path,
    pass_name: str,
    build_partial_report: Callable[[list[dict[str, Any]], list[dict[str, Any]]], dict[str, Any]],
    clone_root: Path,
    deadline: float | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=settings.repo_workers) as executor:
        future_to_entry: dict[Any, dict[str, Any]] = {}
        next_target_index = _submit_ready_targets(
            executor,
            future_to_entry,
            targets,
            0,
            clone_root,
            settings,
            deadline,
        )
        completed = 0
        while future_to_entry:
            future = next(as_completed(list(future_to_entry)))
            completed += 1
            entry = future_to_entry.pop(future)
            try:
                result = future.result()
            except (subprocess.SubprocessError, OSError, RuntimeError, ValueError) as exc:
                repo_id = entry.get("id") or "repo"
                result = _empty_target_result(
                    entry.get("url") or entry.get("repo", ""),
                    repo_id,
                    settings,
                    time.perf_counter(),
                    "runner-exception",
                    error=str(exc),
                )

            result["pass_name"] = pass_name
            results.append(result)
            _record_target_result(campaign_data, result)
            _write_json(CAMPAIGN_FILE, campaign_data)
            _print_result_line(completed, len(targets), result, pass_name=pass_name)

            unstarted_targets = targets[next_target_index:]
            partial_report = build_partial_report(
                sorted(results, key=lambda item: str(item.get("repo_id", ""))),
                unstarted_targets,
            )
            _persist_report(output_dir, partial_report, final=False)
            next_target_index = _submit_ready_targets(
                executor,
                future_to_entry,
                targets,
                next_target_index,
                clone_root,
                settings,
                deadline,
            )
    return sorted(results, key=lambda item: str(item.get("repo_id", ""))), targets[next_target_index:]


def _run_campaign(
    campaign_data: dict[str, Any],
    targets: list[dict[str, Any]],
    args: argparse.Namespace,
    settings: CampaignSettings,
    run_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    triage_results: list[dict[str, Any]] = []
    verification_results: list[dict[str, Any]] = []
    verification_candidates: list[dict[str, Any]] = []
    triage_unstarted_targets: list[dict[str, Any]] = []
    verification_unstarted_targets: list[dict[str, Any]] = []
    deadline = (
        time.perf_counter() + settings.campaign_budget_seconds
        if settings.campaign_budget_seconds
        else None
    )

    def build_partial_report(
        triage_partial: list[dict[str, Any]],
        triage_unstarted_partial: list[dict[str, Any]],
        verification_partial: list[dict[str, Any]] | None = None,
        verification_unstarted_partial: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return _build_report(
            run_id=run_id,
            requested_batch=args.batch,
            targets=targets,
            settings=settings,
            results=triage_partial,
            unstarted_targets=triage_unstarted_partial,
            verification_candidates=verification_candidates,
            verification_results=verification_partial or verification_results,
            verification_unstarted_targets=verification_unstarted_partial or verification_unstarted_targets,
        )

    with tempfile.TemporaryDirectory(prefix="ansede-zd-") as tmpdir:
        triage_clone_root = Path(tmpdir) / "triage_repos"
        triage_clone_root.mkdir(parents=True, exist_ok=True)
        triage_results, triage_unstarted_targets = _run_pass(
            campaign_data,
            targets,
            settings,
            output_dir=args.output_dir,
            pass_name="triage",
            build_partial_report=lambda partial_results, partial_unstarted: build_partial_report(
                partial_results,
                partial_unstarted,
            ),
            clone_root=triage_clone_root,
            deadline=deadline,
        )

        if settings.mode == "hotspot" and settings.verify_top_repos > 0:
            verification_candidates = _select_verification_candidates(
                triage_results,
                limit=settings.verify_top_repos,
                min_signal_score=settings.verify_min_signal_score,
            )
            target_by_repo_id = {str(target.get("id")): target for target in targets}
            triage_by_repo_id = {str(result.get("repo_id")): result for result in triage_results}
            verification_targets = [
                {
                    **target_by_repo_id[candidate["repo_id"]],
                    "_scan_paths_override": _select_verification_focus_paths(
                        triage_by_repo_id[candidate["repo_id"]],
                        limit=min(12, max(1, settings.max_hotspot_files)),
                    ),
                }
                for candidate in verification_candidates
                if candidate.get("repo_id") in target_by_repo_id
                and candidate.get("repo_id") in triage_by_repo_id
            ]
            if verification_targets:
                _emit_status(
                    f"Starting deep verification for {len(verification_targets)} high-signal repo(s)"
                )
                verification_settings = _verification_settings(settings)
                verification_clone_root = Path(tmpdir) / "verification_repos"
                verification_clone_root.mkdir(parents=True, exist_ok=True)
                verification_results, verification_unstarted_targets = _run_pass(
                    campaign_data,
                    verification_targets,
                    verification_settings,
                    output_dir=args.output_dir,
                    pass_name="verification",
                    build_partial_report=lambda partial_results, partial_unstarted: build_partial_report(
                        triage_results,
                        triage_unstarted_targets,
                        partial_results,
                        partial_unstarted,
                    ),
                    clone_root=verification_clone_root,
                    deadline=deadline,
                )

    return (
        triage_results,
        triage_unstarted_targets,
        verification_candidates,
        verification_results,
        verification_unstarted_targets,
    )


def main() -> int:
    args = _build_parser().parse_args()

    campaign_data = _load_campaign_data()
    targets = _select_targets(campaign_data, args.batch)
    if not targets:
        print("No queued targets found in campaign manifest")
        return 1

    settings = _build_settings(args)
    run_id = time.strftime("%Y%m%d_%H%M%S")
    _emit_status(
        f"Zero-day scanner: {len(targets)} targets | mode={settings.mode} | "
        f"repo-workers={settings.repo_workers} | file-workers={settings.workers}"
    )
    if settings.campaign_budget_seconds:
        _emit_status(f"Campaign budget: {settings.campaign_budget_seconds}s wall-clock")
    if settings.mode == "hotspot" and settings.verify_top_repos > 0:
        _emit_status(
            f"Deep verification: top={settings.verify_top_repos}, "
            f"min-signal={settings.verify_min_signal_score}, timeout={settings.verify_scan_timeout}s"
        )
    _emit_status("=" * 72)

    (
        results,
        unstarted_targets,
        verification_candidates,
        verification_results,
        verification_unstarted_targets,
    ) = _run_campaign(campaign_data, targets, args, settings, run_id)

    final_report = _build_report(
        run_id=run_id,
        requested_batch=args.batch,
        targets=targets,
        settings=settings,
        results=results,
        unstarted_targets=unstarted_targets,
        verification_candidates=verification_candidates,
        verification_results=verification_results,
        verification_unstarted_targets=verification_unstarted_targets,
    )
    report_path, sarif_path = _persist_report(args.output_dir, final_report, final=True)

    _emit_status("\n" + "=" * 72)
    _emit_status(f"SCAN COMPLETE — {final_report['summary']['completed_targets']} repos processed")
    _emit_status(f"Status counts: {final_report['summary']['status_counts']}")
    _emit_status(f"High/Critical findings: {final_report['summary']['total_high_critical']}")
    _emit_status(f"Likely-real structural findings: {final_report['summary']['total_likely_real_high_critical']}")
    if final_report["summary"]["verification_attempted_targets"]:
        _emit_status(
            f"Deep verification targets: {final_report['summary']['verification_attempted_targets']} "
            f"(high/crit={final_report['summary']['verification_total_high_critical']})"
        )
    if final_report["summary"]["unstarted_target_count"]:
        _emit_status(f"Deferred by budget: {final_report['summary']['unstarted_target_count']} targets")
    if final_report["summary"]["verification_unstarted_target_count"]:
        _emit_status(
            f"Verification deferred by budget: {final_report['summary']['verification_unstarted_target_count']} targets"
        )
    _emit_status(f"Full report: {report_path}")
    if sarif_path is not None:
        _emit_status(f"SARIF:       {sarif_path}")

    if args.json:
        json.dump(final_report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
