"""
benchmarks.external_corpus
──────────────────────────
Manifest-driven external corpus runner for repo-shaped sample projects.

Unlike the inline quality corpus, this runner scans directories of source files
using the public scanner API so it better approximates real project structure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ansede_static import _JS_EXTS, _PYTHON_EXTS, scan_file


_GIT_KIND = "git"
_PATH_KIND = "path"
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


@dataclass(frozen=True)
class ExternalCorpusSource:
    kind: str = _PATH_KIND
    path: str = ""
    repo: str = ""
    ref: str = ""
    subdir: str = ""


@dataclass(frozen=True)
class ExternalCorpusEntry:
    case_id: str
    path: str = ""
    source: ExternalCorpusSource = field(default_factory=ExternalCorpusSource)
    language: str | None = None
    targets: tuple[str, ...] = field(default_factory=tuple)
    expected_cwes: tuple[str, ...] = field(default_factory=tuple)
    forbidden_cwes: tuple[str, ...] = field(default_factory=tuple)
    expected_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    forbidden_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    js_backend: str = "auto"
    notes: str = ""


@dataclass(frozen=True)
class ExternalCorpusManifest:
    entries: tuple[ExternalCorpusEntry, ...]


def _source_from_manifest_item(item: dict[str, Any]) -> tuple[str, ExternalCorpusSource]:
    path_value = str(item.get("path", "") or "")
    source_data = item.get("source")

    if source_data is None:
        return path_value, ExternalCorpusSource(kind=_PATH_KIND, path=path_value)

    if not isinstance(source_data, dict):
        raise ValueError("external corpus entry `source` must be an object")

    source_kind = str(source_data.get("kind", _PATH_KIND) or _PATH_KIND).strip().lower()
    if source_kind == _PATH_KIND:
        source_path = str(source_data.get("path", path_value) or "")
        return source_path, ExternalCorpusSource(kind=_PATH_KIND, path=source_path)

    if source_kind == _GIT_KIND:
        repo = str(source_data.get("repo", "") or "")
        subdir = str(source_data.get("subdir", path_value) or "")
        display_path = path_value or subdir or repo
        return display_path, ExternalCorpusSource(
            kind=_GIT_KIND,
            repo=repo,
            ref=str(source_data.get("ref", "") or ""),
            subdir=subdir,
        )

    raise ValueError(f"unsupported external corpus source kind: {source_kind!r}")


def _default_cache_dir() -> Path:
    return Path(tempfile.gettempdir()) / "ansede-static-external-corpus"


def _safe_cache_name(text: str) -> str:
    normalized = _SAFE_NAME_RE.sub("-", text).strip("-._")
    return normalized or "repo"


def _git_cache_key(source: ExternalCorpusSource) -> str:
    repo_name = Path(source.repo.rstrip("/\\")).name or "repo"
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    digest = hashlib.sha256(
        f"{source.repo}\n{source.ref}\n{source.subdir}".encode("utf-8")
    ).hexdigest()[:12]
    return f"{_safe_cache_name(repo_name)}-{digest}"


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
        raise RuntimeError("git is required for git-backed external corpus entries") from exc
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout or "").strip()
        message = details or f"git {' '.join(args)} failed"
        raise RuntimeError(message) from exc
    return completed.stdout.strip()


def _on_rmtree_error(func, path: str, exc_info: tuple[type[BaseException], BaseException, object]) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    func(path)


def _remove_tree(path: Path) -> None:
    shutil.rmtree(path, onerror=_on_rmtree_error)


def _resolve_source_root(
    entry: ExternalCorpusEntry,
    manifest_dir: Path,
    *,
    cache_dir: Path,
    refresh: bool,
    offline: bool,
) -> tuple[Path, dict[str, Any]]:
    if entry.source.kind == _PATH_KIND:
        base_path = (manifest_dir / entry.source.path).resolve()
        return base_path, {
            "kind": _PATH_KIND,
            "path": entry.source.path,
            "resolved_path": str(base_path),
        }

    if entry.source.kind != _GIT_KIND:
        raise ValueError(f"unsupported external corpus source kind: {entry.source.kind!r}")

    if not entry.source.repo.strip():
        raise ValueError(f"git-backed external corpus entry {entry.case_id!r} is missing `source.repo`")

    checkout_dir = cache_dir / _git_cache_key(entry.source)
    cache_hit = checkout_dir.exists()

    if refresh and checkout_dir.exists():
        _remove_tree(checkout_dir)
        cache_hit = False

    if not checkout_dir.exists():
        if offline:
            raise FileNotFoundError(
                f"offline mode requested but no cached checkout exists for external corpus case {entry.case_id!r}"
            )
        cache_dir.mkdir(parents=True, exist_ok=True)
        _run_git(["clone", "--quiet", entry.source.repo, str(checkout_dir)])
    elif not (checkout_dir / ".git").exists():
        raise RuntimeError(f"cached external corpus checkout is not a git repository: {checkout_dir}")

    if entry.source.ref:
        try:
            _run_git(["checkout", "--quiet", entry.source.ref], cwd=checkout_dir)
        except RuntimeError:
            if offline:
                raise
            _run_git(["fetch", "--quiet", "--all", "--tags"], cwd=checkout_dir)
            _run_git(["checkout", "--quiet", entry.source.ref], cwd=checkout_dir)

    resolved_ref = _run_git(["rev-parse", "HEAD"], cwd=checkout_dir)
    base_path = (checkout_dir / entry.source.subdir).resolve() if entry.source.subdir else checkout_dir.resolve()
    if not base_path.exists():
        raise FileNotFoundError(
            f"external corpus case {entry.case_id!r} resolved to missing path: {base_path}"
        )

    return base_path, {
        "kind": _GIT_KIND,
        "repo": entry.source.repo,
        "ref_requested": entry.source.ref,
        "resolved_ref": resolved_ref,
        "subdir": entry.source.subdir,
        "cache_hit": cache_hit,
        "cache_path": str(checkout_dir.resolve()),
        "resolved_path": str(base_path),
    }


def load_manifest(manifest_path: str | Path) -> ExternalCorpusManifest:
    path = Path(manifest_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    entries_data = data.get("entries", [])
    entries: list[ExternalCorpusEntry] = []
    for item in entries_data:
        display_path, source = _source_from_manifest_item(item)
        entries.append(
            ExternalCorpusEntry(
                case_id=str(item["case_id"]),
                path=display_path,
                source=source,
                language=(str(item.get("language")) if item.get("language") else None),
                targets=tuple(str(value) for value in item.get("targets", [])),
                expected_cwes=tuple(str(value) for value in item.get("expected_cwes", [])),
                forbidden_cwes=tuple(str(value) for value in item.get("forbidden_cwes", [])),
                expected_rule_ids=tuple(str(value) for value in item.get("expected_rule_ids", [])),
                forbidden_rule_ids=tuple(str(value) for value in item.get("forbidden_rule_ids", [])),
                js_backend=str(item.get("js_backend", "auto")),
                notes=str(item.get("notes", "")),
            )
        )
    return ExternalCorpusManifest(entries=tuple(entries))


def _supported_file(path: Path, language: str | None) -> bool:
    suffix = path.suffix.lower()
    if language == "python":
        return suffix in _PYTHON_EXTS
    if language == "javascript":
        return suffix in _JS_EXTS
    return suffix in _PYTHON_EXTS or suffix in _JS_EXTS


def _scan_roots(base_path: Path, entry: ExternalCorpusEntry) -> list[Path]:
    if not entry.targets:
        return [base_path]
    return [base_path / target for target in entry.targets]


def _iter_files(base_path: Path, entry: ExternalCorpusEntry) -> list[Path]:
    files: list[Path] = []
    for root in _scan_roots(base_path, entry):
        if root.is_file() and _supported_file(root, entry.language):
            files.append(root)
            continue
        if not root.exists():
            continue
        for child in sorted(root.rglob("*")):
            if child.is_file() and _supported_file(child, entry.language):
                files.append(child)
    return files


def _evaluate_entry(
    entry: ExternalCorpusEntry,
    manifest_dir: Path,
    *,
    cache_dir: Path,
    refresh: bool,
    offline: bool,
) -> dict[str, Any]:
    base_path, source_record = _resolve_source_root(
        entry,
        manifest_dir,
        cache_dir=cache_dir,
        refresh=refresh,
        offline=offline,
    )
    files = _iter_files(base_path, entry)
    results = [scan_file(file_path, js_backend=entry.js_backend) for file_path in files]

    seen_cwes = {finding.cwe for result in results for finding in result.findings if finding.cwe}
    seen_rule_ids = {finding.rule_id for result in results for finding in result.findings if finding.rule_id}

    checks: list[dict[str, Any]] = []
    for token in entry.expected_cwes:
        checks.append({"token": token, "kind": "expected-cwe", "passed": token in seen_cwes})
    for token in entry.forbidden_cwes:
        checks.append({"token": token, "kind": "forbidden-cwe", "passed": token not in seen_cwes})
    for token in entry.expected_rule_ids:
        checks.append({"token": token, "kind": "expected-rule", "passed": token in seen_rule_ids})
    for token in entry.forbidden_rule_ids:
        checks.append({"token": token, "kind": "forbidden-rule", "passed": token not in seen_rule_ids})

    findings: list[dict[str, Any]] = []
    for result in results:
        relative_path = str(Path(result.file_path).resolve().relative_to(base_path)) if files else result.file_path
        for finding in result.sorted_findings():
            finding_payload = finding.as_dict(language=result.language)
            finding_payload["file_path"] = relative_path
            findings.append(finding_payload)

    return {
        "case_id": entry.case_id,
        "language": entry.language,
        "js_backend": entry.js_backend,
        "path": entry.path,
        "source": source_record,
        "files_scanned": len(files),
        "passed": all(check["passed"] for check in checks),
        "checks": checks,
        "findings": findings,
        "notes": entry.notes,
    }


def run_external_corpus(
    manifest_path: str | Path,
    *,
    case_filter: str | None = None,
    lang_filter: str | None = None,
    cache_dir: str | Path | None = None,
    refresh: bool = False,
    offline: bool = False,
    quiet: bool = False,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path)
    manifest = load_manifest(manifest_file)
    resolved_cache_dir = Path(cache_dir).resolve() if cache_dir is not None else _default_cache_dir().resolve()
    entries = [entry for entry in manifest.entries if (not case_filter or entry.case_id == case_filter) and (not lang_filter or entry.language == lang_filter)]

    case_results = [
        _evaluate_entry(
            entry,
            manifest_file.parent,
            cache_dir=resolved_cache_dir,
            refresh=refresh,
            offline=offline,
        )
        for entry in entries
    ]
    checks_total = sum(len(case["checks"]) for case in case_results)
    checks_passed = sum(1 for case in case_results for check in case["checks"] if check["passed"])
    passed_cases = sum(1 for case in case_results if case["passed"])

    per_token: dict[str, dict[str, int]] = defaultdict(lambda: {"checks": 0, "passed": 0})
    for case in case_results:
        for check in case["checks"]:
            bucket = per_token[check["token"]]
            bucket["checks"] += 1
            bucket["passed"] += 1 if check["passed"] else 0

    summary = {
        "total_cases": len(case_results),
        "passed_cases": passed_cases,
        "checks_total": checks_total,
        "checks_passed": checks_passed,
        "score_pct": round((checks_passed / checks_total * 100.0) if checks_total else 0.0, 2),
    }
    report = {
        "manifest": str(manifest_file),
        "cache_dir": str(resolved_cache_dir),
        "cases": case_results,
        "summary": summary,
        "per_token": dict(sorted(per_token.items())),
    }

    if not quiet:
        print()
        print("┌" + "─" * 72 + "┐")
        print("│{:^72}│".format("ansede-static External Corpus Runner"))
        print("│{:^72}│".format("Manifest-driven checks over repo-shaped sample projects"))
        print("└" + "─" * 72 + "┘")
        print()
        for case in case_results:
            icon = "✓" if case["passed"] else "✗"
            source = case.get("source", {})
            source_label = source.get("kind", _PATH_KIND)
            if source_label == _GIT_KIND:
                cache_state = "hit" if source.get("cache_hit") else "miss"
                resolved_ref = str(source.get("resolved_ref", ""))[:8]
                source_label = f"git/{cache_state}"
                if resolved_ref:
                    source_label = f"{source_label}@{resolved_ref}"
            print(
                f"  {icon}  {case['case_id']:<24} {case['language'] or 'mixed':<11} "
                f"files={case['files_scanned']:<3} backend={case['js_backend']:<10} source={source_label}"
            )
            for check in case["checks"]:
                status = "pass" if check["passed"] else "FAIL"
                print(f"       - {status:<4} {check['kind']:<14} {check['token']}")
        print()
        print(f"  Score: {summary['checks_passed']}/{summary['checks_total']} checks passed ({summary['score_pct']:.2f}%)")
        print(f"  Cases: {summary['passed_cases']}/{summary['total_cases']} fully green")
        print()

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static external corpus runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json
              python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --case python-portal-vuln
                            python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.example.json --cache-dir .tmp/ansede-corpus --refresh
              python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100 --quiet --json
        """),
    )
    parser.add_argument("--manifest", type=Path, default=Path("benchmarks/external_manifest.json"), metavar="FILE",
                        help="Path to the external corpus manifest JSON")
    parser.add_argument("--case", default=None, metavar="CASE_ID",
                        help="Run only one manifest entry by case_id")
    parser.add_argument("--lang", choices=["python", "javascript"], default=None,
                        help="Only evaluate one language slice")
    parser.add_argument("--cache-dir", type=Path, default=None, metavar="DIR",
                        help="Cache directory for fetched git-backed external corpus sources")
    parser.add_argument("--refresh", action="store_true",
                        help="Re-fetch cached git-backed corpus sources before evaluating them")
    parser.add_argument("--offline", action="store_true",
                        help="Use only locally cached git-backed corpus sources; fail if a cache entry is missing")
    parser.add_argument("--fail-under", type=float, default=0.0, metavar="PCT",
                        help="Exit with code 1 if score is below this percentage")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress the human summary")
    parser.add_argument("--json", action="store_true",
                        help="Print the final report as JSON")
    args = parser.parse_args()

    if args.refresh and args.offline:
        parser.error("--refresh and --offline cannot be used together")

    report = run_external_corpus(
        args.manifest,
        case_filter=args.case,
        lang_filter=args.lang,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        quiet=args.quiet,
    )

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if args.fail_under and report["summary"]["score_pct"] < args.fail_under:
        sys.exit(1)


if __name__ == "__main__":
    main()
