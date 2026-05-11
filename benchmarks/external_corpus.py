"""
benchmarks.external_corpus
──────────────────────────
Manifest-driven external corpus runner for repo-shaped sample projects.

Unlike the inline quality corpus, this runner scans directories of source files
using the public scanner API so it better approximates real project structure.
"""
from __future__ import annotations

import argparse
import fnmatch
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

from ansede_static import _CSHARP_EXTS, _GO_EXTS, _JAVA_EXTS, _JS_EXTS, _PYTHON_EXTS, scan_file


_GIT_KIND = "git"
_PATH_KIND = "path"
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SUPPORTED_LANGUAGES = ("python", "javascript", "go", "java", "csharp")


class OfflineCacheMissError(FileNotFoundError):
    """Raised when offline mode is requested but the required cache is missing."""


@dataclass(frozen=True)
class ExpectedFindingRange:
    min: int | None = None
    max: int | None = None


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
    name: str = ""
    path: str = ""
    source: ExternalCorpusSource = field(default_factory=ExternalCorpusSource)
    language: str | None = None
    languages: tuple[str, ...] = field(default_factory=tuple)
    targets: tuple[str, ...] = field(default_factory=tuple)
    exclude_paths: tuple[str, ...] = field(default_factory=tuple)
    expected_cwes: tuple[str, ...] = field(default_factory=tuple)
    forbidden_cwes: tuple[str, ...] = field(default_factory=tuple)
    expected_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    forbidden_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    expected_findings: ExpectedFindingRange = field(default_factory=ExpectedFindingRange)
    js_backend: str = "auto"
    notes: str = ""

    def effective_languages(self) -> tuple[str, ...]:
        if self.languages:
            return self.languages
        if self.language:
            return (self.language,)
        return ()


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


def _is_windows() -> bool:
    return os.name == "nt"


def _run_git(args: list[str], *, cwd: Path | None = None) -> str:
    cmd = ["git"]
    if _is_windows():
        cmd.extend(["-c", "core.longpaths=true"])
    cmd.extend(args)
    try:
        completed = subprocess.run(
            cmd,
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


def _normalize_languages(item: dict[str, Any]) -> tuple[str, ...]:
    raw_languages = item.get("languages")
    if raw_languages is None:
        language = str(item.get("language", "") or "").strip().lower()
        return (language,) if language else ()
    if not isinstance(raw_languages, list):
        raise ValueError("external corpus entry `languages` must be an array")
    languages = tuple(str(value).strip().lower() for value in raw_languages if str(value).strip())
    unknown = sorted({value for value in languages if value not in _SUPPORTED_LANGUAGES})
    if unknown:
        raise ValueError(f"unsupported external corpus languages: {', '.join(unknown)}")
    return languages


def _parse_expected_findings(item: dict[str, Any]) -> ExpectedFindingRange:
    raw_range = item.get("expected_findings")
    if raw_range is None:
        return ExpectedFindingRange()
    if not isinstance(raw_range, dict):
        raise ValueError("external corpus entry `expected_findings` must be an object")
    minimum = raw_range.get("min")
    maximum = raw_range.get("max")
    return ExpectedFindingRange(
        min=(int(minimum) if minimum is not None else None),
        max=(int(maximum) if maximum is not None else None),
    )


def _display_path_for_item(item: dict[str, Any], source: ExternalCorpusSource, fallback_path: str) -> str:
    explicit_path = str(item.get("path", "") or "")
    if explicit_path:
        return explicit_path
    if source.subdir:
        return source.subdir
    if source.repo:
        return source.repo
    return fallback_path


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
            raise OfflineCacheMissError(
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
        languages = _normalize_languages(item)
        expected_findings = _parse_expected_findings(item)
        entries.append(
            ExternalCorpusEntry(
                case_id=str(item["case_id"]),
                name=str(item.get("name", "")),
                path=_display_path_for_item(item, source, display_path),
                source=source,
                language=(str(item.get("language")) if item.get("language") else None),
                languages=languages,
                targets=tuple(str(value) for value in item.get("targets", [])),
                exclude_paths=tuple(str(value) for value in item.get("exclude_paths", [])),
                expected_cwes=tuple(str(value) for value in item.get("expected_cwes", [])),
                forbidden_cwes=tuple(str(value) for value in item.get("forbidden_cwes", [])),
                expected_rule_ids=tuple(str(value) for value in item.get("expected_rule_ids", [])),
                forbidden_rule_ids=tuple(str(value) for value in item.get("forbidden_rule_ids", [])),
                expected_findings=expected_findings,
                js_backend=str(item.get("js_backend", "auto")),
                notes=str(item.get("notes", "")),
            )
        )
    return ExternalCorpusManifest(entries=tuple(entries))


def _supported_file(path: Path, languages: tuple[str, ...]) -> bool:
    suffix = path.suffix.lower()
    if not languages:
        return suffix in _PYTHON_EXTS or suffix in _JS_EXTS or suffix in _GO_EXTS or suffix in _JAVA_EXTS or suffix in _CSHARP_EXTS
    allowed_suffixes: set[str] = set()
    if "python" in languages:
        allowed_suffixes.update(_PYTHON_EXTS)
    if "javascript" in languages:
        allowed_suffixes.update(_JS_EXTS)
    if "go" in languages:
        allowed_suffixes.update(_GO_EXTS)
    if "java" in languages:
        allowed_suffixes.update(_JAVA_EXTS)
    if "csharp" in languages:
        allowed_suffixes.update(_CSHARP_EXTS)
    return suffix in allowed_suffixes


def _scan_roots(base_path: Path, entry: ExternalCorpusEntry) -> list[Path]:
    if not entry.targets:
        return [base_path]
    return [base_path / target for target in entry.targets]


def _matches_exclude_pattern(relative_path: str, pattern: str) -> bool:
    normalized_path = relative_path.replace("\\", "/")
    normalized_pattern = pattern.replace("\\", "/").strip()
    if not normalized_pattern:
        return False
    if normalized_pattern.endswith("/"):
        prefix = normalized_pattern.rstrip("/")
        return normalized_path == prefix or normalized_path.startswith(prefix + "/")
    return fnmatch.fnmatch(normalized_path, normalized_pattern) or fnmatch.fnmatch(Path(normalized_path).name, normalized_pattern)


def _is_excluded(child: Path, base_path: Path, exclude_paths: tuple[str, ...]) -> bool:
    if not exclude_paths:
        return False
    relative_path = str(child.resolve().relative_to(base_path.resolve())).replace("\\", "/")
    return any(_matches_exclude_pattern(relative_path, pattern) for pattern in exclude_paths)


def _iter_files(base_path: Path, entry: ExternalCorpusEntry) -> list[Path]:
    files: list[Path] = []
    languages = entry.effective_languages()
    for root in _scan_roots(base_path, entry):
        if root.is_file() and _supported_file(root, languages) and not _is_excluded(root, base_path, entry.exclude_paths):
            files.append(root)
            continue
        if not root.exists():
            continue
        for child in sorted(root.rglob("*")):
            if child.is_file() and _supported_file(child, languages) and not _is_excluded(child, base_path, entry.exclude_paths):
                files.append(child)
    return files


def _noise_quotient(findings_count: int, lines_scanned: int) -> float:
    if lines_scanned <= 0:
        return 0.0
    return round(findings_count / (lines_scanned / 1000.0), 4)


def _excess_findings(entry: ExternalCorpusEntry, findings_count: int) -> int:
    if entry.expected_findings.max is None:
        return 0
    return max(0, findings_count - entry.expected_findings.max)


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
    findings_count = sum(len(result.findings) for result in results)
    lines_scanned = sum(result.lines_scanned for result in results)
    excess_findings = _excess_findings(entry, findings_count)

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
    if entry.expected_findings.min is not None:
        checks.append({
            "token": str(entry.expected_findings.min),
            "kind": "expected-findings-min",
            "passed": findings_count >= entry.expected_findings.min,
        })
    if entry.expected_findings.max is not None:
        checks.append({
            "token": str(entry.expected_findings.max),
            "kind": "expected-findings-max",
            "passed": findings_count <= entry.expected_findings.max,
        })

    findings: list[dict[str, Any]] = []
    for result in results:
        relative_path = str(Path(result.file_path).resolve().relative_to(base_path)) if files else result.file_path
        for finding in result.sorted_findings():
            finding_payload = finding.as_dict(language=result.language)
            finding_payload["file_path"] = relative_path
            findings.append(finding_payload)

    return {
        "case_id": entry.case_id,
        "name": entry.name,
        "language": entry.language,
        "languages": list(entry.effective_languages()),
        "js_backend": entry.js_backend,
        "path": entry.path,
        "source": source_record,
        "files_scanned": len(files),
        "lines_scanned": lines_scanned,
        "findings_count": findings_count,
        "excess_findings": excess_findings,
        "raw_noise_quotient": _noise_quotient(findings_count, lines_scanned),
        "noise_quotient": _noise_quotient(excess_findings, lines_scanned),
        "exclude_paths": list(entry.exclude_paths),
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
    noise_gate: float | None = None,
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
    total_findings = sum(int(case.get("findings_count", 0)) for case in case_results)
    total_excess_findings = sum(int(case.get("excess_findings", 0)) for case in case_results)
    total_lines = sum(int(case.get("lines_scanned", 0)) for case in case_results)
    aggregate_raw_noise = _noise_quotient(total_findings, total_lines)
    aggregate_noise = _noise_quotient(total_excess_findings, total_lines)
    noise_gate_failures = [
        {
            "case_id": case["case_id"],
            "name": case.get("name", ""),
            "noise_quotient": case.get("noise_quotient", 0.0),
            "raw_noise_quotient": case.get("raw_noise_quotient", 0.0),
            "findings_count": case.get("findings_count", 0),
            "excess_findings": case.get("excess_findings", 0),
            "lines_scanned": case.get("lines_scanned", 0),
        }
        for case in case_results
        if noise_gate is not None and case.get("noise_quotient", 0.0) > noise_gate
    ]

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
        "total_findings": total_findings,
        "total_excess_findings": total_excess_findings,
        "lines_scanned": total_lines,
        "raw_noise_quotient": aggregate_raw_noise,
        "noise_quotient": aggregate_noise,
    }
    report = {
        "manifest": str(manifest_file),
        "cache_dir": str(resolved_cache_dir),
        "cases": case_results,
        "summary": summary,
        "per_token": dict(sorted(per_token.items())),
        "noise_gate": {
            "threshold": noise_gate,
            "passed": (aggregate_noise <= noise_gate) if noise_gate is not None else True,
            "failures": noise_gate_failures,
        },
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
                f"  {icon}  {case['case_id']:<24} {(case['language'] or ','.join(case.get('languages', [])) or 'mixed'):<11} "
                f"files={case['files_scanned']:<3} backend={case['js_backend']:<10} source={source_label}"
            )
            if case.get("findings_count") is not None:
                print(
                    f"       findings={case['findings_count']:<4} excess={case['excess_findings']:<4} lines={case['lines_scanned']:<6} "
                    f"raw_noise={case['raw_noise_quotient']:.4f} gate_noise={case['noise_quotient']:.4f}"
                )
            for check in case["checks"]:
                status = "pass" if check["passed"] else "FAIL"
                print(f"       - {status:<4} {check['kind']:<14} {check['token']}")
        print()
        print(f"  Score: {summary['checks_passed']}/{summary['checks_total']} checks passed ({summary['score_pct']:.2f}%)")
        print(f"  Cases: {summary['passed_cases']}/{summary['total_cases']} fully green")
        print(
            f"  Noise: {summary['total_findings']} findings ({summary['raw_noise_quotient']:.4f} / kLOC raw), "
            f"{summary['total_excess_findings']} excess findings ({summary['noise_quotient']:.4f} / kLOC gate)"
        )
        if noise_gate is not None and report["noise_gate"]["failures"]:
            print(f"  Noise gate FAIL (> {noise_gate:.4f} / kLOC):")
            for failure in report["noise_gate"]["failures"]:
                label = failure["name"] or failure["case_id"]
                print(
                    f"       - {label}: {failure['noise_quotient']:.4f} / kLOC gate "
                    f"({failure['excess_findings']} excess over calibrated max; raw {failure['raw_noise_quotient']:.4f})"
                )
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
    parser.add_argument("--lang", choices=list(_SUPPORTED_LANGUAGES), default=None,
                        help="Only evaluate one language slice")
    parser.add_argument("--cache-dir", type=Path, default=None, metavar="DIR",
                        help="Cache directory for fetched git-backed external corpus sources")
    parser.add_argument("--refresh", action="store_true",
                        help="Re-fetch cached git-backed corpus sources before evaluating them")
    parser.add_argument("--offline", action="store_true",
                        help="Use only locally cached git-backed corpus sources; fail if a cache entry is missing")
    parser.add_argument("--noise-gate", type=float, default=None, metavar="NQ",
                        help="Exit with code 1 if aggregate findings per 1k LOC exceed this threshold")
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
        noise_gate=args.noise_gate,
        quiet=args.quiet,
    )

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if args.fail_under and report["summary"]["score_pct"] < args.fail_under:
        sys.exit(1)
    if args.noise_gate is not None and not report["noise_gate"]["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
