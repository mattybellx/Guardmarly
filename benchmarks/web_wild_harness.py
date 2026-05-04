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

_stdout_reconfigure = getattr(sys.stdout, "reconfigure", None)
if callable(_stdout_reconfigure):
    try:
        _stdout_reconfigure(encoding="utf-8", errors="replace")
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
    "tests", "test", "docs", "doc", "docs_src", "examples", "example", "tutorial",
    "migrations", "locale", "i18n", "fixtures", "__pycache__", "node_modules",
    # Git hooks and project-management scripts are not web-app code.
    "scripts",
})

_VENDOR_PATH_SEGMENTS: frozenset[str] = frozenset({
    "vendor", "vendors", "third_party", "third-party", "node_modules", "bower_components",
})

_MINIFIED_FILE_RE = re.compile(r"(?:\.min\.(?:js|css)$|(?:^|[._-])(bundle|chunk)(?:[._-]|\.)?.*\.js$)", re.IGNORECASE)

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


@dataclass(frozen=True)
class CuratedLabel:
    repo: str
    relative_path: str
    expected_cwes: tuple[str, ...] = ()
    label_reasons: tuple[str, ...] = ()
    notes: str = ""


_FRAMEWORK_WEAK_LABEL_SUPPRESSIONS: dict[str, frozenset[str]] = {
    "pallets/flask": frozenset({"CWE-22", "CWE-918"}),
    "django/django": frozenset({"CWE-22", "CWE-918"}),
    "tiangolo/fastapi": frozenset({"CWE-22", "CWE-918"}),
    "expressjs/express": frozenset({"CWE-22", "CWE-918", "CWE-98"}),
}

_FRAMEWORK_WEAK_FILE_SUPPRESSIONS: tuple[tuple[str, re.Pattern[str], frozenset[str]], ...] = (
    (
        "django/django",
        re.compile(r"^django/contrib/admin/static/admin/js/", re.IGNORECASE),
        frozenset({"CWE-79"}),
    ),
    (
        "django/django",
        re.compile(r"^django/core/management/commands/shell\.py$", re.IGNORECASE),
        frozenset({"CWE-22"}),
    ),
    (
        "django/django",
        re.compile(r"^django/core/management/utils\.py$", re.IGNORECASE),
        frozenset({"CWE-22"}),
    ),
    (
        "django/django",
        re.compile(r"^django/db/", re.IGNORECASE),
        frozenset({"CWE-89"}),
    ),
    (
        "django/django",
        re.compile(r"^django/contrib/auth/admin\.py$", re.IGNORECASE),
        frozenset({"CWE-601"}),
    ),
    (
        "django/django",
        re.compile(r"^django/utils/autoreload\.py$", re.IGNORECASE),
        frozenset({"CWE-22"}),
    ),
    (
        "pallets/flask",
        re.compile(r"^src/flask/config\.py$", re.IGNORECASE),
        frozenset({"CWE-95"}),
    ),
    (
        "pallets/flask",
        re.compile(r"^src/flask/cli\.py$", re.IGNORECASE),
        frozenset({"CWE-22", "CWE-95"}),
    ),
    (
        "pallets/flask",
        re.compile(r"^src/flask/helpers\.py$", re.IGNORECASE),
        frozenset({"CWE-22"}),
    ),
)


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


def _normalize_relative_path(value: str | Path) -> str:
    return str(value).replace("\\", "/").strip("/")


def _is_vendor_or_minified_file(path: Path, *, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    rel_parts = {part.lower() for part in relative.parts}
    if rel_parts & _VENDOR_PATH_SEGMENTS:
        return True
    return bool(_MINIFIED_FILE_RE.search(path.name))


def _is_vendor_or_minified_relative_path(relative_path: str) -> bool:
    rel = Path(_normalize_relative_path(relative_path))
    rel_parts = {part.lower() for part in rel.parts}
    if rel_parts & _VENDOR_PATH_SEGMENTS:
        return True
    return bool(_MINIFIED_FILE_RE.search(rel.name))


def _repo_slug_from_source(repo_value: str) -> str:
    text = repo_value.strip().rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    match = re.search(r"github\.com[/:]([^/]+)/([^/]+)$", text, re.IGNORECASE)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    parts = text.replace("\\", "/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return text


def _load_curated_labels(manifest_path: str | Path | None) -> dict[tuple[str, str], CuratedLabel]:
    if manifest_path is None:
        return {}
    path = Path(manifest_path)
    if not path.exists():
        raise FileNotFoundError(f"curated label manifest not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", [])
    labels: dict[tuple[str, str], CuratedLabel] = {}
    for item in entries:
        source = item.get("source", {}) if isinstance(item.get("source", {}), dict) else {}
        targets = [str(value) for value in item.get("targets", [])]
        if not targets and item.get("path"):
            targets = [str(item["path"])]
        repo = _repo_slug_from_source(str(source.get("repo", "") or item.get("repo", "")))
        subdir = _normalize_relative_path(str(source.get("subdir", "") or ""))
        expected = tuple(sorted({str(value) for value in item.get("expected_cwes", [])}))
        if not repo or not targets:
            continue
        for target in targets:
            relative_path = _normalize_relative_path(Path(subdir) / target if subdir else Path(target))
            reasons = (
                f"curated manifest: {path.name}:{item.get('case_id', relative_path)}",
                *( [str(item.get("notes", ""))] if str(item.get("notes", "")).strip() else [] ),
            )
            key = (repo, relative_path)
            existing = labels.get(key)
            merged_expected = tuple(sorted({*expected, *(existing.expected_cwes if existing else ())}))
            merged_reasons = tuple(dict.fromkeys((*(existing.label_reasons if existing else ()), *reasons)))
            merged_notes = " | ".join(
                dict.fromkeys(
                    note for note in (
                        existing.notes if existing else "",
                        str(item.get("notes", "")),
                    ) if note.strip()
                )
            )
            labels[key] = CuratedLabel(
                repo=repo,
                relative_path=relative_path,
                expected_cwes=merged_expected,
                label_reasons=merged_reasons,
                notes=merged_notes,
            )
    return labels


def _has_non_request_path_signal(code: str) -> bool:
    return bool(re.search(r"(?:os\.environ|getenv|process\.env|sys\.argv|argv\[)", code, re.IGNORECASE))


def _apply_weak_label_policy(sample: SampledFile, code: str, labels: set[str], reasons: list[str]) -> tuple[set[str], list[str]]:
    suppressed = _FRAMEWORK_WEAK_LABEL_SUPPRESSIONS.get(sample.repo, frozenset())
    kept_labels = {
        label
        for label in labels
        if label not in suppressed or (label == "CWE-22" and _has_non_request_path_signal(code))
    }
    file_suppressed: set[str] = set()
    rel_path = _normalize_relative_path(sample.relative_path)
    for repo, path_re, cwes in _FRAMEWORK_WEAK_FILE_SUPPRESSIONS:
        if sample.repo == repo and path_re.search(rel_path):
            file_suppressed.update(cwes)
    kept_labels = {label for label in kept_labels if label not in file_suppressed}
    if kept_labels == labels:
        return labels, reasons
    all_suppressed = set(suppressed) | file_suppressed
    kept_reasons = [reason for reason in reasons if not any(label in reason for label in all_suppressed)]
    return kept_labels, kept_reasons


def _labels_for_sample(
    sample: SampledFile,
    code: str,
    *,
    label_mode: str,
    curated_labels: dict[tuple[str, str], CuratedLabel] | None,
) -> tuple[set[str], list[str], str]:
    curated = (curated_labels or {}).get((sample.repo, _normalize_relative_path(sample.relative_path)))
    weak_labels, weak_reasons = _infer_expected_labels(code)
    weak_labels, weak_reasons = _apply_weak_label_policy(sample, code, weak_labels, weak_reasons)
    if label_mode == "curated":
        if curated is None:
            return set(), [], "curated-unlabeled"
        return set(curated.expected_cwes), list(curated.label_reasons), "curated"
    if label_mode == "hybrid" and curated is not None:
        return set(curated.expected_cwes), list(curated.label_reasons), "curated"
    return weak_labels, weak_reasons, "weak"


def _collect_repo_files(root: Path, *, max_file_bytes: int, vendor_mode: str = "include") -> list[Path]:
    files: list[Path] = []
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        if not _is_candidate_file(file):
            continue
        rel_parts = {part.lower() for part in file.relative_to(root).parts}
        if rel_parts & _SKIP_PATH_SEGMENTS:
            continue
        vendor_like = _is_vendor_or_minified_file(file, root=root)
        if vendor_mode == "exclude" and vendor_like:
            continue
        if vendor_mode == "only" and not vendor_like:
            continue
        try:
            if file.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        files.append(file)
    return files


_LABEL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CWE-95", re.compile(r"(?<!def\s)(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(", re.IGNORECASE)),
    ("CWE-89", re.compile(r"[\"'`]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,160}(?:[\"'`]\s*\+|\$\{)|execute\s*\(\s*f[\"']", re.IGNORECASE)),
    ("CWE-79", re.compile(r"innerHTML\s*=|document\.write\s*\(", re.IGNORECASE)),
    ("CWE-918", re.compile(r"(?:requests\.(?:get|post|put|delete|request)|fetch|axios\.(?:get|post|put|delete)|needle\.(?:get|post|request))\s*\(\s*(?:req(?:uest)?\.|\b(?:url|uri|endpoint|target|host|callback|webhook)\b|[A-Za-z_][\w]*(?:url|uri|endpoint|target|host|callback|webhook)[A-Za-z_\d]*)", re.IGNORECASE)),
    ("CWE-601", re.compile(r"redirect\s*\(\s*(?:req\.|request\.)", re.IGNORECASE)),
    ("CWE-98", re.compile(r"\brequire\s*\(\s*(?![\"']).+\)|\bimport\s*\(\s*(?![\"']).+\)", re.IGNORECASE)),
)

_COMMAND_EXEC_RE = re.compile(r"\bchild_process\.exec\s*\(", re.IGNORECASE)
_COMMAND_EXEC_ALIAS_RE = re.compile(
    r"\b(?:const|let|var)\s+(?P<alias>[A-Za-z_][\w]*)\s*=\s*require\(\s*['\"]child_process['\"]\s*\)\.exec\b",
    re.IGNORECASE,
)
_COMMAND_DYNAMIC_RE = re.compile(r"\+|process\.env|os\.environ|argv\[|\barg\b|\bcmd\b|\bcommand\b", re.IGNORECASE)
_SUBPROCESS_SHELL_RE = re.compile(
    r"subprocess\.(?:run|Popen|call|check_output|check_call)\s*\((?P<args>[\s\S]*?)\)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?P<key>\b(?:SECRET_KEY|API_KEY|apiKey|cookieSecret|zapApiKey|cryptoKey|clientSecret|accessKey|secret|token|dbPassword|db_pass|passwd|password)\b)\s*[:=]\s*[\"'](?P<value>[^\"']{6,})[\"']",
    re.IGNORECASE,
)
_UNSAFE_YAML_LOAD_RE = re.compile(r"yaml\.load\s*\(", re.IGNORECASE)
_SAFE_YAML_LOADER_RE = re.compile(r"Loader\s*=\s*(?:yaml\.)?(?:C?SafeLoader)", re.IGNORECASE)

_PATH_USER_CONTROL_RE = re.compile(
    r"request\.|req\.|(?:^|\W)(?:params|query|body)\.|"
    r"\.get\s*\(\s*[\"'](?:file|path|filename|filepath|name)[\"']\s*\)|"
    r"(?:sys\.argv|argv\[|request\.files|req\.files|os\.environ|getenv|process\.env)",
    re.IGNORECASE,
)

_PATH_SINK_RE = re.compile(
    r"os\.path\.join\s*\(|(?:^|\W)open\s*\(|Path\s*\(|"
    r"send_file\s*\(|send_from_directory\s*\(|FileResponse\s*\(|"
    r"fs\.(?:readFile|readFileSync|createReadStream)\s*\(|res\.(?:sendFile|download)\s*\(",
    re.IGNORECASE,
)


def _infer_path_traversal_label(code: str) -> tuple[bool, str | None]:
    lines = code.splitlines()
    user_lines = [index for index, line in enumerate(lines) if _PATH_USER_CONTROL_RE.search(line)]
    sink_lines = [index for index, line in enumerate(lines) if _PATH_SINK_RE.search(line)]
    if not user_lines or not sink_lines:
        return False, None

    for user_line in user_lines:
        for sink_line in sink_lines:
            if abs(user_line - sink_line) <= 8:
                return True, "CWE-22: nearby user-controlled path signal + file/path sink"
    return False, None


def _infer_command_injection_label(code: str) -> tuple[bool, str | None]:
    if _COMMAND_EXEC_RE.search(code) and _COMMAND_DYNAMIC_RE.search(code):
        return True, "CWE-78: dynamic exec() command construction"

    for match in _COMMAND_EXEC_ALIAS_RE.finditer(code):
        alias = re.escape(match.group("alias"))
        if re.search(rf"\b{alias}\s*\([\s\S]{{0,160}}?(?:\+|process\.env|os\.environ|argv\[|\barg\b|\bcmd\b|\bcommand\b)", code, re.IGNORECASE):
            return True, "CWE-78: dynamic child_process.exec alias invocation"

    for match in _SUBPROCESS_SHELL_RE.finditer(code):
        args = match.group("args")
        if "shell=True" not in args and "shell = True" not in args:
            continue
        first_arg = args.split(",", 1)[0].strip()
        if first_arg.startswith(("'", '"')) and _COMMAND_DYNAMIC_RE.search(first_arg) is None:
            continue
        if _COMMAND_DYNAMIC_RE.search(args):
            return True, "CWE-78: subprocess shell=True with dynamic command input"
    return False, None


def _infer_code_injection_label(code: str) -> tuple[bool, str | None]:
    if re.search(r"(?<!def\s)(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(", code, re.IGNORECASE):
        return True, "CWE-95: dynamic code execution primitive"
    if _COMMAND_EXEC_ALIAS_RE.search(code) or _COMMAND_EXEC_RE.search(code):
        return False, None
    if re.search(r"\bexec\s*\(", code):
        return True, "CWE-95: exec() dynamic code execution"
    return False, None


def _looks_like_secret_value(key: str, value: str) -> bool:
    stripped = value.strip()
    if not stripped or len(stripped) < 8:
        return False
    strong_secret_key = key.lower() in {"secret_key", "apikey", "api_key", "cookiesecret", "zapapikey", "cryptokey", "clientsecret"}
    if stripped.endswith(":"):
        return False
    if any(ch.isspace() for ch in stripped) and not strong_secret_key:
        return False
    lowered = stripped.lower()
    if any(token in lowered for token in ("enter ", "again", "username", "password: ", "aborted", "change password")):
        return False
    return True


def _infer_hardcoded_secret_label(code: str) -> tuple[bool, str | None]:
    if re.search(r"AKIA[0-9A-Z]{16}", code):
        return True, "CWE-798: hardcoded access key pattern"
    for match in _SECRET_ASSIGNMENT_RE.finditer(code):
        if _looks_like_secret_value(match.group("key"), match.group("value")):
            return True, f"CWE-798: suspicious hardcoded secret in `{match.group('key')}`"
    return False, None


def _infer_unsafe_deserialization_label(code: str) -> tuple[bool, str | None]:
    if re.search(r"pickle\.loads?\s*\(|marshal\.loads?\s*\(", code):
        return True, "CWE-502: unsafe deserializer call"
    for line in code.splitlines():
        if not _UNSAFE_YAML_LOAD_RE.search(line):
            continue
        if _SAFE_YAML_LOADER_RE.search(line) or "yaml.safe_load" in line:
            continue
        return True, "CWE-502: yaml.load without safe loader"
    return False, None


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def _infer_expected_labels(code: str) -> tuple[set[str], list[str]]:
    labels: set[str] = set()
    reasons: list[str] = []
    for cwe, rx in _LABEL_PATTERNS:
        if rx.search(code):
            labels.add(cwe)
            reasons.append(f"{cwe}: pattern {rx.pattern[:40]}...")
    command_hit, command_reason = _infer_command_injection_label(code)
    if command_hit:
        labels.add("CWE-78")
        if command_reason:
            reasons.append(command_reason)
    code_exec_hit, code_exec_reason = _infer_code_injection_label(code)
    if code_exec_hit:
        labels.add("CWE-95")
        if code_exec_reason:
            reasons.append(code_exec_reason)
    secret_hit, secret_reason = _infer_hardcoded_secret_label(code)
    if secret_hit:
        labels.add("CWE-798")
        if secret_reason:
            reasons.append(secret_reason)
    deserialization_hit, deserialization_reason = _infer_unsafe_deserialization_label(code)
    if deserialization_hit:
        labels.add("CWE-502")
        if deserialization_reason:
            reasons.append(deserialization_reason)
    path_hit, path_reason = _infer_path_traversal_label(code)
    if path_hit:
        labels.add("CWE-22")
        if path_reason:
            reasons.append(path_reason)
    return labels, reasons


def _partition_candidates_by_labels(
    candidates: list[SampledFile],
    *,
    label_mode: str,
    curated_labels: dict[tuple[str, str], CuratedLabel] | None,
) -> tuple[list[SampledFile], list[SampledFile]]:
    curated_candidates, weak_labeled_candidates, unlabeled_candidates = _partition_candidates_by_label_source(
        candidates,
        label_mode=label_mode,
        curated_labels=curated_labels,
    )
    return [*curated_candidates, *weak_labeled_candidates], unlabeled_candidates


def _partition_candidates_by_label_source(
    candidates: list[SampledFile],
    *,
    label_mode: str,
    curated_labels: dict[tuple[str, str], CuratedLabel] | None,
) -> tuple[list[SampledFile], list[SampledFile], list[SampledFile]]:
    curated_candidates: list[SampledFile] = []
    weak_labeled_candidates: list[SampledFile] = []
    labeled_candidates: list[SampledFile] = []
    unlabeled_candidates: list[SampledFile] = []
    for candidate in candidates:
        try:
            code = candidate.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unlabeled_candidates.append(candidate)
            continue
        expected, _, _ = _labels_for_sample(
            candidate,
            code,
            label_mode=label_mode,
            curated_labels=curated_labels,
        )
        _, _, label_source = _labels_for_sample(
            candidate,
            code,
            label_mode=label_mode,
            curated_labels=curated_labels,
        )
        if expected:
            labeled_candidates.append(candidate)
            if label_source == "curated":
                curated_candidates.append(candidate)
            else:
                weak_labeled_candidates.append(candidate)
        else:
            unlabeled_candidates.append(candidate)
    return curated_candidates, weak_labeled_candidates, unlabeled_candidates


def _sample_candidates(
    candidates: list[SampledFile],
    *,
    total: int,
    rng: random.Random,
    sampling_mode: str,
) -> list[SampledFile]:
    if total <= 0 or not candidates:
        return []
    if sampling_mode == "global":
        return rng.sample(candidates, min(total, len(candidates)))

    buckets: dict[str, list[SampledFile]] = {}
    for candidate in candidates:
        buckets.setdefault(candidate.repo, []).append(candidate)
    repo_order = list(buckets)
    rng.shuffle(repo_order)
    for repo in repo_order:
        rng.shuffle(buckets[repo])

    sampled: list[SampledFile] = []
    while repo_order and len(sampled) < total:
        next_order: list[str] = []
        for repo in repo_order:
            bucket = buckets[repo]
            if bucket and len(sampled) < total:
                sampled.append(bucket.pop())
            if bucket:
                next_order.append(repo)
        repo_order = next_order
    return sampled


def _select_samples(
    *,
    candidates: list[SampledFile],
    n_files: int,
    min_labeled: int,
    seed: int,
    label_mode: str,
    curated_labels: dict[tuple[str, str], CuratedLabel] | None,
    sampling_mode: str,
) -> tuple[list[SampledFile], int]:
    rng = random.Random(seed)
    sample_count = min(n_files, len(candidates))
    curated_candidates, weak_labeled_candidates, _ = _partition_candidates_by_label_source(
        candidates,
        label_mode=label_mode,
        curated_labels=curated_labels,
    )
    labeled_candidates = [*curated_candidates, *weak_labeled_candidates]

    target_labeled = min(max(0, min_labeled), sample_count, len(labeled_candidates))
    sampled: list[SampledFile] = []
    curated_target = min(target_labeled, len(curated_candidates))
    if curated_target:
        sampled.extend(
            _sample_candidates(
                curated_candidates,
                total=curated_target,
                rng=rng,
                sampling_mode=sampling_mode,
            )
        )
    remaining_labeled = target_labeled - len(sampled)
    if remaining_labeled > 0:
        sampled_keys = {(item.repo, item.relative_path) for item in sampled}
        weak_pool = [candidate for candidate in weak_labeled_candidates if (candidate.repo, candidate.relative_path) not in sampled_keys]
        sampled.extend(
            _sample_candidates(
                weak_pool,
                total=remaining_labeled,
                rng=rng,
                sampling_mode=sampling_mode,
            )
        )

    remaining = sample_count - len(sampled)
    if remaining > 0:
        sampled_keys = {(item.repo, item.relative_path) for item in sampled}
        pool = [candidate for candidate in candidates if (candidate.repo, candidate.relative_path) not in sampled_keys]
        sampled.extend(
            _sample_candidates(
                pool,
                total=remaining,
                rng=rng,
                sampling_mode=sampling_mode,
            )
        )
    return sampled, len(labeled_candidates)


def _severity_allows(finding: dict[str, Any], threshold: str) -> bool:
    s = str(finding.get("severity", "info")).lower()
    return _SEVERITY_ORDER.get(s, 0) >= _SEVERITY_ORDER.get(threshold.lower(), 0)


def _score_sample(
    sample: SampledFile,
    *,
    severity_min: str,
    js_backend: str,
    suppression_config: Path | None,
    label_mode: str = "weak",
    curated_labels: dict[tuple[str, str], CuratedLabel] | None = None,
) -> dict[str, Any]:
    code = sample.path.read_text(encoding="utf-8", errors="replace")
    expected_labels, label_reasons, label_source = _labels_for_sample(
        sample,
        code,
        label_mode=label_mode,
        curated_labels=curated_labels,
    )

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
        "label_source": label_source,
        "predicted_labels": sorted(predicted_labels),
        "vendor_or_minified": _is_vendor_or_minified_relative_path(sample.relative_path),
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
    sampling_mode: str = "global",
    vendor_mode: str = "include",
    label_mode: str = "weak",
    label_manifest: Path | None = None,
    quiet: bool,
) -> dict[str, Any]:
    repo_meta: list[dict[str, Any]] = []
    candidates: list[SampledFile] = []
    curated_labels = _load_curated_labels(label_manifest)

    for repo in repos:
        repo_root, meta = _ensure_repo(repo, cache_dir=cache_dir, refresh=refresh, offline=offline)
        repo_meta.append(meta)
        files = _collect_repo_files(repo_root, max_file_bytes=max_file_bytes, vendor_mode=vendor_mode)
        for file in files:
            candidates.append(
                SampledFile(
                    repo=repo.slug,
                    path=file,
                    relative_path=_normalize_relative_path(file.resolve().relative_to(repo_root.resolve())),
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
    sampled, labeled_pool = _select_samples(
        candidates=candidates,
        n_files=n_files,
        min_labeled=min_labeled,
        seed=seed,
        label_mode=label_mode,
        curated_labels=curated_labels,
        sampling_mode=sampling_mode,
    )

    sample_reports = [
        _score_sample(
            sample,
            severity_min=severity_min,
            js_backend=js_backend,
            suppression_config=suppression_config,
            label_mode=label_mode,
            curated_labels=curated_labels,
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
        "labeled_candidate_pool": labeled_pool,
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
        "sampling_mode": sampling_mode,
        "vendor_mode": vendor_mode,
        "label_mode": label_mode,
        "label_manifest": str(label_manifest) if label_manifest else None,
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


def _run_cve_quality_gate(*, suppression_config: Path | None, min_recall: float) -> tuple[bool, dict[str, Any]]:
    """Run the CVE corpus quality gate and return (passed, payload)."""
    if suppression_config is None:
        return True, {"skipped": True, "reason": "no suppression config"}

    try:
        from benchmarks.cve_recall_runner import run_cve_recall
        report = run_cve_recall(quiet=True, suppression_config=suppression_config)
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        recall = float(summary.get("recall", 0.0)) if isinstance(summary, dict) else 0.0
        passed = recall >= float(min_recall)
        return passed, {
            "skipped": False,
            "recall": recall,
            "min_recall": float(min_recall),
            "summary": summary,
        }
    except Exception as exc:  # noqa: BLE001
        return False, {"skipped": False, "error": str(exc)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ansede-static web wild online corpus harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              python -m benchmarks.web_wild_harness --n-files 40 --seed 1337
              python -m benchmarks.web_wild_harness --repos OWASP/NodeGoat pallets/flask --n-files 20
                            python -m benchmarks.web_wild_harness --sampling-mode balanced --vendor-mode exclude --label-mode hybrid --label-manifest benchmarks/real_world_manifest.json
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
    parser.add_argument("--sampling-mode", choices=["global", "balanced"], default="global",
                        help="Sampling strategy across repos")
    parser.add_argument("--vendor-mode", choices=["include", "exclude", "only"], default="include",
                        help="Whether to include vendor/minified files in the candidate pool")
    parser.add_argument("--label-mode", choices=["weak", "curated", "hybrid"], default="weak",
                        help="How expected labels are sourced for scoring")
    parser.add_argument("--label-manifest", type=Path, default=None, metavar="FILE",
                        help="Optional curated real-world manifest used by --label-mode curated/hybrid")
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
    parser.add_argument("--output", type=Path, default=None, metavar="FILE",
                        help="Optional UTF-8 file to write the JSON report to")
    parser.add_argument("--quality-gate-cve", action="store_true",
                        help="Run CVE recall gate when --suppression-config is provided")
    parser.add_argument("--quality-gate-min-recall", type=float, default=100.0, metavar="PCT",
                        help="Minimum CVE recall percentage required by --quality-gate-cve (default: 100)")
    args = parser.parse_args()

    if args.refresh and args.offline:
        parser.error("--refresh and --offline cannot be used together")

    specs = _parse_repo_specs(args.repos)
    cache_dir = (args.cache_dir or _default_cache_dir()).resolve()
    label_manifest = args.label_manifest
    if label_manifest is None and args.label_mode in {"curated", "hybrid"}:
        label_manifest = Path("benchmarks/real_world_manifest.json")

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
        sampling_mode=args.sampling_mode,
        vendor_mode=args.vendor_mode,
        label_mode=args.label_mode,
        label_manifest=label_manifest,
        quiet=args.quiet,
    )

    quality_gate_failed = False
    if args.quality_gate_cve:
        passed, payload = _run_cve_quality_gate(
            suppression_config=args.suppression_config,
            min_recall=args.quality_gate_min_recall,
        )
        quality_gate_failed = not passed
        report["quality_gate_cve"] = payload

    if args.output is not None:
        _write_report(args.output, report)

    if args.json or args.quiet:
        print(json.dumps(report, indent=2))

    if _fails_thresholds(
        report,
        fail_under_recall=args.fail_under_recall,
        fail_under_precision=args.fail_under_precision,
        fail_under_f1=args.fail_under_f1,
        max_fp_rate=args.max_fp_rate,
    ) or quality_gate_failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
