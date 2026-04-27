from __future__ import annotations

import json
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

from benchmarks.external_corpus import load_manifest, run_external_corpus


def _run_git(args: list[str], *, cwd: Path) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout.strip()


def _init_git_fixture_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    _run_git(["init"], cwd=repo_dir)
    _run_git(["config", "user.email", "ansede@example.test"], cwd=repo_dir)
    _run_git(["config", "user.name", "Ansede Test"], cwd=repo_dir)

    sample_dir = repo_dir / "sample"
    sample_dir.mkdir()
    (sample_dir / "app.py").write_text(
        """
from flask import Flask

app = Flask(__name__)

@app.route('/admin/users')
def list_users():
    return []
""".strip() + "\n",
        encoding="utf-8",
    )

    _run_git(["add", "."], cwd=repo_dir)
    _run_git(["commit", "-m", "fixture"], cwd=repo_dir)
    return _run_git(["rev-parse", "HEAD"], cwd=repo_dir)


def test_load_external_manifest_has_entries():
    manifest = load_manifest(Path("benchmarks/external_manifest.json"))

    assert manifest.entries
    assert {entry.case_id for entry in manifest.entries} == {
        "python-portal-vuln",
        "python-portal-safe",
        "js-portal-vuln",
        "js-portal-safe",
    }


def test_external_corpus_manifest_is_green():
    report = run_external_corpus(Path("benchmarks/external_manifest.json"), quiet=True)

    assert report["summary"]["checks_total"] > 0
    assert report["summary"]["score_pct"] == 100.0


def test_external_corpus_case_filter_runs_single_entry():
    report = run_external_corpus(Path("benchmarks/external_manifest.json"), case_filter="python-portal-vuln", quiet=True)

    assert report["summary"]["total_cases"] == 1
    assert report["cases"][0]["case_id"] == "python-portal-vuln"


def test_load_real_world_manifest_has_curated_git_entries():
    manifest = load_manifest(Path("benchmarks/real_world_manifest.json"))

    assert {entry.case_id for entry in manifest.entries} == {
        "nodegoat-open-redirect-and-bruteforce",
        "nodegoat-redos-validation",
        "nodegoat-eval-code-injection",
    }
    assert all(entry.source.kind == "git" for entry in manifest.entries)
    assert all(entry.source.repo == "https://github.com/OWASP/NodeGoat.git" for entry in manifest.entries)
    assert all(len(entry.source.ref) == 40 for entry in manifest.entries)
    assert all(entry.js_backend == "structural" for entry in manifest.entries)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for git-backed corpus tests")
def test_load_manifest_supports_git_source(tmp_path):
    repo_dir = tmp_path / "fixture-repo"
    head = _init_git_fixture_repo(repo_dir)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "entries": [{
            "case_id": "git-python-admin-vuln",
            "source": {
                "kind": "git",
                "repo": str(repo_dir),
                "ref": head,
                "subdir": "sample",
            },
            "language": "python",
            "expected_cwes": ["CWE-862"],
            "expected_rule_ids": ["PY-020"],
        }]
    }, indent=2), encoding="utf-8")

    manifest = load_manifest(manifest_path)

    assert len(manifest.entries) == 1
    entry = manifest.entries[0]
    assert entry.source.kind == "git"
    assert entry.source.repo == str(repo_dir)
    assert entry.source.ref == head
    assert entry.source.subdir == "sample"


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for git-backed corpus tests")
def test_external_corpus_git_source_uses_cache_and_supports_offline(tmp_path):
    repo_dir = tmp_path / "fixture-repo"
    head = _init_git_fixture_repo(repo_dir)
    cache_dir = tmp_path / "cache"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "entries": [{
            "case_id": "git-python-admin-vuln",
            "source": {
                "kind": "git",
                "repo": str(repo_dir),
                "ref": head,
                "subdir": "sample",
            },
            "language": "python",
            "expected_cwes": ["CWE-862"],
            "expected_rule_ids": ["PY-020"],
        }]
    }, indent=2), encoding="utf-8")

    first_report = run_external_corpus(manifest_path, cache_dir=cache_dir, quiet=True)

    assert first_report["summary"]["score_pct"] == 100.0
    first_case = first_report["cases"][0]
    assert first_case["source"]["kind"] == "git"
    assert first_case["source"]["cache_hit"] is False
    assert first_case["source"]["resolved_ref"] == head

    second_report = run_external_corpus(manifest_path, cache_dir=cache_dir, offline=True, quiet=True)

    assert second_report["summary"]["score_pct"] == 100.0
    second_case = second_report["cases"][0]
    assert second_case["source"]["cache_hit"] is True
    assert second_case["source"]["resolved_ref"] == head


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for git-backed corpus tests")
def test_external_corpus_git_source_refresh_handles_readonly_cache(tmp_path):
    repo_dir = tmp_path / "fixture-repo"
    head = _init_git_fixture_repo(repo_dir)
    cache_dir = tmp_path / "cache"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "entries": [{
            "case_id": "git-python-admin-vuln",
            "source": {
                "kind": "git",
                "repo": str(repo_dir),
                "ref": head,
                "subdir": "sample",
            },
            "language": "python",
            "expected_cwes": ["CWE-862"],
            "expected_rule_ids": ["PY-020"],
        }]
    }, indent=2), encoding="utf-8")

    first_report = run_external_corpus(manifest_path, cache_dir=cache_dir, quiet=True)
    cache_path = Path(first_report["cases"][0]["source"]["cache_path"])
    readonly_file = cache_path / "readonly-marker.txt"
    readonly_file.write_text("marker\n", encoding="utf-8")
    readonly_file.chmod(stat.S_IREAD)

    refreshed_report = run_external_corpus(manifest_path, cache_dir=cache_dir, refresh=True, quiet=True)

    assert refreshed_report["summary"]["score_pct"] == 100.0
    refreshed_case = refreshed_report["cases"][0]
    assert refreshed_case["source"]["cache_hit"] is False
    assert refreshed_case["source"]["resolved_ref"] == head


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for git-backed corpus tests")
def test_external_corpus_offline_git_source_requires_existing_cache(tmp_path):
    repo_dir = tmp_path / "fixture-repo"
    head = _init_git_fixture_repo(repo_dir)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "entries": [{
            "case_id": "git-python-admin-vuln",
            "source": {
                "kind": "git",
                "repo": str(repo_dir),
                "ref": head,
                "subdir": "sample",
            },
            "language": "python",
            "expected_cwes": ["CWE-862"],
            "expected_rule_ids": ["PY-020"],
        }]
    }, indent=2), encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        run_external_corpus(manifest_path, cache_dir=tmp_path / "missing-cache", offline=True, quiet=True)
