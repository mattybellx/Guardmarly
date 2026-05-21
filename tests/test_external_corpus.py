from __future__ import annotations

import json
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

import benchmarks.external_corpus as external_corpus
from benchmarks.external_corpus import OfflineCacheMissError, load_manifest, run_external_corpus


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
        "nodegoat-login-bruteforce",
        "nodegoat-signup-bruteforce",
        "nodegoat-open-redirect-learn-link",
        "nodegoat-redos-validation",
        "nodegoat-eval-code-injection",
        "nodegoat-hardcoded-zap-api-key",
        "nodegoat-hardcoded-cookie-and-crypto-secrets",
        "nodegoat-index-missing-csrf-protection",
        "django-i18n-open-redirect",
        "webgoat-full-repo",
        "nodegoat-full-repo",
        "flask-login-full-repo",
        "dvna-full-repo",
        "gin-full-repo",
        "aspnetcore-security-subtree",
        "django-full",
        "express-full",
        "fastapi-full",
        "flask-full",
        "laravel-full",
        "pytorch-full",
        "rails-full",
        "spring-boot-full",
        "typescript-compiler",
        "vue-core",
        "webgoat-net",
    }
    assert all(entry.source.kind == "git" for entry in manifest.entries)
    assert {entry.source.repo for entry in manifest.entries} == {
        "https://github.com/OWASP/NodeGoat.git",
        "https://github.com/django/django.git",
        "https://github.com/WebGoat/WebGoat.git",
        "https://github.com/maxcountryman/flask-login.git",
        "https://github.com/appsecco/dvna.git",
        "https://github.com/gin-gonic/gin.git",
        "https://github.com/dotnet/aspnetcore.git",
    }
    assert all(len(entry.source.ref) == 40 for entry in manifest.entries)
    assert all(entry.js_backend == "structural" for entry in manifest.entries if entry.language == "javascript")
    assert any(entry.language == "python" and entry.expected_rule_ids == ("PY-046",) for entry in manifest.entries)
    assert any(entry.case_id == "webgoat-full-repo" and entry.languages == ("java",) for entry in manifest.entries)
    assert any(entry.case_id == "dvna-full-repo" and entry.exclude_paths == ("node_modules/", "test/") for entry in manifest.entries)
    assert any(entry.case_id == "flask-login-full-repo" and entry.expected_findings.min == 3 and entry.expected_findings.max == 7 for entry in manifest.entries)


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

    with pytest.raises(OfflineCacheMissError):
        run_external_corpus(manifest_path, cache_dir=tmp_path / "missing-cache", offline=True, quiet=True)


def test_load_manifest_supports_repo_ranges_and_excludes(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "entries": [{
            "case_id": "repo-java-scan",
            "name": "Example Java Repo",
            "source": {
                "kind": "git",
                "repo": "https://github.com/example/repo.git",
                "ref": "0123456789abcdef0123456789abcdef01234567",
            },
            "languages": ["java"],
            "exclude_paths": ["src/test/", "*.md"],
            "expected_findings": {"min": 5, "max": 40},
            "notes": "Repo-level entry",
        }]
    }, indent=2), encoding="utf-8")

    manifest = load_manifest(manifest_path)
    entry = manifest.entries[0]

    assert entry.name == "Example Java Repo"
    assert entry.languages == ("java",)
    assert entry.exclude_paths == ("src/test/", "*.md")
    assert entry.expected_findings.min == 5
    assert entry.expected_findings.max == 40


def test_external_corpus_reports_noise_gate(tmp_path):
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
            "expected_findings": {"min": 1, "max": 0},
        }]
    }, indent=2), encoding="utf-8")

    report = run_external_corpus(manifest_path, cache_dir=tmp_path / "cache", noise_gate=0.5, quiet=True)

    assert report["summary"]["score_pct"] < 100.0
    assert report["summary"]["noise_quotient"] > 0.5
    assert report["noise_gate"]["passed"] is False
    assert report["noise_gate"]["failures"][0]["case_id"] == "git-python-admin-vuln"


def test_external_corpus_run_git_enables_core_longpaths_on_windows(monkeypatch):
    captured: dict[str, object] = {}

    class _Completed:
        stdout = "ok\n"

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return _Completed()

    monkeypatch.setattr(external_corpus, "_is_windows", lambda: True)
    monkeypatch.setattr(external_corpus.subprocess, "run", _fake_run)

    result = external_corpus._run_git(["rev-parse", "HEAD"], cwd=Path("."))

    assert result == "ok"
    assert captured["cmd"] == ["git", "-c", "core.longpaths=true", "rev-parse", "HEAD"]
