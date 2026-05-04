from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from benchmarks.real_world_compare import run_real_world_compare



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



def _init_js_fixture_repo(repo_dir: Path) -> str:
    repo_dir.mkdir(parents=True, exist_ok=True)
    _run_git(["init"], cwd=repo_dir)
    _run_git(["config", "user.email", "ansede@example.test"], cwd=repo_dir)
    _run_git(["config", "user.name", "Ansede Test"], cwd=repo_dir)

    sample_dir = repo_dir / "sample"
    sample_dir.mkdir()
    (sample_dir / "app.js").write_text(
        """
app.post('/login', (req, res) => {
    eval(req.body.code);
    return res.redirect(req.query.next);
});
""".strip()
        + "\n",
        encoding="utf-8",
    )

    _run_git(["add", "."], cwd=repo_dir)
    _run_git(["commit", "-m", "fixture"], cwd=repo_dir)
    return _run_git(["rev-parse", "HEAD"], cwd=repo_dir)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required for comparison benchmark tests")
def test_real_world_compare_runs_against_local_git_manifest(tmp_path):
    repo_dir = tmp_path / "fixture-repo"
    head = _init_js_fixture_repo(repo_dir)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "case_id": "fixture-js-dangerous-route",
                        "source": {
                            "kind": "git",
                            "repo": str(repo_dir),
                            "ref": head,
                            "subdir": "sample",
                        },
                        "language": "javascript",
                        "targets": ["app.js"],
                        "expected_cwes": ["CWE-95", "CWE-601", "CWE-307"],
                        "js_backend": "structural",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    report = run_real_world_compare(manifest_path, cache_dir=tmp_path / "cache", quiet=True)

    assert report["engines"]["ansede"]["summary"]["total_cases"] == 1
    assert report["engines"]["semgrep_style"]["summary"]["total_cases"] == 1
    assert report["engines"]["ansede"]["summary"]["recall"] >= 66.0
    assert "CWE-307" in report["engines"]["ansede"]["cases"][0]["predicted_cwes"]
    assert report["engines"]["semgrep_style"]["summary"]["recall"] >= 33.0
