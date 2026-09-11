"""Regression tests: context heuristics must not read host ancestor dirs.

A project that merely *lives under* a directory named like a test/example/
generated directory (``benchmarks``, ``samples``, ``build``, ``scripts``,
``perf`` ...) used to have its findings silently discarded, because those
ancestor names were matched as if they were part of the project's own layout.

Observed impact (pre-fix): the same tree scanned by absolute path reported
**0 findings** while the identical tree scanned by relative path reported 78.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from guardmarly.engine.triage import ContextAnalyzer

REPO = Path(__file__).resolve().parent.parent
VULN_PY = textwrap.dedent(
    '''
    from flask import Flask, request
    import os

    app = Flask(__name__)


    @app.route("/run")
    def run():
        cmd = request.args.get("cmd")
        os.system("echo " + cmd)
        return "ok"
    '''
)


@pytest.fixture(autouse=True)
def _reset_scan_root():
    """Never leak scan-root state between tests."""
    ContextAnalyzer.set_scan_root(None)
    yield
    ContextAnalyzer.set_scan_root(None)


def _tree(*parts: str) -> tuple[Path, Path]:
    """Create an isolated temp tree and return ``(base, deepest_dir)``.

    Callers must clean up ``base`` only — never an ancestor of it.  Note this
    deliberately avoids pytest's ``tmp_path``, whose directory name contains
    ``test_`` and would itself be treated as a triage pattern.
    """
    base = Path(tempfile.mkdtemp(prefix="guardmarly_ctx_"))
    deepest = base.joinpath(*parts)
    deepest.mkdir(parents=True, exist_ok=True)
    return base, deepest


def test_ancestor_dir_named_benchmarks_is_not_test_context():
    """The classic case: project checked out under a 'benchmarks' ancestor."""
    base, root = _tree("benchmarks", "corpus")
    try:
        target = root / "handlers.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        is_test, reason = ContextAnalyzer.is_test_context(str(target), "")
        assert is_test is False, f"ancestor leaked into triage: {reason}"
        is_mock, reason = ContextAnalyzer.is_mock_context(str(target), "")
        assert is_mock is False, f"ancestor leaked into triage: {reason}"
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.parametrize(
    "ancestor",
    ["benchmarks", "samples", "build", "scripts", "perf", "docs", "demo", "dist"],
)
def test_no_ancestor_name_causes_a_context_classification(ancestor: str):
    """No host ancestor may ever trigger test/generated classification."""
    base, root = _tree(ancestor, "service")
    try:
        target = root / "views.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        assert ContextAnalyzer.is_test_context(str(target), "")[0] is False
        assert ContextAnalyzer.is_mock_context(str(target), "")[0] is False
        assert ContextAnalyzer.is_generated(str(target))[0] is False
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_project_own_test_directory_is_still_detected():
    """Scan-root scoping must not defeat the feature it protects."""
    base, root = _tree("service")
    try:
        tests_dir = root / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        target = tests_dir / "test_views.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        assert ContextAnalyzer.is_test_context(str(target), "")[0] is True
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_project_own_samples_directory_is_still_detected():
    base, root = _tree("service")
    try:
        samples = root / "samples"
        samples.mkdir(parents=True, exist_ok=True)
        target = samples / "demo.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        assert ContextAnalyzer.is_test_context(str(target), "")[0] is True
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.parametrize("parent", ["test_sandbox", "test_of_matth", "my_tests"])
def test_parent_directory_token_does_not_leak_into_classification(parent: str):
    """The *parent* directory must be judged from the scoped path, not the host.

    pytest's own ``tmp_path`` is named after the test, so it contains ``test_``.
    Deriving the parent-dir token from the raw host path classified every file
    in such a tree as test code, discarding its findings.
    """
    base, root = _tree(parent, "app")
    try:
        target = root / "handlers.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        assert ContextAnalyzer.is_test_context(str(target), "")[0] is False
        assert ContextAnalyzer.is_mock_context(str(target), "")[0] is False
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_scan_root_itself_may_be_named_like_a_test_directory():
    """A scan root called ``test_project`` must not make everything test code."""
    base, root = _tree("test_project")
    try:
        target = root / "handlers.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(root)

        assert ContextAnalyzer.is_test_context(str(target), "")[0] is False
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_clearing_scan_root_restores_legacy_behaviour():
    base, root = _tree("benchmarks")
    try:
        target = root / "handlers.py"
        target.write_text(VULN_PY, encoding="utf-8")
        ContextAnalyzer.set_scan_root(None)
        # With no root the raw path is used; this assertion documents the
        # fallback rather than endorsing it.
        assert ContextAnalyzer.is_test_context(str(target), "")[0] is True
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_end_to_end_absolute_and_relative_scans_agree():
    """The user-visible guarantee: invocation form must not change findings."""
    base, root = _tree("samples", "vulnapp")
    try:
        (root / "handlers.py").write_text(VULN_PY, encoding="utf-8")

        def scan(target: str) -> int:
            out = root / "report.json"
            env = dict(**__import__("os").environ)
            env["PYTHONPATH"] = str(REPO / "src")
            subprocess.run(
                [sys.executable, "-m", "guardmarly.cli", target, "--format", "json",
                 "--output", str(out), "--fail-on", "never", "--no-colour"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", cwd=str(root), env=env, stdin=subprocess.DEVNULL,
                timeout=300, check=False,
            )
            import json

            report = json.loads(out.read_text(encoding="utf-8"))
            return int(report["summary"]["total_findings"])

        absolute = scan(str(root))
        relative = scan(".")

        assert absolute > 0, "absolute-path scan reported no findings at all"
        assert absolute == relative, (
            f"scan results depend on how the path was passed: "
            f"absolute={absolute} relative={relative}"
        )
    finally:
        shutil.rmtree(base, ignore_errors=True)
