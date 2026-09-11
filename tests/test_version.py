"""
tests.test_version
──────────────────
Guards against version drift between the source tree, the build metadata and
what the CLI reports.

Regression context: ``pyproject.toml`` said 6.6.0, the installed distribution
metadata said 6.4.0 (stale editable install) and ``engine_version`` carried a
dead 6.2.2 fallback, so ``guardmarly --version`` disagreed with the release
that produced it.
"""
from __future__ import annotations

import re
from pathlib import Path

import guardmarly
from guardmarly._version import __version__ as source_version
from guardmarly.engine_version import get_engine_version

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_VERSION_FILE = _REPO_ROOT / "src" / "guardmarly" / "_version.py"


def test_source_version_file_exists_and_is_semver():
    assert _VERSION_FILE.is_file(), "src/guardmarly/_version.py is the version source of truth"
    assert re.fullmatch(r"\d+\.\d+\.\d+([.\-+][0-9A-Za-z.\-]+)?", source_version), source_version


def test_engine_version_prefers_source_tree_version():
    """The reported version must not depend on stale dist-info metadata."""
    assert get_engine_version() == source_version
    assert guardmarly.__version__ == source_version


def test_pyproject_reads_version_from_single_source():
    text = _PYPROJECT.read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text, "pyproject must not hard-code a version"
    assert not re.search(r'^version\s*=\s*"', text, flags=re.MULTILINE), (
        "pyproject.toml must declare version dynamically via [tool.hatch.version]"
    )
    assert '[tool.hatch.version]' in text
    assert 'path = "src/guardmarly/_version.py"' in text
