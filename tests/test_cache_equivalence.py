"""T4: a warm cache must not change the findings.

If a cached run and a cold run disagree, every reproducibility claim is
conditional on cache state -- the same tree scanned twice would report different
results, which is exactly the class of defect a "reproducible metrics" harness is
supposed to rule out.

The two runs share one working directory and one HOME, so the second run sees
whatever cache state the first produced. Findings are compared as a set of
(file, line, rule id, CWE, severity) tuples, so ordering and clustering do not
cause false failures.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

VULNERABLE = '''
import os
import subprocess


def handler(request):
    cmd = request.args.get("cmd")
    os.system(cmd)
    subprocess.run(cmd, shell=True)
'''

BENIGN = '''
import hashlib


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
'''

CLI_TIMEOUT = 300


def _scan(tmp: pathlib.Path) -> tuple[list[tuple], bool]:
    """Run one scan and return its findings plus whether a cache file appeared."""
    out = tmp / "report.json"
    env = dict(
        os.environ,
        HOME=str(tmp),
        USERPROFILE=str(tmp),
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "guardmarly.cli", str(tmp), "--format", "json",
         "--output", str(out), "--fail-on", "never", "--no-colour"],
        cwd=str(tmp), capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env, timeout=CLI_TIMEOUT, stdin=subprocess.DEVNULL,
    )
    assert out.exists(), (
        f"no JSON report written (exit {proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    data = json.loads(out.read_text(encoding="utf-8"))

    findings: list[tuple] = []
    for result in data.get("results", []):
        for finding in result.get("findings", []):
            findings.append((
                str(finding.get("file") or result.get("file") or ""),
                finding.get("line"),
                finding.get("rule_id"),
                finding.get("cwe"),
                finding.get("severity"),
            ))
    findings.sort(key=lambda row: tuple(str(part) for part in row))

    cache_present = any(tmp.rglob("*.db")) or (tmp / ".guardmarly").exists()
    return findings, cache_present


@pytest.fixture(scope="module")
def two_runs() -> tuple[list[tuple], list[tuple], bool]:
    with tempfile.TemporaryDirectory(prefix="guardmarly_cache_") as d:
        tmp = pathlib.Path(d)
        (tmp / "app.py").write_text(VULNERABLE, encoding="utf-8")
        (tmp / "clean.py").write_text(BENIGN, encoding="utf-8")
        cold, _ = _scan(tmp)
        warm, cache_present = _scan(tmp)
        return cold, warm, cache_present


def test_scan_produced_findings(two_runs: tuple) -> None:
    cold = two_runs[0]
    assert cold, "expected the shell-injection sinks to produce findings"


def test_warm_cache_matches_cold_scan(two_runs: tuple) -> None:
    cold, warm, _ = two_runs
    assert cold == warm, (
        "a warm-cache scan disagreed with a cold scan -- findings are not "
        "reproducible across cache state\n"
        f"only in cold: {sorted(set(cold) - set(warm))}\n"
        f"only in warm: {sorted(set(warm) - set(cold))}"
    )
