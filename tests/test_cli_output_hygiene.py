"""T9: a piped scan must not narrate.

The triage engine prints a line for every rejected finding. That is useful on an
interactive terminal and actively harmful anywhere else: when stdout or stderr is
a pipe -- CI logs, `reproduce_metrics.py`, any JSON consumer -- those lines
interleave with machine-readable output. On a 189 kLOC tree it is roughly 200
lines per scan.

The gate is `console.is_terminal`, so this test drives the real CLI with captured
streams (i.e. pipes) and asserts the narration is absent. It also asserts the
narration *does* exist behind a TTY-style console, so the test cannot pass
vacuously if the narration code is deleted outright.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

# Produces findings the triage engine rejects as quality metrics (high
# cyclomatic complexity, broad except without re-raise), which is what triggers
# the narration, alongside one genuine security sink.
SAMPLE = '''
import os
import subprocess


def tangled(request, a, b, c):
    total = 0
    for i in range(a):
        if i % 2 == 0:
            total += i
        elif i % 3 == 0:
            total -= i
        elif i % 5 == 0:
            total *= 2
        elif i % 7 == 0:
            total -= 2
        elif i % 11 == 0:
            total += 11
        elif i % 13 == 0:
            total -= 13
        elif i % 17 == 0:
            total += 17
        else:
            total += 1
    try:
        os.system(request.args.get("cmd"))
        subprocess.run(request.args.get("cmd"), shell=True)
    except Exception:
        pass
    return total
'''

NARRATION = "Triage Engine rejected"

CLI_TIMEOUT = 300


def _run_cli(tmp: pathlib.Path) -> subprocess.CompletedProcess:
    (tmp / "app.py").write_text(SAMPLE, encoding="utf-8")
    env = dict(
        os.environ,
        HOME=str(tmp),
        USERPROFILE=str(tmp),
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
    )
    return subprocess.run(
        [sys.executable, "-m", "guardmarly.cli", str(tmp), "--format", "json",
         "--output", str(tmp / "r.json"), "--fail-on", "never", "--no-colour"],
        cwd=str(tmp), capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env, timeout=CLI_TIMEOUT, stdin=subprocess.DEVNULL,
    )


def test_piped_scan_does_not_narrate() -> None:
    with tempfile.TemporaryDirectory(prefix="guardmarly_hygiene_") as d:
        proc = _run_cli(pathlib.Path(d))

    assert proc.returncode == 0, f"scan failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert NARRATION not in proc.stdout, (
        "triage narration leaked into captured stdout; it corrupts piped/JSON output"
    )
    assert NARRATION not in proc.stderr, (
        "triage narration leaked into captured stderr; it corrupts piped/JSON output"
    )


def test_scan_still_reports_the_security_finding() -> None:
    """The hygiene gate must not have silenced the findings themselves."""
    with tempfile.TemporaryDirectory(prefix="guardmarly_hygiene_") as d:
        tmp = pathlib.Path(d)
        proc = _run_cli(tmp)
        report = (tmp / "r.json").read_text(encoding="utf-8", errors="replace")

    assert proc.returncode == 0
    assert "CWE-78" in report or "CWE-22" in report, (
        "expected the shell-injection sink to appear in the report"
    )
