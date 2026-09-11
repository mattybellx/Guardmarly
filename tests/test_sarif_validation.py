"""T3: emitted SARIF must satisfy SARIF 2.1.0's structural requirements.

A SARIF file that fails these requirements is *silently ignored* by GitHub code
scanning and most other consumers: the scanner looks correct locally while being
invisible on the platform it is meant to feed. That makes this check binary
rather than cosmetic, which is why it is a test and not a documentation note.

The scan runs the real CLI through a subprocess, so what is validated is the
artifact a user actually gets, not an in-process helper.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

import pytest

# Deliberately obvious, high-severity, request-derived sinks so the report is
# guaranteed to contain at least one result. The temp directory prefix avoids
# test-directory tokens, which the triage engine legitimately uses to demote
# fixture code.
VULNERABLE = '''
import os
import subprocess


def handler(request):
    cmd = request.args.get("cmd")
    os.system(cmd)
    subprocess.run(cmd, shell=True)
'''

CLI_TIMEOUT = 300


def _scan_sarif(tmp: pathlib.Path) -> dict:
    (tmp / "app.py").write_text(VULNERABLE, encoding="utf-8")
    out = tmp / "report.sarif"
    env = dict(
        os.environ,
        HOME=str(tmp),
        USERPROFILE=str(tmp),
        PYTHONIOENCODING="utf-8",
        PYTHONUTF8="1",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "guardmarly.cli", str(tmp), "--format", "sarif",
         "--output", str(out), "--fail-on", "never", "--no-colour"],
        cwd=str(tmp), capture_output=True, text=True, encoding="utf-8",
        errors="replace", env=env, timeout=CLI_TIMEOUT, stdin=subprocess.DEVNULL,
    )
    assert out.exists(), (
        f"no SARIF file written (exit {proc.returncode})\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    return json.loads(out.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sarif() -> dict:
    with tempfile.TemporaryDirectory(prefix="guardmarly_sarif_") as d:
        return _scan_sarif(pathlib.Path(d))


def test_version_is_2_1_0(sarif: dict) -> None:
    assert sarif.get("version") == "2.1.0", "SARIF consumers key off this exact string"


def test_schema_is_declared(sarif: dict) -> None:
    schema = sarif.get("$schema", "")
    assert "sarif" in schema.lower() and "2.1.0" in schema, f"unexpected $schema: {schema!r}"


def test_single_run_declares_the_driver(sarif: dict) -> None:
    runs = sarif.get("runs")
    assert isinstance(runs, list) and runs, "runs must be a non-empty array"
    driver = runs[0].get("tool", {}).get("driver", {})
    assert driver.get("name"), "runs[0].tool.driver.name is required"


def test_at_least_one_result(sarif: dict) -> None:
    # Guards against the test passing vacuously on an empty report.
    results = sarif["runs"][0].get("results")
    assert isinstance(results, list) and results, (
        "expected the two shell-injection sinks to produce at least one result"
    )


def test_results_have_required_fields(sarif: dict) -> None:
    for i, result in enumerate(sarif["runs"][0]["results"]):
        assert result.get("ruleId"), f"results[{i}].ruleId is required"
        message = result.get("message")
        assert isinstance(message, dict) and message.get("text"), (
            f"results[{i}].message.text is required"
        )


def test_locations_are_well_formed(sarif: dict) -> None:
    for i, result in enumerate(sarif["runs"][0]["results"]):
        locations = result.get("locations")
        assert isinstance(locations, list) and locations, (
            f"results[{i}].locations is required and must be non-empty"
        )
        for j, location in enumerate(locations):
            physical = location.get("physicalLocation")
            assert isinstance(physical, dict), (
                f"results[{i}].locations[{j}].physicalLocation is required"
            )
            artifact = physical.get("artifactLocation", {})
            assert artifact.get("uri"), (
                f"results[{i}].locations[{j}]....artifactLocation.uri is required"
            )
            region = physical.get("region", {})
            start = region.get("startLine")
            assert isinstance(start, int) and start >= 1, (
                f"results[{i}].locations[{j}]....region.startLine must be an integer >= 1, got {start!r}"
            )


def test_declared_rules_are_present(sarif: dict) -> None:
    """Every ruleId used by a result should be declared in the driver's rules."""
    run = sarif["runs"][0]
    declared = {
        rule.get("id")
        for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        if isinstance(rule, dict)
    }
    if not declared:
        pytest.skip("driver declares no rules array; ruleId-linkage is not enforced")
    used = {r.get("ruleId") for r in run.get("results", [])}
    undeclared = sorted(r for r in used - declared if r)
    assert not undeclared, f"results reference rules not declared in driver.rules: {undeclared}"
