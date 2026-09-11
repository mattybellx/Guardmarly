"""Console output must never abort a scan.

Windows consoles default to a legacy code page (cp1252/cp437) that cannot
encode the emoji used in progress, triage and licence messages.  Rich's legacy
Windows renderer writes through ``file.write`` using the stream's own codec, so
an unencodable character raised ``UnicodeEncodeError`` mid-scan and killed the
process *before any report was written* -- a scanner that silently produces no
output on the platform most callers use.

``guardmarly._stdio.never_fail_stream`` is the single choke point that makes
this impossible: every ``rich`` console in the package wraps its stream with it.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap

import pytest

from guardmarly._stdio import _NeverFailStream, harden_stdio_encoding, never_fail_stream

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

EMOJI_LINES = [
    "🤖 Triage Engine rejected False Positive: x\n   ➔ Reason: y\n",
    "[dim]✅ 3 auto-fixable issue(s)[/dim]\n",
    "🔍 Scanning...\n",
    "⚠️ warning\n",
]


def test_never_fail_stream_substitutes_unencodable_characters():
    raw = io.BytesIO()
    strict = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="")
    proxy = never_fail_stream(strict)

    # Would raise UnicodeEncodeError without the proxy.
    proxy.write("🤖 triage engine\n")
    proxy.flush()

    written = raw.getvalue().decode("cp1252")
    assert "triage engine" in written
    assert "🤖" not in written


@pytest.mark.parametrize("line", EMOJI_LINES)
def test_every_emoji_message_survives_a_strict_cp1252_stream(line):
    raw = io.BytesIO()
    strict = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", newline="")
    never_fail_stream(strict).write(line + "\n")


def test_never_fail_stream_is_idempotent():
    raw = io.BytesIO()
    strict = io.TextIOWrapper(raw, encoding="cp1252", errors="replace", newline="")
    once = never_fail_stream(strict)
    assert never_fail_stream(once) is once
    never_fail_stream(once).write("plain\n")


def test_package_consoles_are_all_wrapped():
    """Every rich console in the package must use the proxy."""
    import guardmarly.cli as cli
    import guardmarly.reporters as reporters
    from guardmarly.engine import triage

    for name, module in (("cli", cli), ("reporters", reporters), ("triage", triage)):
        con = getattr(module, "console", None)
        if con is None:
            pytest.skip(f"{name} has no rich console installed")
        assert isinstance(con.file, _NeverFailStream), (
            f"{name}.console writes to {type(con.file).__name__}; "
            "an unencodable character would abort the scan"
        )


def test_second_console_on_stderr_is_not_bypassed():
    """The crash happened on the stderr console, not stdout."""
    from guardmarly.engine import triage

    if triage.console is None:
        pytest.skip("rich not installed")
    assert isinstance(triage.console.file, _NeverFailStream)


def _vulnerable_fixture() -> str:
    return textwrap.dedent(
        """
        from flask import request
        import os

        def run():
            os.system("echo " + request.args.get("cmd"))
            password = "hunter2-not-a-placeholder"
        """
    )


def test_cli_writes_a_report_under_a_narrow_console_encoding(tmp_path):
    """End-to-end: a cp1252 console must still produce a report."""
    target = tmp_path / "app.py"
    target.write_text(_vulnerable_fixture(), encoding="utf-8")
    out = tmp_path / "report.json"

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "cp1252"
    env["PYTHONPATH"] = os.path.join(REPO, "src")
    proc = subprocess.run(
        [sys.executable, "-m", "guardmarly.cli", str(target), "--format", "json",
         "--output", str(out), "--fail-on", "never", "--no-colour"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        cwd=str(tmp_path), env=env, stdin=subprocess.DEVNULL, timeout=300, check=False,
    )

    assert "UnicodeEncodeError" not in (proc.stderr or ""), proc.stderr[-800:]
    assert out.exists(), f"no report written; stderr={proc.stderr[-800:]}"
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["total_findings"] > 0


def test_harden_stdio_encoding_is_callable_and_idempotent():
    harden_stdio_encoding()
    harden_stdio_encoding()
