"""Regression tests for Python fallback-rule precision.

These lock in the fixes for the five root causes of the 81%-of-all-HIGH+ noise
measured on the Python standard library: sinks matched inside comments, a
five-line "dynamic data" window, non-XSS sinks in the XSS rule, missing word
boundaries, and bare `read`/`write` being treated as path sinks.
"""
from __future__ import annotations

import textwrap

import pytest

from guardmarly.python_analyzer import (
    _mask_py_comments,
    _mask_py_literals,
    _py_arg_is_dynamic,
    _py_first_arg,
    _python_fallback_detect,
    analyze_python,
)

# ── masking helpers ──────────────────────────────────────────────────────


def test_mask_py_comments_blanks_text_and_preserves_offsets():
    code = 'x = 1  # read() would block\ny = 2\n'
    masked = _mask_py_comments(code)
    assert "read()" not in masked
    assert len(masked) == len(code)
    assert masked.count("\n") == code.count("\n")
    assert masked.splitlines()[1] == "y = 2"


def test_mask_py_comments_ignores_hash_inside_string():
    code = 'url = "http://x/#frag"  # note\n'
    masked = _mask_py_comments(code)
    assert '"http://x/#frag"' in masked
    assert "note" not in masked


def test_mask_py_literals_blanks_string_bodies_only():
    code = 'mode = "rb+"  # comment\nname = "x"\n'
    masked = _mask_py_literals(code)
    assert "rb+" not in masked
    assert "comment" not in masked
    assert "mode" in masked and "name" in masked
    assert len(masked) == len(code)


def test_mask_py_literals_leaves_fstring_prefix_readable():
    masked = _mask_py_literals('q = f"SELECT {name}"\n')
    assert 'f"' in masked
    assert "SELECT" not in masked


# ── argument helpers ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("path, 'r+' + mode", "path"),
        ("a + b, c", "a + b"),
        ("os.path.join(base, name)", "os.path.join(base, name)"),
        ("f(a, b), c", "f(a, b)"),
    ],
)
def test_py_first_arg_splits_on_top_level_commas(text, expected):
    assert _py_first_arg(text) == expected


@pytest.mark.parametrize(
    ("arg", "dynamic"),
    [
        ("'rb+'", False),          # a file mode is not concatenation
        ("path", False),
        ("os.path.join(base, n)", False),
        ("'/srv/files/' + name", True),
        ('f"/srv/{name}"', True),
        ('"{}".format(name)', True),
    ],
)
def test_py_arg_is_dynamic(arg, dynamic):
    assert _py_arg_is_dynamic(arg) is dynamic


# ── the fallback engine must stay quiet on non-vulnerable real code ──────


QUIET_CASES = {
    "terminal escape write": 'os.write(self.output_fd, b"\\033[?7h")\n',
    "comment mentioning read()": "# or until an EOF occurs or until read() would block.\n",
    "safe path join, no taint": (
        'def load(base, name):\n    with open(os.path.join(base, name), "rb") as f:\n'
        "        return f.read()\n"
    ),
    "byte buffer write": "def emit(out, data):\n    out.write(FRAME + pack('<Q', data))\n",
    "mode string concatenation": (
        "def reopen(path, mode):\n    return open(path, 'r+' + mode)\n"
    ),
    "date formatting": (
        'def iso(self):\n    return "%04d-%02d-%02d" % (self.year, self.month, self.day)\n'
    ),
    "logging with args": (
        "def log(args):\n    args.log.write('%s' % sum(args.integers))\n"
    ),
    "incomplete read exception": (
        "def fixup(x):\n    raise IncompleteRead(b''.join(x))\n"
    ),
}


@pytest.mark.parametrize("name", sorted(QUIET_CASES))
def test_fallback_stays_quiet_on_safe_code(name):
    """Each of these produced a HIGH finding before the precision fixes."""
    findings = _python_fallback_detect(QUIET_CASES[name], f"{name}.py")
    assert findings == [], (
        f"{name}: unexpected {[(f.rule_id, f.cwe, f.line) for f in findings]}"
    )


# ── and must still catch the canonical vulnerabilities ───────────────────


def test_fallback_still_detects_tainted_xss():
    code = textwrap.dedent(
        """
        from flask import Flask, request, render_template_string
        app = Flask(__name__)

        @app.route("/hello")
        def hello():
            name = request.args.get("name")
            return render_template_string("<h1>Hello " + name + "</h1>")
        """
    )
    cwes = {f.cwe for f in _python_fallback_detect(code, "app.py")}
    assert "CWE-79" in cwes


def test_fallback_still_detects_tainted_path_traversal():
    code = textwrap.dedent(
        """
        import os
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/download")
        def download():
            name = request.args.get("file")
            with open(os.path.join("/srv/files", name)) as fh:
                return fh.read()
        """
    )
    cwes = {f.cwe for f in _python_fallback_detect(code, "app.py")}
    assert "CWE-22" in cwes


def test_xss_rule_does_not_treat_redirect_as_xss():
    """redirect() is CWE-601; the XSS rule must not claim it."""
    code = textwrap.dedent(
        """
        from flask import Flask, request, redirect
        app = Flask(__name__)

        @app.route("/go")
        def go():
            return redirect(request.args.get("next"))
        """
    )
    cwes = {f.cwe for f in _python_fallback_detect(code, "app.py")}
    assert "CWE-79" not in cwes


def test_open_redirect_is_reported():
    """The CWE-601 rule must accept a globally imported request proxy."""
    code = textwrap.dedent(
        """
        from flask import Flask, request, redirect
        app = Flask(__name__)

        @app.route("/go")
        def go():
            return redirect(request.args.get("next"))
        """
    )
    result = analyze_python(code, filename="app.py")
    assert any(f.cwe == "CWE-601" for f in result.findings), (
        f"expected CWE-601, got {[(f.rule_id, f.cwe) for f in result.findings]}"
    )
