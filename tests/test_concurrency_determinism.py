"""Concurrency safety and determinism of the Python analyzer.

``analyze_python`` used to monkey-patch ``ast.walk`` globally and cache node
lists by ``id()``.  The CLI analyses Python files in a thread pool, so two
workers shared one closure over an ``id()``-keyed cache holding *different*
trees — a worker could read another worker's cached node list, and ``id()``
reuse across freed trees could return the wrong nodes outright.  `ast.walk` is
now a thread-scoped dispatcher (see ``_thread_scoped_walk``).
"""
from __future__ import annotations

import ast
import concurrent.futures as cf
import textwrap

from guardmarly.python_analyzer import (
    _ORIGINAL_AST_WALK,
    _thread_scoped_walk,
    analyze_python,
)

CODE = textwrap.dedent(
    """
    from flask import Flask, request
    import os

    app = Flask(__name__)


    @app.route("/run")
    def run():
        cmd = request.args.get("cmd")
        os.system("echo " + cmd)
        return "ok"
    """
)


def test_ast_walk_is_not_left_patched_by_analysis():
    """A completed analysis must not leave a cache behind for other callers."""
    analyze_python(CODE, filename="app.py")
    assert ast.walk is _thread_scoped_walk, "analysis replaced ast.walk"

    tree = ast.parse("x = 1")
    assert len(list(_ORIGINAL_AST_WALK(tree))) == len(list(ast.walk(tree)))


def test_concurrent_analysis_is_stable():
    """Same file analysed from many threads must give identical findings.

    This is the regression guard for the shared `ast.walk` cache: before the
    fix, concurrent workers could observe each other's node lists.
    """
    def scan(_i: int) -> tuple:
        result = analyze_python(CODE, filename="app.py")
        return tuple(sorted((f.rule_id, f.cwe, f.line) for f in result.findings))

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = {fut for fut in pool.map(scan, range(64))}
    assert len(outcomes) == 1, f"concurrent analysis was not stable: {outcomes}"


def test_concurrent_analysis_of_different_files_does_not_cross_contaminate():
    """Two workers on different sources must each get their own findings."""
    a = textwrap.dedent(
        """
        import os
        from flask import request
        def run():
            os.system("echo " + request.args.get("x"))
        """
    )
    b = textwrap.dedent(
        """
        import hashlib
        def fingerprint(data):
            return hashlib.sha256(data).hexdigest()
        """
    )

    def scan_a(_i: int) -> tuple:
        r = analyze_python(a, filename="a.py")
        return tuple(sorted((f.rule_id, f.line) for f in r.findings))

    def scan_b(_i: int) -> tuple:
        r = analyze_python(b, filename="b.py")
        return tuple(sorted((f.rule_id, f.line) for f in r.findings))

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = []
        for i in range(32):
            futs.append(pool.submit(scan_a, i))
            futs.append(pool.submit(scan_b, i))
        got_a = {f.result() for f in futs[0::2]}
        got_b = {f.result() for f in futs[1::2]}

    assert len(got_a) == 1, f"file A results varied: {got_a}"
    assert len(got_b) == 1, f"file B results varied: {got_b}"
    assert got_a != got_b, "two different files produced the same findings"
    assert any(rid.startswith("PY-0") for rid, _ in next(iter(got_a))), got_a


# ── per-file taint caches must be thread-private ──────────────────────────
#
# ``_taint_source_cache`` / ``_sink_name_cache`` are keyed on
# ``(lineno, col_offset, type_name)``, which is unique only *within one file*.
# They were module-level dicts, and the CLI analyses files in a thread pool, so
# two workers whose files had a node at the same coordinates read each other's
# entries.  Observed: a `hashlib.sha256` helper reported with the neighbouring
# file's SSRF finding, and rule ids for one weakness varying between identical
# runs (PY-005 vs PY-012, PY-008 vs PY-022, PY-004 vs PY-004F).


def test_per_file_caches_are_thread_private():
    import threading

    from guardmarly.python_analyzer import _sink_name_cache, _taint_source_cache

    key = (5, 12, "Call")
    _taint_source_cache.clear()
    _taint_source_cache[key] = "main-thread"

    seen: dict[str, object] = {}

    def worker() -> None:
        seen["visible_at_start"] = key in _taint_source_cache
        _taint_source_cache[key] = "worker"
        seen["own_value"] = _taint_source_cache[key]

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert seen["visible_at_start"] is False, "worker saw another thread's cache entry"
    assert seen["own_value"] == "worker"
    assert _taint_source_cache[key] == "main-thread", "worker overwrote main thread"

    _sink_name_cache.clear()
    _taint_source_cache.clear()


SAME_COORDS_A = textwrap.dedent(
    """
    import requests
    from flask import request
    def fetch():
        target = request.args.get("url")
        return requests.get(target)
    """
)

SAME_COORDS_B = textwrap.dedent(
    """
    import hashlib
    def fetch(data):
        return hashlib.sha256(data).hexdigest()
    """
)


def test_same_coordinates_in_two_files_do_not_contaminate():
    """A clean helper must never inherit its neighbour's SSRF finding."""
    def scan_b(_i: int) -> tuple:
        r = analyze_python(SAME_COORDS_B, filename="b.py")
        return tuple(sorted((f.rule_id, f.cwe, f.line) for f in r.findings))

    def scan_a(_i: int) -> tuple:
        r = analyze_python(SAME_COORDS_A, filename="a.py")
        return tuple(sorted((f.rule_id, f.cwe, f.line) for f in r.findings))

    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        # Interleave so the two files are analysed at the same time.
        futs = []
        for i in range(48):
            futs.append(pool.submit(scan_a, i))
            futs.append(pool.submit(scan_b, i))
        a_results = {f.result() for f in futs[0::2]}
        b_results = {f.result() for f in futs[1::2]}

    assert len(a_results) == 1, f"file A results varied: {a_results}"
    assert len(b_results) == 1, f"file B results varied: {b_results}"

    b_findings = next(iter(b_results))
    assert not any(cwe == "CWE-918" for _, cwe, _ in b_findings), (
        f"clean hashlib helper inherited an SSRF finding: {b_findings}"
    )
    a_findings = next(iter(a_results))
    assert any(cwe == "CWE-918" for _, cwe, _ in a_findings), (
        f"SSRF was not detected in file A: {a_findings}"
    )
