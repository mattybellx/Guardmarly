from __future__ import annotations

from ansede_static._types import Severity
from ansede_static.js_ast_analyzer import analyze_js_ast
from ansede_static.python_analyzer import analyze_python


def test_js_vendor_minified_open_redirect_is_downgraded(tmp_path):
    bundle_file = tmp_path / "vendor" / "select2.full.min.js"
    bundle_file.parent.mkdir(parents=True)
    code = "function go(req,res){res.redirect(req.query.next);}\n"
    bundle_file.write_text(code, encoding="utf-8")

    result = analyze_js_ast(code, filename=str(bundle_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-039")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.15
    assert "vendor/minified asset heuristic downgraded" in finding.description


def test_js_framework_internal_dynamic_require_is_downgraded(tmp_path):
    framework_file = tmp_path / "expressjs__express" / "lib" / "view.js"
    framework_file.parent.mkdir(parents=True)
    code = "function load(name){ return require(name); }\n"
    framework_file.write_text(code, encoding="utf-8")

    result = analyze_js_ast(code, filename=str(framework_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-023")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_silent_except_is_downgraded():
    code = """
def load_config():
    try:
        return read_config()
    except Exception:
        pass
"""
    result = analyze_python(code, filename="C:/tmp/site-packages/flask/config.py")
    finding = next(f for f in result.findings if f.cwe == "CWE-617")

    assert finding.rule_id == "PY-001"
    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_gis_path_traversal_is_not_downgraded():
    code = """
import os

def clone(filename):
    return os.path.join('/vsimem', filename)
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/contrib/gis/gdal/raster/source.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-023")

    assert finding.severity == Severity.HIGH
    assert finding.confidence > 0.25
    assert "framework-internal implementation heuristic downgraded" not in finding.description


def test_python_framework_internal_autoreload_command_exec_is_downgraded():
    code = """
import sys
import subprocess

def restart_with_reloader():
    args = sys.argv
    return subprocess.run(args)
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/utils/autoreload.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-005")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_pickle_cache_backend_is_downgraded():
    code = """
import pickle

def load_cache(key):
    with open(key, 'rb') as f:
        return pickle.loads(f.read())
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/core/cache/backends/db.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-012")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_test_hardcoded_password_is_downgraded():
    code = 'TEST_PASSWORD = "password"\n'
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/db/backends/oracle/creation.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-010")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_dangerous_defaults_is_downgraded():
    code = "secure = False\nhttponly = False\n"
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/http/response.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-011")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_legacy_hash_is_downgraded():
    code = """
import hashlib

def check_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/contrib/auth/hashers.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-013")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_flask_cli_eval_is_downgraded():
    code = """
import os

def shell_command():
    startup = os.environ.get('PYTHONSTARTUP')
    eval(compile(open(startup).read(), startup, 'exec'))
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/flask/cli.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-006" and "eval" in f.title.lower())

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_db_clone_subprocess_is_downgraded():
    code = """
import subprocess
import os

def _clone_db():
    cmd = os.environ.get('DB_CLONE_CMD', 'mysqldump')
    subprocess.run(cmd, shell=True)
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/db/backends/mysql/creation.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-005")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_csrf_session_is_downgraded():
    code = """
from flask import request

def process_request():
    session['csrf_token'] = request.headers.get('X-CSRFToken')
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/middleware/csrf.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-016")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


def test_python_framework_internal_generic_dispatch_is_downgraded():
    code = """
def dispatch(request):
    method = request.method.lower()
    handler = getattr(self, method)
    return handler(request)
"""
    result = analyze_python(
        code,
        filename="C:/tmp/site-packages/django/views/generic/base.py",
    )
    finding = next(f for f in result.findings if f.rule_id == "PY-036")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description
