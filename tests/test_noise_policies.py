from __future__ import annotations

from guardmarly._types import Severity
from guardmarly.js_ast_analyzer import analyze_js_ast
from guardmarly.python_analyzer import analyze_python
from guardmarly.registry.sharded_loader import load_rules_for_code


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


def test_js_framework_internal_dynamic_require_is_not_downgraded(tmp_path):
    framework_file = tmp_path / "expressjs__express" / "lib" / "view.js"
    framework_file.parent.mkdir(parents=True)
    code = "function load(name){ return require(name); }\n"
    framework_file.write_text(code, encoding="utf-8")

    result = analyze_js_ast(code, filename=str(framework_file))
    finding = next(f for f in result.findings if f.rule_id == "JS-023")

    # Dynamic require() with variable args is a real pattern even inside
    # framework repos — vendor AMD loaders (select2 etc.) live under
    # framework source trees and must remain at full severity.
    assert finding.severity == Severity.HIGH
    assert finding.confidence > 0.25


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


def test_python_framework_internal_gis_path_traversal_is_downgraded():
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

    # GIS GDAL raster helpers operate on a non-HTTP virtual filesystem (GDAL /vsimem/);
    # the path argument is not user-HTTP-controlled, so this is framework noise.
    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "framework-internal implementation heuristic downgraded" in finding.description


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


def test_python_framework_internal_pickle_cache_backend_is_not_downgraded():
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

    # Django cache backends are genuinely unsafe when storage is attacker-controlled;
    # the exemption path keeps findings at full severity for curated analysis.
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence > 0.25
    assert "framework-internal implementation heuristic downgraded" not in finding.description


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
    finding = next(f for f in result.findings if f.rule_id == "PY-006")

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


def test_python_guardmarly_internal_silent_except_is_downgraded():
    code = """
def _parse_exports():
    try:
        return parse_data()
    except Exception:
        pass
"""
    result = analyze_python(code, filename="C:/tmp/project/src/guardmarly/js_engine/project.py")
    finding = next(f for f in result.findings if f.rule_id == "PY-001")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "tool-internal implementation heuristic downgraded" in finding.description


def test_python_guardmarly_internal_complexity_is_downgraded():
    branches = "\n".join(f"    if x == {idx}:\n        return {idx}" for idx in range(30))
    code = f"def _main_impl(x):\n{branches}\n    return -1\n"

    result = analyze_python(code, filename="C:/tmp/project/src/guardmarly/cli.py")
    finding = next(f for f in result.findings if f.rule_id == "PY-044")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "tool-internal implementation heuristic downgraded" in finding.description


def test_python_guardmarly_internal_cli_path_open_is_downgraded():
    code = """
from pathlib import Path

def _apply_auto_fixes(output_file):
    with open(Path(output_file), 'r', encoding='utf-8') as handle:
        return handle.read()
"""
    result = analyze_python(code, filename="C:/tmp/project/src/guardmarly/cli.py")
    finding = next(f for f in result.findings if f.rule_id == "PY-045")

    assert finding.severity == Severity.LOW
    assert finding.confidence <= 0.25
    assert "tool-internal implementation heuristic downgraded" in finding.description


def test_python_dangerous_default_ignores_inline_comments():
    code = """
def docs_only():
    value = 1  # secure=False in docs, not executable config
    return value
"""
    result = analyze_python(code, filename="app.py")

    assert all(f.rule_id != "PY-011" for f in result.findings)


def test_python_tls_disable_ignores_comments_and_example_strings():
    code = """
def docs_only():
    # requests.get(url, verify=False)
    example = "requests.get(url, verify=False)"
    return example
"""
    result = analyze_python(code, filename="app.py")

    assert all(f.rule_id != "PY-040" for f in result.findings)


def test_lazy_sharded_loader_uses_stdlib_parser_for_yaml_pack():
    code = "from fastapi import FastAPI\napp = FastAPI()\n"

    rules = load_rules_for_code(code)

    assert rules
    assert any(
        isinstance(rule, dict)
        and rule.get("id", "")
        and str(rule.get("cwe", "")).startswith("CWE-")
        for rule in rules
    )


def test_python_auth_guard_suppresses_missing_auth_route_finding():
    code = """
from flask import Flask, request, abort
app = Flask(__name__)

@app.get('/admin/users')
def admin_users():
    if not request.user.is_authenticated:
        abort(403)
    return list_users()
"""
    result = analyze_python(code, filename="app.py")

    assert not any(f.rule_id == "PY-020" for f in result.findings)


def test_python_explicit_permission_guard_downgrades_access_control_finding():
    code = """
from flask import Flask
app = Flask(__name__)

@app.get('/admin/users')
@login_required
def admin_users():
    if permission_check():
        return list_users()
    return deny()
"""
    result = analyze_python(code, filename="app.py")

    finding = next(f for f in result.findings if f.rule_id == "PY-027")
    assert finding.confidence <= 0.15
    assert finding.severity != Severity.CRITICAL
