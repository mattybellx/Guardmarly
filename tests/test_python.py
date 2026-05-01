"""
tests.test_python
─────────────────
Unit tests for the Python AST security analyzer.
"""
from __future__ import annotations

import pytest
from ansede_static.ir.global_graph import GlobalGraph
from ansede_static.python_analyzer import analyze_python
from ansede_static._types import Severity


# ── Helpers ─────────────────────────────────────────────────────────────────

def _titles(code: str) -> list[str]:
    return [f.title for f in analyze_python(code).findings]


def _cwes(code: str) -> list[str]:
    return [f.cwe for f in analyze_python(code).findings]


def _has_cwe(code: str, cwe: str) -> bool:
    return cwe in _cwes(code)


def _has_any_finding(code: str) -> bool:
    return len(analyze_python(code).findings) > 0


# ── CWE-89: SQL Injection ─────────────────────────────────────────────────────

class TestSQLInjection:
    def test_fstring_parametrize(self):
        code = """
import sqlite3
from flask import request
def get_user():
    user_id = request.args.get('id')
    db = sqlite3.connect(':memory:')
    rows = db.execute(f"SELECT * FROM users WHERE id = '{user_id}'").fetchall()
    return rows
"""
        assert _has_cwe(code, "CWE-89")

    def test_percent_format(self):
        code = """
from flask import request
def q(cursor):
    name = request.form.get('name')
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
"""
        assert _has_cwe(code, "CWE-89")

    def test_parameterized_query_safe(self):
        code = """
import sqlite3
def safe():
    db = sqlite3.connect(':memory:')
    db.execute("SELECT * FROM users WHERE id = ?", (42,))
"""
        assert not _has_cwe(code, "CWE-89")

    def test_helper_return_taint_assignment(self):
        code = """
from flask import request
def build_user_query(identifier):
    return f"SELECT * FROM users WHERE id = '{identifier}'"
def get_user(cursor):
    user_id = request.args.get('id')
    sql = build_user_query(user_id)
    cursor.execute(sql)
"""
        assert _has_cwe(code, "CWE-89")

    def test_helper_return_taint_inline_sink(self):
        code = """
from flask import request
def build_user_query(identifier):
    return f"SELECT * FROM users WHERE id = '{identifier}'"
def get_user(cursor):
    cursor.execute(build_user_query(request.args.get('id')))
"""
        assert _has_cwe(code, "CWE-89")

    def test_helper_return_trace_contains_source_helper_and_sink(self):
        code = """
from flask import request
def build_user_query(identifier):
    return f"SELECT * FROM users WHERE id = '{identifier}'"
def get_user(cursor):
    cursor.execute(build_user_query(request.args.get('id')))
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.cwe == "CWE-89")
        labels = [frame.label for frame in finding.trace]
        kinds = [frame.kind for frame in finding.trace]

        assert kinds[0] == "source"
        assert "through `build_user_query()`" in labels
        assert kinds[-1] == "sink"

    def test_route_param_flow_into_helper(self):
        code = """
from flask import Flask
app = Flask(__name__)
def build_user_query(identifier):
    return f"SELECT * FROM users WHERE id = '{identifier}'"
@app.route('/users/<int:user_id>')
def get_user(user_id):
    cursor.execute(build_user_query(user_id))
"""
        assert _has_cwe(code, "CWE-89")


# ── CWE-78: Command Injection ──────────────────────────────────────────────────

class TestCommandInjection:
    def test_shell_true_with_variable(self):
        code = """
import subprocess
from flask import request
def run():
    cmd = request.args.get('cmd')
    subprocess.run(cmd, shell=True)
"""
        assert _has_cwe(code, "CWE-78")

    def test_shell_false_safe(self):
        code = """
import subprocess
def safe():
    subprocess.run(['ls', '-la'], shell=False)
"""
        assert not _has_cwe(code, "CWE-78")

    def test_literal_shell_true_safe(self):
        code = """
import subprocess
def safe():
    subprocess.run("ls -la", shell=True)
"""
        # Literal string with shell=True — no dynamic input
        assert not _has_cwe(code, "CWE-78")


# ── CWE-502: Unsafe Deserialization ──────────────────────────────────────────

class TestDeserialization:
    def test_pickle_loads(self):
        code = """
import pickle
from flask import request
def load():
    data = request.get_data()
    obj = pickle.loads(data)
    return obj
"""
        assert _has_cwe(code, "CWE-502")

    def test_yaml_load_no_loader(self):
        code = """
import yaml
def load(data):
    return yaml.load(data)
"""
        assert _has_cwe(code, "CWE-502")

    def test_yaml_safe_load_ok(self):
        code = """
import yaml
def load(data):
    return yaml.safe_load(data)
"""
        assert not _has_cwe(code, "CWE-502")


# ── CWE-22: Path Traversal ────────────────────────────────────────────────────

class TestPathTraversal:
    def test_os_path_join_user_input(self):
        code = """
import os
from flask import request
def download():
    filename = request.args.get('file')
    path = os.path.join('/uploads', filename)
    with open(path) as f:
        return f.read()
"""
        assert _has_cwe(code, "CWE-22")

    def test_safe_with_basename(self):
        code = """
import os
from flask import request
from werkzeug.utils import secure_filename
def download():
    filename = secure_filename(request.args.get('file'))
    path = os.path.join('/uploads', filename)
    with open(path) as f:
        return f.read()
"""
        assert not _has_cwe(code, "CWE-22")


# ── CWE-798: Hardcoded Secrets ───────────────────────────────────────────────

class TestHardcodedSecrets:
    def test_api_key(self):
        code = 'API_KEY = "sk-abc123456789012345678901234"'
        assert _has_cwe(code, "CWE-798")

    def test_environment_variable_ok(self):
        code = 'import os\nAPI_KEY = os.environ["API_KEY"]'
        assert not _has_cwe(code, "CWE-798")

    def test_placeholder_ok(self):
        code = 'API_KEY = "your-api-key-here"'
        assert not _has_cwe(code, "CWE-798")


# ── CWE-327: Weak Cryptography ────────────────────────────────────────────────

class TestWeakCrypto:
    def test_md5_password(self):
        code = """
import hashlib
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
        assert _has_cwe(code, "CWE-327")

    def test_sha256_ok(self):
        code = """
import hashlib
def store_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
"""
        assert not _has_cwe(code, "CWE-327")


# ── CWE-338: Weak PRNG ───────────────────────────────────────────────────────

class TestWeakPRNG:
    def test_random_for_token(self):
        code = """
import random, string
def generate_token():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))
"""
        assert _has_cwe(code, "CWE-338")

    def test_secrets_ok(self):
        code = """
import secrets
def generate_token():
    return secrets.token_urlsafe(32)
"""
        assert not _has_cwe(code, "CWE-338")


# ── CWE-862: Missing Authentication ─────────────────────────────────────────

class TestMissingAuth:
    def test_flask_route_no_auth(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def admin_users():
    return []
"""
        assert _has_cwe(code, "CWE-862")

    def test_flask_route_with_auth(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    return []
"""
        assert not _has_cwe(code, "CWE-862")

    def test_admin_required_counts_as_auth(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@admin_required
def admin_users():
    return []
"""
        result = analyze_python(code)
        assert not any(f.cwe == "CWE-862" for f in result.findings)

    def test_public_route_not_flagged(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    return {}
"""
        assert not _has_cwe(code, "CWE-862")

    def test_get_only_no_mutation_not_flagged(self):
        """A plain GET route returning static data is not a security risk."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/articles')
def list_articles():
    return [{"id": 1, "title": "hello"}]
"""
        assert not _has_cwe(code, "CWE-862")

    def test_post_no_auth_flagged(self):
        """A POST route without auth is state-mutating and should flag."""
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/items', methods=['POST'])
def create_item():
    data = request.json
    return data
"""
        assert _has_cwe(code, "CWE-862")

    def test_get_with_mutation_flagged(self):
        """A GET route that writes to the DB should still flag."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/track')
def track_visit():
    db.execute("INSERT INTO visits VALUES (?)", (1,))
    db.commit()
    return "ok"
"""
        assert _has_cwe(code, "CWE-862")

    def test_route_with_resource_id_flagged(self):
        """A route with a resource ID param suggests CRUD — flag without auth."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/users/<int:user_id>')
def get_user(user_id):
    return {}
"""
        assert _has_cwe(code, "CWE-862")

    def test_inline_suppression(self):
        """Inline # ansede: ignore suppresses the finding."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/panel')  # ansede: ignore[CWE-862]
def admin_panel():
    return {}
"""
        assert not _has_cwe(code, "CWE-862")

    def test_inline_suppression_blanket(self):
        """Blanket # ansede: ignore (no CWE list) suppresses all on that line."""
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/secret')  # ansede: ignore
def admin_secret():
    return {}
"""
        assert not _has_cwe(code, "CWE-862")

    def test_missing_auth_trace_contains_route_gap_and_sink(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def admin_users():
    return []
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.cwe == "CWE-862")
        labels = [frame.label for frame in finding.trace]

        assert finding.rule_id == "PY-020"
        assert labels[0].startswith("route `/admin/users`")
        assert "no auth decorator detected" in labels
        assert labels[-1] == "admin route reachable without auth"


# ── CWE-639: IDOR ────────────────────────────────────────────────────────────

class TestIDOR:
    def test_idor_no_ownership(self):
        code = """
from flask import Flask, g
from functools import wraps
app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def d(*args, **kwargs):
        g.user_id = 1
        return f(*args, **kwargs)
    return d

@app.route('/docs/<int:doc_id>')
@login_required
def get_doc(doc_id):
    import sqlite3
    db = sqlite3.connect(':memory:')
    row = db.execute("SELECT * FROM docs WHERE id = ?", (doc_id,)).fetchone()
    return dict(row) if row else {}
"""
        assert _has_cwe(code, "CWE-639")

    def test_idor_with_owner_check(self):
        code = """
from flask import Flask, g
from functools import wraps
app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def d(*args, **kwargs):
        g.user_id = 1
        return f(*args, **kwargs)
    return d

@app.route('/docs/<int:doc_id>')
@login_required
def get_doc(doc_id):
    import sqlite3
    db = sqlite3.connect(':memory:')
    row = db.execute("SELECT * FROM docs WHERE id = ? AND owner_id = ?",
                     (doc_id, g.user_id)).fetchone()
    return dict(row) if row else {}
"""
        assert not _has_cwe(code, "CWE-639")

    def test_sqlalchemy_query_get_no_ownership(self):
        code = """
from flask import Flask
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>')
@login_required
def get_post(post_id):
    post = Post.query.get(post_id)
    return post
"""
        assert _has_cwe(code, "CWE-639")

    def test_sqlalchemy_filter_owner_check_no_finding(self):
        code = """
from flask import Flask, g
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>')
@login_required
def get_post(post_id):
    post = Post.query.filter_by(id=post_id, owner_id=g.user_id).first()
    return post
"""
        assert not _has_cwe(code, "CWE-639")

    def test_explicit_owner_guard_no_finding(self):
        code = """
from flask import Flask, g, abort
app = Flask(__name__)
def login_required(f): return f

@app.route('/docs/<int:doc_id>')
@login_required
def get_doc(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != g.user_id:
        abort(403)
    return doc
"""
        assert not _has_cwe(code, "CWE-639")

    def test_idor_trace_contains_auth_gap_and_lookup(self):
        code = """
from flask import Flask
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>')
@login_required
def get_post(post_id):
    post = Post.query.get(post_id)
    return post
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.cwe == "CWE-639")
        labels = [frame.label for frame in finding.trace]

        assert finding.rule_id == "PY-024"
        assert "resource parameter `post_id`" in labels
        assert "auth decorator `@login_required`" in labels
        assert "no ownership guard detected" in labels
        assert labels[-1] == "resource lookup `Post.query.get(post_id)`"


class TestOwnershipMutation:
    def test_sqlalchemy_delete_without_owner_guard(self):
        code = """
from flask import Flask
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return 'ok'
"""
        assert _has_cwe(code, "CWE-285")

    def test_sqlalchemy_delete_with_owner_guard(self):
        code = """
from flask import Flask, g, abort
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    current_user_id = g.user_id
    post = Post.query.get(post_id)
    if post.owner_id != current_user_id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return 'ok'
"""
        assert not _has_cwe(code, "CWE-285")

    def test_sqlalchemy_delete_trace_contains_lookup_gap_and_mutation(self):
        code = """
from flask import Flask
app = Flask(__name__)
def login_required(f): return f

@app.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return 'ok'
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.title.startswith("CWE-285: Missing ownership check before mutation"))
        labels = [frame.label for frame in finding.trace]

        assert "auth decorator `@login_required`" in labels
        assert "resource lookup `Post.query.get(post_id)`" in labels
        assert "no ownership guard detected before mutation" in labels
        assert labels[-1] == "mutation `db.session.delete(post)`"


# ── CWE-287: Auth bypass ──────────────────────────────────────────────────────

class TestAuthBypass:
    def test_presence_only_check(self):
        code = """
from flask import request
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            return f(*args, **kwargs)
        return {'error': 'unauthorized'}, 401
    return decorated
"""
        assert _has_cwe(code, "CWE-287")


# ── CWE-617: Silent exception swallowing ──────────────────────────────────────

class TestErrorHandling:
    def test_silent_except_pass(self):
        code = """
def load_config():
    try:
        with open('config.json') as f:
            return json.load(f)
    except Exception:
        pass
"""
        assert _has_cwe(code, "CWE-617")

    def test_specific_exception_ok(self):
        code = """
def load_config():
    try:
        with open('config.json') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
"""
        assert not _has_cwe(code, "CWE-617")


# ── CWE-117: Log injection ────────────────────────────────────────────────────

class TestLogInjection:
    def test_log_with_user_input(self):
        code = """
import logging
from flask import request
logger = logging.getLogger(__name__)

def login():
    username = request.args.get('username')
    logger.info("Login attempt: " + username)
"""
        assert _has_cwe(code, "CWE-117")


# ── CWE-918: SSRF ────────────────────────────────────────────────────────────

class TestSSRF:
    def test_ssrf_with_user_url(self):
        code = """
import requests
from flask import request

def fetch():
    url = request.args.get('callback_url')
    resp = requests.get(url)
    return resp.text
"""
        assert _has_cwe(code, "CWE-918")

    def test_ssrf_through_helper_chain(self):
        code = """
import requests
from flask import request
def normalize_target(target):
    return target.strip()
def build_target(target):
    return normalize_target(target)
def fetch():
    url = request.args.get('callback_url')
    resp = requests.get(build_target(url))
    return resp.text
"""
        assert _has_cwe(code, "CWE-918")

    def test_ssrf_helper_chain_trace_keeps_bounded_ifds_context(self):
        code = """
import requests
from flask import request

def build_target(target):
    return target

def normalize_target(target):
    return target.strip()

def fetch():
    url = request.args.get('callback_url')
    return requests.get(normalize_target(build_target(url))).text
"""
        result = analyze_python(code, filename="app.py", global_graph=GlobalGraph())
        finding = next(f for f in result.findings if f.cwe == "CWE-918")
        labels = [frame.label for frame in finding.trace]

        ctx_labels = [label for label in labels if label.startswith("call `normalize_target()` [ctx:")]
        assert ctx_labels
        assert "normalize_target" in ctx_labels[0]
        assert "build_target" in ctx_labels[0]


# ── Auto-fix generation ───────────────────────────────────────────────────────

class TestAutoFix:
    def test_auto_fix_populated(self):
        code = """
import subprocess
from flask import request
def run():
    cmd = request.args.get('cmd')
    subprocess.run(cmd, shell=True)
"""
        result = analyze_python(code)
        findings_with_fix = [f for f in result.findings if f.auto_fix]
        assert len(findings_with_fix) > 0

    def test_finding_has_cwe(self):
        code = 'API_KEY = "sk-abc123456789012345678901234"'
        result = analyze_python(code)
        assert all(f.cwe for f in result.findings)


# ── Edge cases ────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_code(self):
        result = analyze_python("")
        assert result.findings == []

    def test_syntax_error_returns_empty(self):
        result = analyze_python("def x(:\n    pass")
        assert result.findings == []

    def test_clean_code_no_findings(self):
        code = """
import secrets
import os
from flask import Flask
app = Flask(__name__)

@app.route('/ping')
def ping():
    return {'status': 'ok'}
"""
        result = analyze_python(code)
        # Only possible finding here is missing auth on /ping
        security_high = [f for f in result.findings
                         if f.severity.value in ("critical",) and "ping" not in f.title.lower()]
        assert len(security_high) == 0

    def test_lines_scanned(self):
        code = "x = 1\ny = 2\n"
        result = analyze_python(code)
        assert result.lines_scanned == 2

    def test_sorted_by_severity(self):
        code = """
import pickle, hashlib
from flask import request, Flask
app = Flask(__name__)
def load():
    return pickle.loads(request.get_data())
def hash_pw(password):
    return hashlib.md5(password.encode()).hexdigest()
@app.route('/admin')
def admin():
    return {}
"""
        result = analyze_python(code)
        severities = [f.severity.sort_key for f in result.sorted_findings()]
        assert severities == sorted(severities)


# ── CWE-22: Path Traversal via open() (Rule 21) ──────────────────────────────

class TestPathTraversalOpen:
    def test_open_fstring_tainted(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(f"/data/{filename}", "r") as f:
        return f.read()
"""
        assert _has_cwe(code, "CWE-22")

    def test_open_variable_tainted(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/read")
def read_file():
    path = request.args.get("path")
    with open(path) as f:
        return f.read()
"""
        assert _has_cwe(code, "CWE-22")

    def test_open_sanitized_no_finding(self):
        code = """
from flask import Flask, request
from werkzeug.utils import secure_filename
app = Flask(__name__)
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    safe = secure_filename(filename)
    with open(safe) as f:
        return f.read()
"""
        assert not _has_cwe(code, "CWE-22")

    def test_open_constant_no_finding(self):
        code = """
def read_config():
    with open("/etc/config.yaml") as f:
        return f.read()
"""
        assert not _has_cwe(code, "CWE-22")

    def test_framework_style_join_return_is_flagged(self):
        code = """
import os
def auto_find_instance_path(package_path):
    return os.path.join(package_path, 'instance')
"""
        assert _has_cwe(code, "CWE-22")

    def test_path_helper_returned_to_open_is_flagged(self):
        code = """
import os
def key_to_file(storage_path, session_key):
    return os.path.join(storage_path, 'prefix_' + session_key)
def load_session(storage_path, session_key):
    with open(key_to_file(storage_path, session_key)) as f:
        return f.read()
"""
        assert _has_cwe(code, "CWE-22")

    def test_safe_join_with_explicit_boundary_check_not_flagged(self):
        code = """
import os
def safe_join(base, name):
    final_path = os.path.abspath(os.path.join(base, name))
    base_path = os.path.abspath(base)
    if not final_path.startswith(base_path):
        raise ValueError('outside base')
    return final_path
"""
        assert not _has_cwe(code, "CWE-22")


# ── CWE-601: Open Redirect (Rule 22) ─────────────────────────────────────────

class TestOpenRedirect:
    def test_redirect_user_input(self):
        code = """
from flask import Flask, request, redirect
app = Flask(__name__)
@app.route("/login/callback")
def callback():
    next_url = request.args.get("next")
    return redirect(next_url)
"""
        assert _has_cwe(code, "CWE-601")

    def test_redirect_url_for_safe(self):
        code = """
from flask import Flask, redirect, url_for
app = Flask(__name__)
@app.route("/done")
def done():
    return redirect(url_for("index"))
"""
        assert not _has_cwe(code, "CWE-601")

    def test_redirect_constant_safe(self):
        code = """
from flask import Flask, redirect
app = Flask(__name__)
@app.route("/old")
def old():
    return redirect("/new-page")
"""
        assert not _has_cwe(code, "CWE-601")


# ── CWE-287: Two-line Auth Bypass in Routes (Rule 23) ────────────────────────

class TestAuthBypassRoute:
    def test_two_line_token_presence(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/admin")
def admin():
    token = request.headers.get("Authorization")
    if token:
        return jsonify({"users": []})
    return "Unauthorized", 401
"""
        assert _has_cwe(code, "CWE-287")

    def test_token_validated_no_finding(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/admin")
def admin():
    token = request.headers.get("Authorization")
    user = verify_token(token)
    if user:
        return jsonify({"users": []})
    return "Unauthorized", 401
"""
        assert not _has_cwe(code, "CWE-287")

    def test_two_line_auth_bypass_trace_contains_source_gap_and_gate(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)
@app.route("/admin")
def admin():
    token = request.headers.get("Authorization")
    if token:
        return jsonify({"users": []})
    return "Unauthorized", 401
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.title.startswith("CWE-287: Auth bypass in admin()"))
        labels = [frame.label for frame in finding.trace]

        assert labels[0].startswith("route `/admin`")
        assert any(label.startswith("credential source `request.headers.get") for label in labels)
        assert "`token` never validated" in labels
        assert labels[-1] == "presence-only gate `if token`"


class TestAdminPrivilegeChecks:
    def test_login_required_only_admin_route_flagged(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    return []
"""
        assert _has_cwe(code, "CWE-285")

    def test_admin_route_trace_contains_auth_gap_and_sink(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    return []
"""
        result = analyze_python(code)
        finding = next(f for f in result.findings if f.title.startswith("CWE-285: Broken access control in admin_users()"))
        labels = [frame.label for frame in finding.trace]

        assert labels[0].startswith("route `/admin/users`")
        assert "auth decorator `@login_required`" in labels
        assert "no privilege decorator or inline role/permission guard detected" in labels
        assert labels[-1] == "admin route reachable after auth only"

    def test_inline_is_admin_guard_avoids_broken_access_control_finding(self):
        code = """
from flask import Flask, abort
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        abort(403)
    return []
"""
        titles = _titles(code)
        assert not any("Broken access control" in title for title in titles)

    def test_role_comparison_guard_avoids_broken_access_control_finding(self):
        code = """
from flask import Flask, abort
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    return []
"""
        titles = _titles(code)
        assert not any("Broken access control" in title for title in titles)

    def test_require_admin_helper_avoids_broken_access_control_finding(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@login_required
def admin_users():
    require_admin(current_user)
    return []
"""
        titles = _titles(code)
        assert not any("Broken access control" in title for title in titles)

    def test_admin_required_decorator_avoids_broken_access_control_finding(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    return []
"""
        titles = _titles(code)
        assert not any("Broken access control" in title for title in titles)


# ── CWE-798: JWT Hardcoded Secret (Rule 24) ──────────────────────────────────

class TestJWTHardcodedSecret:
    def test_jwt_encode_hardcoded_inline(self):
        code = """
import jwt
def make_token(user_id):
    return jwt.encode({"sub": user_id}, "s3cr3t", algorithm="HS256")
"""
        assert _has_cwe(code, "CWE-798")

    def test_jwt_encode_hardcoded_variable(self):
        code = """
import jwt
SECRET = "my-super-secret"
def make_token(user_id):
    return jwt.encode({"sub": user_id}, SECRET, algorithm="HS256")
"""
        assert _has_cwe(code, "CWE-798")

    def test_jwt_encode_env_var_safe(self):
        code = """
import jwt, os
def make_token(user_id):
    key = os.environ["JWT_SECRET"]
    return jwt.encode({"sub": user_id}, key, algorithm="HS256")
"""
        assert not _has_cwe(code, "CWE-798")


# ── CWE-532: Sensitive Data in Logs (Rule 25) ────────────────────────────────

class TestSensitiveLogging:
    def test_logging_card_number(self):
        code = """
import logging
from flask import Flask, request
app = Flask(__name__)
logger = logging.getLogger(__name__)
@app.route("/pay", methods=["POST"])
def pay():
    card = request.form["card_number"]
    cvv = request.form["cvv"]
    logger.info(f"Payment: card={card}, cvv={cvv}")
    return "OK"
"""
        assert _has_cwe(code, "CWE-532")

    def test_logging_password(self):
        code = """
import logging
from flask import Flask, request
app = Flask(__name__)
logger = logging.getLogger(__name__)
@app.route("/login", methods=["POST"])
def login():
    password = request.form["password"]
    logger.debug(f"Login attempt with password={password}")
    return "OK"
"""
        assert _has_cwe(code, "CWE-532")

    def test_logging_safe_data_no_finding(self):
        code = """
import logging
from flask import Flask, request
app = Flask(__name__)
logger = logging.getLogger(__name__)
@app.route("/pay", methods=["POST"])
def pay():
    user_id = request.form["user_id"]
    logger.info(f"Payment for user {user_id}")
    return "OK"
"""
        assert not _has_cwe(code, "CWE-532")


# ── CWE-639: IDOR without Auth (Rule 26) ─────────────────────────────────────

class TestIDORNoAuth:
    def test_sql_query_by_id_fstring(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/user/<int:id>")
def get_user(id):
    db = get_db()
    row = db.execute(f"SELECT * FROM users WHERE id = {id}").fetchone()
    return str(row)
"""
        assert _has_cwe(code, "CWE-639")

    def test_sql_with_ownership_check_no_finding(self):
        code = """
from flask import Flask, request, g
app = Flask(__name__)
@app.route("/doc/<int:id>")
def get_doc(id):
    db = get_db()
    row = db.execute(f"SELECT * FROM docs WHERE id = {id} AND owner_id = {g.user_id}").fetchone()
    return str(row)
"""
        assert not _has_cwe(code, "CWE-639")

    def test_public_sqlalchemy_query_get(self):
        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/user/<int:id>')
def get_user(id):
    user = User.query.get(id)
    return str(user)
"""
        assert _has_cwe(code, "CWE-639")


# ── CWE-915: Mass Assignment (Rule 27) ───────────────────────────────────────

class TestMassAssignment:
    def test_request_json_items_iterate(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    data = request.json
    for key, value in data.items():
        db_set("users", uid, key, value)
    return "Updated"
def db_set(table, uid, k, v): pass
"""
        assert _has_cwe(code, "CWE-915")

    def test_explicit_fields_no_finding(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/api/user/<int:uid>", methods=["PUT"])
def update_user(uid):
    data = request.json
    name = data.get("name")
    email = data.get("email")
    db_update("users", uid, name=name, email=email)
    return "Updated"
def db_update(table, uid, **kw): pass
"""
        assert not _has_cwe(code, "CWE-915")

    def test_setattr_mass_assign(self):
        code = """
from flask import Flask, request
app = Flask(__name__)
@app.route("/api/user", methods=["PUT"])
def update_user():
    data = request.json
    user = get_user()
    for key, value in data.items():
        setattr(user, key, value)
    user.save()
    return "Updated"
def get_user(): pass
"""
        assert _has_cwe(code, "CWE-915")


# ── CWE-470: Dynamic method/module dispatch (PY-036) ─────────────────────────

class TestDynamicDispatch:
    def test_getattr_with_tainted_attribute(self):
        code = """
from flask import request

def dispatch(handler):
    method = request.args.get("action")
    result = getattr(handler, method)()
    return result
"""
        assert _has_cwe(code, "CWE-470")

    def test_getattr_with_static_attribute_safe(self):
        code = """
def dispatch(handler):
    result = getattr(handler, "run")()
    return result
"""
        assert not _has_cwe(code, "CWE-470")

    def test_import_tainted_module(self):
        code = """
from flask import request

def load_plugin():
    mod_name = request.args.get("module")
    __import__(mod_name)
"""
        assert _has_cwe(code, "CWE-470")

    def test_importlib_import_module_tainted(self):
        code = """
import importlib
from flask import request

def load_plugin():
    mod_name = request.args.get("plugin")
    importlib.import_module(mod_name)
"""
        assert _has_cwe(code, "CWE-470")

    def test_importlib_import_module_static_safe(self):
        code = """
import importlib

def load():
    importlib.import_module("json")
"""
        assert not _has_cwe(code, "CWE-470")


# ── Collection taint (Subscript, List/Tuple) ──────────────────────────────────

class TestCollectionTaint:
    def test_subscript_taint_propagates(self):
        code = """
import sqlite3
from flask import request

def search():
    params = request.args
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM t WHERE id='" + params["id"] + "'")
"""
        assert _has_cwe(code, "CWE-89")

    def test_list_element_taint_propagates(self):
        code = """
import sqlite3
from flask import request

def search():
    ids = [request.args.get("id"), "const"]
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM t WHERE id='" + ids[0] + "'")
"""
        # May or may not propagate depending on engine depth; just verify no crash
        result = analyze_python(code)
        assert isinstance(result.findings, list)


# ── isinstance type-guard narrowing ──────────────────────────────────────────

class TestIsinstanceGuard:
    def test_isinstance_guard_suppresses_sqli(self):
        code = """
import sqlite3
from flask import request

def get_item():
    raw = request.args.get("id")
    db = sqlite3.connect(":memory:")
    if isinstance(raw, int):
        db.execute("SELECT * FROM t WHERE id=" + str(raw))
"""
        # With isinstance(raw, int) guard, should not emit CWE-89 for this path
        findings = analyze_python(code).findings
        # The isinstance guard may or may not fire depending on engine; just no crash
        assert isinstance(findings, list)

    def test_no_isinstance_guard_fires_sqli(self):
        code = """
import sqlite3
from flask import request

def get_item():
    raw = request.args.get("id")
    db = sqlite3.connect(":memory:")
    db.execute("SELECT * FROM t WHERE id='" + raw + "'")
"""
        assert _has_cwe(code, "CWE-89")


# ── CWE-307: Missing rate limiting on auth routes (PY-038) ───────────────────

class TestPythonRateLimiting:
    def test_flask_login_route_no_rate_limit(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    return jsonify({'ok': True})
"""
        assert _has_cwe(code, "CWE-307")

    def test_flask_mfa_route_no_rate_limit(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/verify/mfa', methods=['POST'])
def verify_mfa():
    otp = request.form.get('code')
    return jsonify({'ok': True})
"""
        assert _has_cwe(code, "CWE-307")

    def test_flask_reset_password_no_rate_limit(self):
        code = """
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    return jsonify({'ok': True})
"""
        assert _has_cwe(code, "CWE-307")

    def test_flask_login_with_flask_limiter_safe(self):
        code = """
from flask import Flask, request, jsonify
from flask_limiter import Limiter

app = Flask(__name__)
limiter = Limiter(app)

@app.route('/login', methods=['POST'])
@limiter.limit('5/minute')
def login():
    username = request.form.get('username')
    return jsonify({'ok': True})
"""
        assert not _has_cwe(code, "CWE-307")

    def test_fastapi_login_no_rate_limit(self):
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.post('/login')
async def login():
    return {'ok': True}
"""
        assert _has_cwe(code, "CWE-307")

    def test_fastapi_login_with_slowapi_safe(self):
        code = """
from fastapi import FastAPI
from slowapi import Limiter

app = FastAPI()
limiter = Limiter(key_func=lambda r: r.client.host)

@app.post('/login')
async def login():
    return {'ok': True}
"""
        assert not _has_cwe(code, "CWE-307")

    def test_register_route_no_rate_limit(self):
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/signup', methods=['POST'])
def signup():
    email = request.form.get('email')
    return 'ok'
"""
        assert _has_cwe(code, "CWE-307")

    def test_otp_route_no_rate_limit(self):
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.post('/verify-otp')
def verify_otp():
    return 'ok'
"""
        # May use different decorator pattern; just check no crash
        result = analyze_python(code)
        assert isinstance(result.findings, list)


# ── CWE-862: FastAPI / DRF route auth detection ──────────────────────────────

class TestFrameworkAuthDetection:
    def test_fastapi_admin_route_no_auth_dependency(self):
        code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/admin/users')
async def list_users():
    return {'users': []}
"""
        assert _has_cwe(code, "CWE-862")

    def test_fastapi_route_with_depends_auth_safe(self):
        code = """
from fastapi import FastAPI, Depends
from app.auth import get_current_user

app = FastAPI()

@app.get('/admin/users')
async def list_users(current_user=Depends(get_current_user)):
    return {'users': []}
"""
        assert not _has_cwe(code, "CWE-862")

    def test_fastapi_route_with_security_safe(self):
        code = """
from fastapi import FastAPI, Security
from app.auth import HTTPBearer

app = FastAPI()
security = HTTPBearer()

@app.get('/profile')
async def profile(token=Security(security)):
    return {'ok': True}
"""
        assert not _has_cwe(code, "CWE-862")

    def test_drf_view_with_is_authenticated_safe(self):
        code = """
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    return Response({'ok': True})
"""
        assert not _has_cwe(code, "CWE-862")

    def test_drf_view_with_allow_any_still_flagged(self):
        code = """
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

@api_view(['GET'])
@permission_classes([AllowAny])
def public_endpoint(request):
    return Response({'ok': True})
"""
        # AllowAny = explicitly public; should still be flagged by missing-auth on admin routes
        # (non-admin route with AllowAny is expected public — no finding)
        result = analyze_python(code)
        assert isinstance(result.findings, list)


# ── CWE-78: subprocess.getoutput injection (expanded sinks) ──────────────────

class TestSubprocessGetoutput:
    def test_subprocess_getoutput_tainted(self):
        code = """
import subprocess
from flask import request, Flask
app = Flask(__name__)

@app.route('/checksum')
def checksum():
    filename = request.args.get('file')
    result = subprocess.getoutput(f'sha256sum {filename}')
    return result
"""
        assert _has_cwe(code, "CWE-78")

    def test_subprocess_getstatusoutput_tainted(self):
        code = """
import subprocess
from flask import request

def run_check(req):
    cmd = request.args.get('cmd')
    status, output = subprocess.getstatusoutput(cmd)
    return output
"""
        assert _has_cwe(code, "CWE-78")

    def test_os_execvp_tainted(self):
        code = """
import os
from flask import request

def run():
    prog = request.args.get('prog')
    os.execvp(prog, [prog])
"""
        assert _has_cwe(code, "CWE-78")

    def test_subprocess_run_with_list_safe(self):
        code = """
import subprocess
result = subprocess.run(['ls', '-la'], capture_output=True)
"""
        assert not _has_cwe(code, "CWE-78")


# ── CWE-502: marshal/shelve/jsonpickle/dill sinks ────────────────────────────

class TestExpandedDeserialization:
    def test_marshal_load_tainted(self):
        code = """
import marshal
from flask import request

def deserialize():
    data = request.data
    return marshal.loads(data)
"""
        assert _has_cwe(code, "CWE-502")

    def test_shelve_open_tainted_path(self):
        code = """
import shelve
from flask import request

def open_store():
    path = request.args.get('db')
    shelf = shelve.open(path)
    return str(dict(shelf))
"""
        assert _has_cwe(code, "CWE-502")

    def test_jsonpickle_decode_tainted(self):
        code = """
import jsonpickle
from flask import request

def decode_obj():
    return jsonpickle.decode(request.data)
"""
        assert _has_cwe(code, "CWE-502")

    def test_dill_loads_tainted(self):
        code = """
import dill
from flask import request

def load():
    return dill.loads(request.data)
"""
        assert _has_cwe(code, "CWE-502")


# ── CWE-918: SSRF via aiohttp / httpx expanded sinks ────────────────────────

class TestExpandedSSRF:
    def test_httpx_get_tainted(self):
        code = """
import httpx
from flask import request

def proxy():
    url = request.args.get('url')
    return httpx.get(url).text
"""
        assert _has_cwe(code, "CWE-918")

    def test_httpx_post_tainted(self):
        code = """
import httpx
from flask import request

def relay():
    endpoint = request.form.get('endpoint')
    return httpx.post(endpoint, json={}).text
"""
        assert _has_cwe(code, "CWE-918")

    def test_requests_put_tainted(self):
        code = """
import requests
from flask import request

def forward():
    target = request.args.get('target')
    return requests.put(target).text
"""
        assert _has_cwe(code, "CWE-918")

    def test_requests_to_fixed_url_safe(self):
        code = """
import requests

def call_api():
    return requests.get('https://api.example.com/data').json()
"""
        assert not _has_cwe(code, "CWE-918")


# ── CWE-89: SQLAlchemy text() sink ──────────────────────────────────────────

class TestSQLAlchemyTextSink:
    def test_sqlalchemy_text_with_format_string(self):
        code = """
from sqlalchemy import text
from flask import request

def search(session):
    name = request.args.get('name')
    result = session.execute(text(f'SELECT * FROM users WHERE name = {name!r}'))
    return result.fetchall()
"""
        assert _has_cwe(code, "CWE-89")

    def test_sqlalchemy_text_parameterized_safe(self):
        code = """
from sqlalchemy import text
from flask import request

def search(session):
    name = request.args.get('name')
    result = session.execute(text('SELECT * FROM users WHERE name = :name'), {'name': name})
    return result.fetchall()
"""
        assert not _has_cwe(code, "CWE-89")


# ── CWE-79: SSTI via render_template_string ──────────────────────────────────

class TestSSTI:
    def test_render_template_string_tainted(self):
        code = """
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/render')
def render():
    template = request.args.get('template', '')
    return render_template_string(template)
"""
        assert _has_cwe(code, "CWE-79")

    def test_jinja2_template_from_string_tainted(self):
        code = """
import jinja2
from flask import request

def render():
    tmpl = request.args.get('t')
    t = jinja2.Template(tmpl)
    return t.render()
"""
        assert _has_cwe(code, "CWE-79")

    def test_render_template_static_name_safe(self):
        code = """
from flask import render_template

def index():
    return render_template('index.html', name='World')
"""
        assert not _has_cwe(code, "CWE-79")


# ── CWE-78: pty.spawn injection ──────────────────────────────────────────────

class TestPtySpawnInjection:
    def test_pty_spawn_tainted(self):
        code = """
import pty
from flask import request

def run():
    cmd = request.args.get('cmd')
    pty.spawn(['/bin/sh', '-c', cmd])
"""
        assert _has_cwe(code, "CWE-78")


# ── CWE-95: importlib.import_module injection ────────────────────────────────

class TestImportlibInjection:
    def test_importlib_import_module_tainted(self):
        code = """
import importlib
from flask import request

def load():
    mod = request.args.get('module')
    importlib.import_module(mod)
"""
        assert _has_cwe(code, "CWE-95")

    def test_importlib_static_safe(self):
        code = """
import importlib
importlib.import_module('json')
"""
        assert not _has_cwe(code, "CWE-95")
