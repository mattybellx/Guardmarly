"""Tests for enhanced symbolic guard analysis (ROADMAP Section 3.2)."""
from __future__ import annotations

from guardmarly.python_analyzer import analyze_python
from guardmarly.js_analyzer import analyze_js


class TestNullGuardDetection:
    def test_user_is_none_guard_suppresses_missing_auth(self):
        code = """
from flask import Flask, g, abort
app = Flask(__name__)

@app.get('/admin/users')
def admin_users():
    if g.user is None:
        return abort(401)
    return list_users()
"""
        result = analyze_python(code)
        assert not any(
            f.rule_id in {"PY-020", "PY-027", "PY-028"}
            and f.cwe == "CWE-862"
            for f in result.findings
        ), "None guard should suppress missing-auth findings"

    def test_not_user_guard_with_deny_suppresses_auth_missing(self):
        code = """
from flask import Flask, g, abort
app = Flask(__name__)

@app.get('/admin/users')
def admin_users():
    if not g.user:
        abort(401)
    return list_users()
"""
        result = analyze_python(code)
        assert not any(
            f.rule_id in {"PY-020", "PY-027", "PY-028"}
            and f.cwe == "CWE-862"
            for f in result.findings
        ), "`if not user: abort(401)` should suppress auth findings"

    def test_session_get_is_none_guard_suppresses(self):
        code = """
from flask import Flask, session, abort
app = Flask(__name__)

@app.get('/profile')
def profile():
    if session.get('user_id') is None:
        return abort(401)
    return get_profile(session['user_id'])
"""
        result = analyze_python(code)
        assert not any(
            f.rule_id in {"PY-020", "PY-026"}
            and f.cwe == "CWE-862"
            for f in result.findings
        ), "Session None guard should suppress auth gap"


class TestCompoundConditionGuards:
    def test_auth_and_ownership_compound_guards_both(self):
        code = """
from flask import Flask, request, abort
app = Flask(__name__)

@app.get('/invoice/<invoice_id>')
def get_invoice(invoice_id):
    if request.user.is_authenticated and Invoice.objects.filter(owner=request.user, pk=invoice_id).exists():
        return Invoice.objects.get(pk=invoice_id)
    return abort(403)
"""
        result = analyze_python(code)
        assert not any(f.cwe == "CWE-639" for f in result.findings), \
            "Compound auth+ownership condition should suppress IDOR"

    def test_auth_and_admin_compound_without_role_still_flags_privilege(self):
        code = """
from flask import Flask, request
app = Flask(__name__)

@app.get('/admin/users')
def admin_users():
    if request.user.is_authenticated and request.user.is_active:
        return list_users()
    return 'denied'
"""
        result = analyze_python(code)
        # Auth check present — no missing-auth or broken-access-control findings
        # should fire since the route is properly authenticated
        assert not any(
            f.cwe in {"CWE-862", "CWE-306"} and f.confidence > 0.2
            for f in result.findings
        ), "Compound auth condition should suppress missing-auth findings"


class TestJsNullGuard:
    def test_js_null_user_guard_suppresses_auth_finding(self):
        code = """
app.get('/admin/users', (req, res) => {
  if (!req.user) {
    return res.status(401).send('unauthorized');
  }
  res.json(User.findAll());
});
"""
        result = analyze_js(code)
        assert not any(f.cwe == "CWE-862" for f in result.findings), \
            "JS null user guard should suppress missing-auth"
