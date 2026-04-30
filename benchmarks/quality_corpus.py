"""
benchmarks.quality_corpus
─────────────────────────
Curated signal-quality fixtures for ansede-static.

These cases are intentionally small and deterministic. They are not a substitute
for large real-world corpora, but they provide a fast precision/recall harness
for the rules most likely to affect user trust.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class QualityCase:
    case_id: str
    language: str
    snippet: str
    expected_cwes: tuple[str, ...] = field(default_factory=tuple)
    forbidden_cwes: tuple[str, ...] = field(default_factory=tuple)
    expected_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    forbidden_rule_ids: tuple[str, ...] = field(default_factory=tuple)
    filename: str = ""
    js_backend: str = "auto"
    notes: str = ""


QUALITY_CORPUS: tuple[QualityCase, ...] = (
    QualityCase(
        case_id="py-sqli-unsafe",
        language="python",
        filename="unsafe_sql.py",
        snippet="""
from flask import request

def run_query(cursor):
    user_id = request.args.get('id')
    cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")
""",
        expected_cwes=("CWE-89",),
        expected_rule_ids=("PY-004",),
        notes="Baseline Python SQL injection hit.",
    ),
    QualityCase(
        case_id="py-sqli-safe",
        language="python",
        filename="safe_sql.py",
        snippet="""
from flask import request

def run_query(cursor):
    user_id = request.args.get('id')
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
""",
        forbidden_cwes=("CWE-89",),
        forbidden_rule_ids=("PY-004",),
        notes="Parameterized query should remain quiet.",
    ),
    QualityCase(
        case_id="py-missing-auth-unsafe",
        language="python",
        filename="missing_auth.py",
        snippet="""
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def list_users():
    return []
""",
        expected_cwes=("CWE-862",),
        expected_rule_ids=("PY-020",),
        notes="Flag missing auth on a sensitive admin route.",
    ),
    QualityCase(
        case_id="py-idor-unsafe",
        language="python",
        filename="idor_lookup.py",
        snippet="""
from flask import Flask, g
app = Flask(__name__)

@app.route('/invoice/<invoice_id>')
@login_required
def get_invoice(invoice_id):
    return db.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
""",
        expected_cwes=("CWE-639",),
        expected_rule_ids=("PY-024",),
        notes="Resource fetched by identifier with no owner scope.",
    ),
    QualityCase(
        case_id="py-ownership-safe",
        language="python",
        filename="safe_ownership.py",
        snippet="""
from flask import Flask, g, abort
app = Flask(__name__)

@app.route('/post/<post_id>/delete', methods=['POST'])
@login_required
def delete_post(post_id):
    row = db.execute('SELECT owner_id FROM posts WHERE id = ?', (post_id,)).fetchone()
    if row['owner_id'] != g.user_id:
        abort(403)
    db.execute('DELETE FROM posts WHERE id = ? AND owner_id = ?', (post_id, g.user_id))
""",
        forbidden_cwes=("CWE-285", "CWE-639"),
        forbidden_rule_ids=("PY-024", "PY-025"),
        notes="Explicit owner guard should suppress route ownership findings.",
    ),
    QualityCase(
        case_id="js-dom-xss-unsafe",
        language="javascript",
        filename="dom_xss.js",
        js_backend="structural",
        snippet="""
function render(req) {
  const el = document.getElementById('out');
  el.innerHTML = req.query.name;
}
""",
        expected_cwes=("CWE-79",),
        expected_rule_ids=("JS-001",),
        notes="Structural DOM XSS detection should fire.",
    ),
    QualityCase(
        case_id="js-dom-xss-sanitized",
        language="javascript",
        filename="dom_xss_safe.js",
        js_backend="structural",
        snippet="""
function render(req) {
  const el = document.getElementById('out');
  const safe = DOMPurify.sanitize(req.query.name);
  el.innerHTML = safe;
}
""",
        forbidden_cwes=("CWE-79",),
        forbidden_rule_ids=("JS-001", "JS-027"),
        notes="Known sanitizer should suppress HTML findings.",
    ),
    QualityCase(
        case_id="js-route-missing-auth",
        language="javascript",
        filename="route_missing_auth.js",
        js_backend="structural",
        snippet="""
const express = require('express');
const app = express();

app.get('/admin/users', (req, res) => {
  res.json([]);
});
""",
        expected_cwes=("CWE-862",),
        expected_rule_ids=("JS-034",),
        notes="Sensitive route with no auth middleware.",
    ),
    QualityCase(
        case_id="js-route-auth-safe",
        language="javascript",
        filename="route_auth_safe.js",
        js_backend="structural",
        snippet="""
const express = require('express');
const app = express();

function requireAuth(req, res, next) { next(); }

app.get('/account/profile', requireAuth, (req, res) => {
  res.json({ ok: true });
});
""",
        forbidden_cwes=("CWE-862",),
        forbidden_rule_ids=("JS-034",),
        notes="Authenticated non-admin route should stay quiet for missing-auth heuristics.",
    ),
    QualityCase(
        case_id="js-open-redirect",
        language="javascript",
        filename="open_redirect.js",
        js_backend="structural",
        snippet="""
function go(req, res) {
  res.redirect(req.query.next);
}
""",
        expected_cwes=("CWE-601",),
        expected_rule_ids=("JS-039",),
        notes="Open redirect through unvalidated target.",
    ),
    # ── New rule coverage entries ─────────────────────────────────────────────
    QualityCase(
        case_id="js-xxe-unsafe",
        language="javascript",
        filename="xxe_unsafe.js",
        js_backend="auto",
        snippet="""
const { DOMParser } = require('xmldom');
const parser = new DOMParser();
const doc = parser.parseFromString(req.body.xml, 'text/xml');
""",
        expected_cwes=("CWE-611",),
        expected_rule_ids=("JS-043",),
        notes="DOMParser without entity restriction should trigger XXE rule.",
    ),
    QualityCase(
        case_id="js-xxe-safe",
        language="javascript",
        filename="xxe_safe.js",
        js_backend="auto",
        snippet="""
const { DOMParser } = require('xmldom');
const parser = new DOMParser({ resolveExternalEntities: false });
const doc = parser.parseFromString(req.body.xml, 'text/xml');
""",
        forbidden_cwes=("CWE-611",),
        forbidden_rule_ids=("JS-043",),
        notes="resolveExternalEntities: false should suppress XXE finding.",
    ),
    QualityCase(
        case_id="js-cookie-no-secure",
        language="javascript",
        filename="cookie_unsafe.js",
        js_backend="auto",
        snippet="""
app.post('/login', (req, res) => {
  res.cookie('session', token, { httpOnly: true });
  res.json({ ok: true });
});
""",
        expected_cwes=("CWE-614",),
        expected_rule_ids=("JS-045",),
        notes="Cookie without secure flag is a CWE-614 finding.",
    ),
    QualityCase(
        case_id="js-cookie-with-secure",
        language="javascript",
        filename="cookie_safe.js",
        js_backend="auto",
        snippet="""
app.post('/login', (req, res) => {
  res.cookie('session', token, { httpOnly: true, secure: true });
  res.json({ ok: true });
});
""",
        forbidden_cwes=("CWE-614",),
        forbidden_rule_ids=("JS-045",),
        notes="Cookie with secure: true should not trigger CWE-614.",
    ),
    QualityCase(
        case_id="js-node-serialize-unsafe",
        language="javascript",
        filename="node_serialize.js",
        js_backend="auto",
        snippet="""
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.body.data);
""",
        expected_cwes=("CWE-502",),
        expected_rule_ids=("JS-046",),
        notes="node-serialize unserialize() is a known RCE vector (CWE-502).",
    ),
    QualityCase(
        case_id="js-header-injection-unsafe",
        language="javascript",
        filename="header_injection.js",
        js_backend="auto",
        snippet="""
app.get('/redirect', (req, res) => {
  res.setHeader('Location', req.query.url);
  res.status(302).end();
});
""",
        expected_cwes=("CWE-113",),
        expected_rule_ids=("JS-044",),
        notes="Setting a response header with unsanitized query input enables HTTP header injection.",
    ),
    QualityCase(
        case_id="py-rate-limit-missing",
        language="python",
        filename="no_rate_limit.py",
        snippet="""
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    return jsonify({'ok': True})
""",
        expected_cwes=("CWE-307",),
        expected_rule_ids=("PY-038",),
        notes="Flask login route with no rate limiter should fire CWE-307.",
    ),
    QualityCase(
        case_id="py-rate-limit-present",
        language="python",
        filename="with_rate_limit.py",
        snippet="""
from flask import Flask, request, jsonify
from flask_limiter import Limiter

app = Flask(__name__)
limiter = Limiter(app)

@app.route('/login', methods=['POST'])
@limiter.limit('5/minute')
def login():
    username = request.form.get('username')
    return jsonify({'ok': True})
""",
        forbidden_cwes=("CWE-307",),
        forbidden_rule_ids=("PY-038",),
        notes="flask_limiter with @limiter.limit should suppress the CWE-307 finding.",
    ),
    QualityCase(
        case_id="py-fastapi-no-auth",
        language="python",
        filename="fastapi_no_auth.py",
        snippet="""
from fastapi import FastAPI

app = FastAPI()

@app.get('/admin/users')
async def list_users():
    return {'users': []}
""",
        expected_cwes=("CWE-862",),
        notes="FastAPI admin route with no Depends() guard should trigger missing-auth.",
    ),
    QualityCase(
        case_id="py-fastapi-with-auth",
        language="python",
        filename="fastapi_with_auth.py",
        snippet="""
from fastapi import FastAPI, Depends
from app.auth import get_current_user

app = FastAPI()

@app.get('/admin/users')
async def list_users(user=Depends(get_current_user)):
    return {'users': []}
""",
        forbidden_cwes=("CWE-862",),
        notes="FastAPI route with Depends() auth should not trigger missing-auth.",
    ),
)
