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
    guard_family: str = ""


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
        guard_family="access-control",
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
        forbidden_rule_ids=("JS-001", "JS-059"),
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
        guard_family="access-control",
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
        guard_family="rate-limit",
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
        guard_family="access-control",
    ),
    QualityCase(
        case_id="py-auth-none-guard-safe",
        language="python",
        filename="auth_none_guard.py",
        snippet="""
from flask import Flask, g, abort
app = Flask(__name__)

@app.get('/admin/users')
def admin_users():
    if g.user is None:
        return abort(401)
    return list_users()
""",
        forbidden_cwes=("CWE-862",),
        notes="Explicit None-check auth guard should suppress missing-auth findings.",
        guard_family="auth-guard",
    ),
    QualityCase(
        case_id="js-auth-null-guard-safe",
        language="javascript",
        filename="js_auth_null_guard.js",
        js_backend="structural",
        snippet="""
app.get('/admin/users', (req, res) => {
  if (!req.user) {
    return res.status(401).send('unauthorized');
  }
  res.json(User.findAll());
});
""",
        forbidden_cwes=("CWE-862",),
        notes="Explicit JS null-user auth guard should suppress missing-auth findings.",
        guard_family="auth-guard",
    ),
    QualityCase(
        case_id="py-nosql-injection-unsafe",
        language="python",
        filename="nosql_unsafe.py",
        snippet="""
from flask import request
from flask import Flask
import pymongo

app = Flask(__name__)
client = pymongo.MongoClient()
db = client['users']

@app.route('/find')
def find_user():
    username = request.args.get('user')
    result = db.users.find({'$where': f'this.username == "{username}"'})
    return str(list(result))
""",
        expected_cwes=("CWE-943",),
        notes="NoSQL injection via $where with user input should fire CWE-943.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-debug-traceback-unsafe",
        language="python",
        filename="debug_traceback.py",
        snippet="""
from flask import Flask
import traceback

app = Flask(__name__)
app.debug = True

@app.route('/crash')
def crash():
    try:
        1 / 0
    except Exception:
        return traceback.print_exc()
""",
        expected_cwes=("CWE-200",),
        expected_rule_ids=("PY-039",),
        notes="Debug mode with traceback exposure should fire CWE-200 / PY-039.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="js-nosql-injection-unsafe",
        language="javascript",
        filename="nosql_unsafe.js",
        js_backend="auto",
        snippet="""
const express = require('express');
const app = express();

app.post('/search', (req, res) => {
  const query = { $where: req.body.q };
  db.collection('items').find(query).toArray((err, items) => {
    res.json(items);
  });
});
""",
        expected_cwes=("CWE-943",),
        expected_rule_ids=("JS-051",),
        notes="NoSQL injection via $where operator with unsanitized input should fire CWE-943.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-command-injection-unsafe",
        language="python",
        filename="cmd_injection.py",
        snippet="""
from flask import request
import subprocess

def run():
    user_cmd = request.args.get('cmd')
    subprocess.call(user_cmd, shell=True)
""",
        expected_cwes=("CWE-78",),
        notes="Shell injection via subprocess with user input should fire CWE-78.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-eval-injection-unsafe",
        language="python",
        filename="eval_injection.py",
        snippet="""
from flask import request

def run():
    user = request.args.get('input')
    eval(user)
""",
        expected_cwes=("CWE-95",),
        notes="Code injection via eval with user input should fire CWE-95.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-ssrf-unsafe",
        language="python",
        filename="ssrf_unsafe.py",
        snippet="""
from flask import request
import requests

def fetch():
    url = request.args.get('url')
    return requests.get(url)
""",
        expected_cwes=("CWE-918",),
        notes="SSRF via requests.get with user input should fire CWE-918.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-deserialization-unsafe",
        language="python",
        filename="deserialize_unsafe.py",
        snippet="""
from flask import request
import pickle

def load():
    data = request.args.get('data')
    return pickle.loads(data)
""",
        expected_cwes=("CWE-502",),
        notes="Unsafe deserialization via pickle.loads should fire CWE-502.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-open-redirect-unsafe",
        language="python",
        filename="redirect_unsafe.py",
        snippet="""
from flask import request, redirect

def go():
    next_url = request.args.get('next')
    return redirect(next_url)
""",
        expected_cwes=("CWE-601",),
        notes="Open redirect via unvalidated next parameter should fire CWE-601.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-path-traversal-unsafe",
        language="python",
        filename="path_traversal.py",
        snippet="""
from flask import request
import os

def read():
    filename = request.args.get('file')
    path = os.path.join('/var/data', filename)
    with open(path) as f:
        return f.read()
""",
        expected_cwes=("CWE-22",),
        notes="Path traversal via user-controlled filename should fire CWE-22.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-weak-crypto-unsafe",
        language="python",
        filename="weak_crypto.py",
        snippet="""
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
""",
        expected_cwes=("CWE-327",),
        notes="Use of weak hash algorithm MD5 should fire CWE-327.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-hardcoded-secret-unsafe",
        language="python",
        filename="hardcoded_secret.py",
        snippet="""
API_SECRET = "sk-live-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
""",
        expected_cwes=("CWE-798",),
        notes="Hardcoded API secret key should fire CWE-798.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="js-redos-unsafe",
        language="javascript",
        filename="redos_unsafe.js",
        js_backend="classic",
        snippet="""
function validate(input) {
    const re = new RegExp('^(a+)+b$');
    return re.test(input);
}
""",
        expected_cwes=("CWE-1333",),
        notes="ReDoS-vulnerable regex pattern should fire CWE-1333.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-xss-unsafe",
        language="python",
        filename="xss_unsafe.py",
        snippet="""
from flask import request, render_template_string

def render():
    name = request.args.get('name')
    return render_template_string('<h1>Hello ' + name + '</h1>')
""",
        expected_cwes=("CWE-79",),
        expected_rule_ids=("PY-009",),
        notes="Reflected XSS via Flask render_template_string with user input should fire CWE-79.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-cleartext-logging-unsafe",
        language="python",
        filename="cleartext_logging.py",
        snippet="""
import logging
from flask import request

def login():
    password = request.form.get('password')
    logging.info('Login attempt with password: %s', password)
""",
        expected_cwes=("CWE-532",),
        expected_rule_ids=("PY-033",),
        notes="Logging sensitive data (password) should fire CWE-532.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="py-weak-prng-token",
        language="python",
        filename="weak_prng.py",
        snippet="""
import random

def generate_token():
    return str(random.randint(0, 999999))
""",
        expected_cwes=("CWE-338",),
        expected_rule_ids=("PY-018",),
        notes="Weak PRNG for security token generation should fire CWE-338.",
        guard_family="shadow-detector",
    ),
    # ── Phase B: CWE-306 / CWE-319 noise reduction cases ──────────────────────
    QualityCase(
        case_id="py-flask-login-required-quiet",
        language="python",
        filename="guarded_route.py",
        snippet="""
from flask import Flask, g
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.route('/dashboard')
@login_required
def dashboard():
    return {'user': g.user}
""",
        forbidden_cwes=("CWE-306", "CWE-319"),
        notes="Flask route with @login_required should not fire missing-auth or TLS noise.",
        guard_family="access-control",
    ),
    QualityCase(
        case_id="py-snippet-no-app-context-quiet",
        language="python",
        filename="bare_route.py",
        snippet="""
@app.route('/maybe_admin')
def maybe_admin():
    return do_stuff()
""",
        forbidden_cwes=("CWE-306",),
        forbidden_rule_ids=("PY-020",),
        notes="Bare route without full Flask app context should stay quiet for missing-auth.",
    ),
    QualityCase(
        case_id="py-hsts-missing-not-high",
        language="python",
        filename="flask_no_hsts.py",
        snippet="""
from flask import Flask

app = Flask(__name__)
app.config['PREFERRED_URL_SCHEME'] = 'http'

@app.route('/')
def index():
    return 'ok'
""",
        forbidden_cwes=("CWE-319",),
        notes="Missing HSTS/PREFERRED_URL_SCHEME=http should not produce HIGH finding after demotion.",
    ),
    # ── Phase C: Clean-repo contract cases ─────────────────────────────────────
    QualityCase(
        case_id="py-subprocess-list-safe",
        language="python",
        filename="safe_subprocess.py",
        snippet="""
import subprocess

def run_tool(tool_name):
    subprocess.run([tool_name, '--version'], shell=False, check=True)
""",
        forbidden_cwes=("CWE-78",),
        notes="subprocess.run with list args and shell=False should stay quiet.",
    ),
    QualityCase(
        case_id="py-yaml-safeload-safe",
        language="python",
        filename="safe_yaml.py",
        snippet="""
import yaml

def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)
""",
        forbidden_cwes=("CWE-502",),
        notes="yaml.safe_load should not fire deserialization warnings.",
    ),
    QualityCase(
        case_id="py-os-system-unsafe",
        language="python",
        filename="unsafe_os_system.py",
        snippet="""
from flask import request
import os

def run():
    user_cmd = request.args.get('cmd')
    os.system(user_cmd)
""",
        expected_cwes=("CWE-78",),
        notes="os.system with user input must still fire CWE-78.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="js-param-query-safe",
        language="javascript",
        filename="safe_param_query.js",
        js_backend="structural",
        snippet="""
const db = require('./db');

async function getUser(req, res) {
    const id = req.query.id;
    const user = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    res.json(user);
}
""",
        forbidden_cwes=("CWE-89",),
        notes="Parameterized query with placeholders should not fire CWE-89.",
    ),
    # ── Phase D: Guard modeling — Java / C# / Go auth guard suppression ────────
    QualityCase(
        case_id="java-spring-preauth-guarded",
        language="java",
        filename="SecureController.java",
        snippet="""
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userRepository.findById(id).orElse(null);
    }
}
""",
        forbidden_cwes=("CWE-862", "CWE-639", "CWE-285"),
        forbidden_rule_ids=("JV-001", "JV-002", "JV-003"),
        notes="Spring controller with @PreAuthorize at class level should suppress auth/IDOR findings.",
        guard_family="access-control",
    ),
    QualityCase(
        case_id="java-spring-unguarded",
        language="java",
        filename="OpenController.java",
        snippet="""
package com.example;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

@RestController
public class OpenController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/admin/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userRepository.findById(id).orElse(null);
    }
}
""",
        expected_cwes=("CWE-862",),
        expected_rule_ids=("JV-001",),
        notes="Spring controller without @PreAuthorize on /admin path should fire missing-auth.",
    ),
    QualityCase(
        case_id="csharp-authorize-guarded",
        language="csharp",
        filename="SecureController.cs",
        snippet="""
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        return Ok(user);
    }
}
""",
        forbidden_cwes=("CWE-862", "CWE-639"),
        forbidden_rule_ids=("CS-001", "CS-002"),
        notes="ASP.NET controller with [Authorize] should suppress auth/IDOR findings.",
        guard_family="access-control",
    ),
    QualityCase(
        case_id="csharp-unguarded-admin",
        language="csharp",
        filename="OpenController.cs",
        snippet="""
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/admin")]
public class OpenController : ControllerBase
{
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        return Ok(user);
    }
}
""",
        expected_cwes=("CWE-862",),
        expected_rule_ids=("CS-001",),
        notes="ASP.NET admin controller without [Authorize] should fire missing-auth.",
    ),
    QualityCase(
        case_id="go-gin-middleware-guarded",
        language="go",
        filename="secure_handler.go",
        snippet="""
package main

import (
    "net/http"
    "github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Next()
    }
}

func main() {
    r := gin.Default()
    r.Use(AuthMiddleware())
    r.GET("/admin/users", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{"users": []string{}})
    })
}
""",
        forbidden_cwes=("CWE-862",),
        notes="Go Gin handler behind AuthMiddleware should not fire missing-auth.",
        guard_family="access-control",
    ),
    # ── P0: Java PreparedStatement safe vs unsafe ────────────────────────────
    QualityCase(
        case_id="java-preparedstatement-safe",
        language="java",
        filename="SafeJdbc.java",
        snippet="""
import java.sql.*;

public class SafeJdbc {
    public User getUser(Connection conn, int id) throws SQLException {
        String sql = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new User(rs.getInt("id"), rs.getString("name"));
            }
            return null;
        }
    }
}
""",
        forbidden_cwes=("CWE-89",),
        forbidden_rule_ids=("JV-004",),
        notes="PreparedStatement with ? placeholders and setInt must NOT fire CWE-89.",
    ),
    QualityCase(
        case_id="java-statement-concat-unsafe",
        language="java",
        filename="UnsafeJdbc.java",
        snippet="""
import java.sql.*;

public class UnsafeJdbc {
    public User getUser(Connection conn, String name) throws SQLException {
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        if (rs.next()) {
            return new User(rs.getInt("id"), rs.getString("name"));
        }
        return null;
    }
}
""",
        expected_cwes=("CWE-89",),
        notes="String concatenation into SQL with Statement must still fire CWE-89.",
    ),
    # ── P1: Guard FP fixes ──────────────────────────────────────────────────
    QualityCase(
        case_id="csharp-antiforgery-no-auth-quiet",
        language="csharp",
        filename="AntiforgeryController.cs",
        snippet="""
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/profile")]
public class ProfileController : ControllerBase
{
    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult UpdateProfile(ProfileModel model)
    {
        _service.Update(model);
        return RedirectToAction("Index");
    }
}
""",
        forbidden_cwes=("CWE-862",),
        forbidden_rule_ids=("CS-001",),
        notes="ASP.NET with [ValidateAntiForgeryToken] should not fire missing-auth.",
        guard_family="access-control",
    ),
    # ── P2: Detection gap closures ───────────────────────────────────────────
    QualityCase(
        case_id="go-exec-command-shell-unsafe",
        language="go",
        filename="cmd_injection.go",
        snippet="""
package main

import "os/exec"

func run(userCmd string) {
    cmd := exec.Command("sh", "-c", userCmd)
    cmd.Run()
}
""",
        expected_cwes=("CWE-78",),
        notes="exec.Command with sh -c and user input should fire CWE-78.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="csharp-fromsqlraw-interp-unsafe",
        language="csharp",
        filename="EfCoreSqlInjection.cs",
        snippet="""
using Microsoft.EntityFrameworkCore;
using System.Linq;
using System.Threading.Tasks;

public class UserRepository
{
    private readonly AppDbContext _context;
    
    public async Task<User> GetUser(string username)
    {
        return await _context.Users
            .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'")
            .FirstOrDefaultAsync();
    }
}
""",
        expected_cwes=("CWE-89",),
        notes="FromSqlRaw with interpolated string should fire CWE-89.",
        guard_family="shadow-detector",
    ),
    # ── P2b: JS gap closures ─────────────────────────────────────────────────
    QualityCase(
        case_id="js-redirect-status-code-unsafe",
        language="javascript",
        filename="redirect_status.js",
        js_backend="structural",
        snippet="""
const express = require('express');
const app = express();

app.get('/go', (req, res) => {
    const dest = req.query.url;
    res.redirect(301, dest);
});
""",
        expected_cwes=("CWE-601",),
        notes="res.redirect(301, userUrl) with status code should fire CWE-601.",
        guard_family="shadow-detector",
    ),
    QualityCase(
        case_id="js-download-path-traversal-unsafe",
        language="javascript",
        filename="download_unsafe.js",
        js_backend="structural",
        snippet="""
const express = require('express');
const app = express();

app.get('/file', (req, res) => {
    const filename = req.query.file;
    res.download('/var/uploads/' + filename);
});
""",
        expected_cwes=("CWE-22",),
        notes="res.download with concatenated user path should fire CWE-22.",
        guard_family="shadow-detector",
    ),
)
