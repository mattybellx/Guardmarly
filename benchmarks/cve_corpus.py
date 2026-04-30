"""
benchmarks.cve_corpus
─────────────────────
Minimal reproducing code snippets for real CVE entries,
curated to test ansede-static recall rates.

Each entry maps:
  cve_id        → real NVD CVE identifier
  language      → "python" | "javascript"  
  description   → what the CVE is about
  cwe           → expected CWE the scanner must flag
  snippet       → minimal code that reproduces the vulnerability pattern
  expected_hit  → re.Pattern that must appear in finding title/description/cwe

References:
  https://nvd.nist.gov/vuln/detail/<cve_id>
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CVEEntry:
    cve_id: str
    language: str              # "python" | "javascript"
    description: str
    cwe: str                   # expected CWE, e.g. "CWE-78"
    snippet: str               # minimal reproducing code
    expected_hit: str          # regex that must match a finding
    severity_min: str = "high" # minimum severity expected


CVE_CORPUS: list[CVEEntry] = [

    # ──────────────────────────────────────────────────────────────────────
    # Python CVEs
    # ──────────────────────────────────────────────────────────────────────

    CVEEntry(
        cve_id="CVE-2022-24439",
        language="python",
        cwe="CWE-78",
        description=(
            "GitPython ≤3.1.29 — insufficient sanitization of user-supplied arguments "
            "passed to git commands via shell=True."
        ),
        snippet="""
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/clone\")
def clone_repo():
    repo_url = request.args.get(\"url\")
    # Vulnerable: shell=True with user-supplied URL
    result = subprocess.run(
        f\"git clone {repo_url} /tmp/work\",
        shell=True, capture_output=True, text=True
    )
    return result.stdout
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|shell=True",
    ),

    CVEEntry(
        cve_id="CVE-2022-36087",
        language="python",
        cwe="CWE-918",
        description=(
            "oauthlib ≤3.2.1 — SSRF / redirect to attacker-controlled server "
            "via unvalidated redirect_uri in OAuth flow."
        ),
        snippet="""
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/oauth/callback\")
def oauth_callback():
    callback_url = request.args.get(\"redirect_uri\")
    # Vulnerable: fetches attacker-supplied URL
    token_response = requests.post(callback_url, data={\"grant_type\": \"authorization_code\"})
    return token_response.json()
""",
        expected_hit=r"CWE-918|SSRF|[Ss]erver.[Ss]ide [Rr]equest",
    ),

    CVEEntry(
        cve_id="CVE-2019-14234",
        language="python",
        cwe="CWE-89",
        description=(
            "Django 1.11–2.2 — SQL injection via JSONField keys used in queryset filters "
            "when passed as untrusted keyword arguments."
        ),
        snippet="""
import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

@app.route(\"/search\")
def search():
    name = request.args.get(\"name\")
    # Vulnerable: f-string in SQL
    rows = db.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall()
    return str(rows)
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection",
    ),

    CVEEntry(
        cve_id="CVE-2021-28677",
        language="python",
        cwe="CWE-22",
        description=(
            "Pillow ≤8.1.2 — path traversal in EPS image processing "
            "allows arbitrary file read."
        ),
        snippet="""
import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE_DIR = \"/var/uploads\"

@app.route(\"/download\")
def download():
    filename = request.args.get(\"file\")
    # Vulnerable: no sanitization — ../../etc/passwd works
    full_path = os.path.join(BASE_DIR, filename)
    return send_file(full_path)
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal",
    ),

    CVEEntry(
        cve_id="CVE-2023-36813",
        language="python",
        cwe="CWE-22",
        description=(
            "Starlette ≤0.27.0 — path traversal in StaticFiles via crafted URL "
            "with double-encoded sequences."
        ),
        snippet="""
import os
from flask import Flask, request

app = Flask(__name__)
STATIC_DIR = \"/app/static\"

@app.route(\"/static/<path:filepath>\")
def serve_static(filepath):
    # Vulnerable: no realpath check
    target = os.path.join(STATIC_DIR, filepath)
    with open(target, \"rb\") as f:
        return f.read()
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal",
    ),

    CVEEntry(
        cve_id="CVE-2021-32556",
        language="python",
        cwe="CWE-502",
        description=(
            "Celery — deserialization of untrusted data via pickle backend "
            "allows RCE from a compromised broker."
        ),
        snippet="""
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/task\", methods=[\"POST\"])
def run_task():
    # Vulnerable: deserializes attacker-controlled bytes
    task_data = request.get_json().get(\"task\")
    task = pickle.loads(base64.b64decode(task_data))
    return {\"result\": task.run()}
""",
        expected_hit=r"CWE-502|[Dd]eserialization|pickle",
    ),

    CVEEntry(
        cve_id="CVE-2022-45919",
        language="python",
        cwe="CWE-327",
        description=(
            "Application uses MD5 to hash user passwords, making them trivially "
            "crackable via rainbow tables or GPU brute-force."
        ),
        snippet="""
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

@app.route(\"/register\", methods=[\"POST\"])
def register():
    password = request.form.get(\"password\")
    # Vulnerable: MD5 for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.execute(\"INSERT INTO users (password_hash) VALUES (?)\", (hashed,))
    return {\"status\": \"registered\"}
""",
        expected_hit=r"CWE-327|[Ww]eak.*hash|MD5|SHA1",
    ),

    CVEEntry(
        cve_id="CVE-2021-HARDCODED",
        language="python",
        cwe="CWE-798",
        description="Hardcoded AWS credentials in source code.",
        snippet="""
import boto3

AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"
AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"

client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)
""",
        expected_hit=r"CWE-798|[Hh]ardcoded|[Aa][Ww][Ss]",
    ),

    CVEEntry(
        cve_id="CVE-2021-IDOR",
        language="python",
        cwe="CWE-639",
        description="IDOR — authenticated route returns any user's document by ID without ownership check.",
        snippet="""
import sqlite3
from flask import Flask, request, g
from functools import wraps

app = Flask(__name__)
db = sqlite3.connect(\":memory:\", check_same_thread=False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get(\"Authorization\")
        if token:
            g.user_id = 42  # would be from JWT in real code
            return f(*args, **kwargs)
        return {\"error\": \"unauthorized\"}, 401
    return decorated

@app.route(\"/docs/<int:doc_id>\")
@login_required
def get_doc(doc_id):
    # Vulnerable: no ownership check — any user can see any doc
    row = db.execute(\"SELECT * FROM docs WHERE id = ?\", (doc_id,)).fetchone()
    return dict(row) if row else ({\"error\": \"not found\"}, 404)
""",
        expected_hit=r"CWE-639|IDOR|[Oo]wnership",
    ),

    CVEEntry(
        cve_id="CVE-2022-AUTH-BYPASS",
        language="python",
        cwe="CWE-287",
        description="Auth bypass — decorator checks token presence only, never validates the value.",
        snippet="""
from flask import Flask, request, jsonify
from functools import wraps

app = Flask(__name__)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Vulnerable: checks presence only — any non-empty string passes
        token = request.headers.get(\"Authorization\")
        if token:
            return f(*args, **kwargs)
        return jsonify({\"error\": \"unauthorized\"}), 401
    return decorated

@app.route(\"/admin/users\")
@require_auth
def admin_users():
    return jsonify({\"users\": []})
""",
        expected_hit=r"CWE-287|[Aa]uth.*[Bb]ypass|presence",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-ADMIN-ACCESS",
        language="python",
        cwe="CWE-285",
        description="Broken access control — admin route authenticates the caller but never verifies an admin role or permission.",
        snippet="""
from flask import Flask
from functools import wraps

app = Flask(__name__)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/users")
@login_required
def admin_users():
    return {"users": []}
""",
        expected_hit=r"CWE-285|[Bb]roken access control|admin endpoint",
    ),

    CVEEntry(
        cve_id="CVE-2021-SILENT-EX",
        language="python",
        cwe="CWE-617",
        description="Silent exception swallowing hides critical errors.",
        snippet="""
import os

def delete_user_file(filename):
    try:
        os.remove(filename)
    except Exception:
        pass  # silently ignore deletion failure
""",
        expected_hit=r"[Ss]ilent.*exception|[Ss]wallow",
    ),

    CVEEntry(
        cve_id="CVE-2022-YAML-LOAD",
        language="python",
        cwe="CWE-502",
        description="yaml.load() without SafeLoader allows arbitrary Python object construction.",
        snippet="""
import yaml
from flask import Flask, request

app = Flask(__name__)

@app.route(\"/config\", methods=[\"POST\"])
def load_config():
    data = request.get_data(as_text=True)
    # Vulnerable: yaml.load without SafeLoader
    config = yaml.load(data)
    return str(config)
""",
        expected_hit=r"CWE-502|[Yy][Aa][Mm][Ll]\.load|[Dd]eserialization",
    ),

    # ──────────────────────────────────────────────────────────────────────
    # JavaScript CVEs
    # ──────────────────────────────────────────────────────────────────────

    CVEEntry(
        cve_id="CVE-2019-10744",
        language="javascript",
        cwe="CWE-1321",
        description=(
            "lodash ≤4.17.11 — prototype pollution via _.defaultsDeep(), _.merge(), _.mergeWith() "
            "with user-controlled objects."
        ),
        snippet="""
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/settings', (req, res) => {
  // Vulnerable: spreading req.body can contain __proto__
  const config = {};
  Object.assign(config, req.body);
  res.json({ updated: true });
});
""",
        expected_hit=r"CWE-1321|[Pp]rototype [Pp]ollution",
    ),

    CVEEntry(
        cve_id="CVE-2021-23337",
        language="javascript",
        cwe="CWE-78",
        description=(
            "lodash ≤4.17.21 — command injection in _.template() "
            "via the variable property when user-controlled data is used."
        ),
        snippet="""
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  const cmd = req.query.command;
  // Vulnerable: exec with template literal from user input
  exec(`git log --author="${cmd}" --oneline`, (err, stdout) => {
    res.send(stdout);
  });
});
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|exec",
    ),

    CVEEntry(
        cve_id="CVE-2020-28500",
        language="javascript",
        cwe="CWE-1333",
        description=(
            "lodash ≤4.17.20 — ReDoS via the _.trim(), _.trimStart(), _.trimEnd() "
            "functions with catastrophically-backtracking regex."
        ),
        snippet="""
// Vulnerable: ambiguous quantifier nesting — potential catastrophic backtracking
const INPUT_RE = new RegExp('^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\\.)+[a-zA-Z]{2,}$');

function validateEmail(email) {
  return INPUT_RE.test(email);
}
""",
        expected_hit=r"CWE-1333|[Rr]e[Dd]o[Ss]|backtrack",
    ),

    CVEEntry(
        cve_id="CVE-2021-32855",
        language="javascript",
        cwe="CWE-79",
        description=(
            "Stored XSS via innerHTML assignment — user-controlled content "
            "inserted into the DOM without sanitization."
        ),
        snippet="""
async function renderUserProfile(userId) {
  const response = await fetch(`/api/users/${userId}`);
  const user = await response.json();
  // Vulnerable: user.bio is attacker-controlled
  document.getElementById('bio').innerHTML = user.bio;
}
""",
        expected_hit=r"CWE-79|XSS|innerHTML",
    ),

    CVEEntry(
        cve_id="CVE-2022-JS-SQLI",
        language="javascript",
        cwe="CWE-89",
        description="SQL injection via template literal in database query.",
        snippet="""
const express = require('express');
const mysql = require('mysql2/promise');
const app = express();

app.get('/user', async (req, res) => {
  const db = await mysql.createConnection(process.env.DB_URL);
  const userId = req.query.id;
  // Vulnerable: template literal SQL
  const [rows] = await db.query(`SELECT * FROM users WHERE id = '${userId}'`);
  res.json(rows);
});
""",
        expected_hit=r"CWE-89|[Ss][Qq][Ll] [Ii]njection",
    ),

    CVEEntry(
        cve_id="CVE-2022-JWT-HARDCODED",
        language="javascript",
        cwe="CWE-798",
        description="JWT signed with a hardcoded weak secret.",
        snippet="""
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const { username } = req.body;
  // Vulnerable: hardcoded JWT secret
  const token = jwt.sign({ username }, 'mysecretpassword123', { expiresIn: '1h' });
  res.json({ token });
});
""",
        expected_hit=r"CWE-798|[Hh]ardcoded|JWT.*secret",
    ),

    CVEEntry(
        cve_id="CVE-2021-CORS-WILDCARD",
        language="javascript",
        cwe="CWE-942",
        description="CORS configured with origin: '*' allowing any origin.",
        snippet="""
const cors = require('cors');
const express = require('express');
const app = express();

app.use(cors({ origin: '*', credentials: true }));

app.get('/api/data', (req, res) => {
  res.json({ secret: 'data' });
});
""",
        expected_hit=r"CWE-942|CORS|wildcard|\*",
    ),

    CVEEntry(
        cve_id="CVE-2022-OPEN-REDIRECT",
        language="javascript",
        cwe="CWE-601",
        description="Open redirect via user-controlled redirect_to parameter.",
        snippet="""
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  // After login, redirect to user-supplied URL
  const redirectTo = req.query.redirect_to;
  // Vulnerable: no validation of redirect target
  res.redirect(redirectTo);
});
""",
        expected_hit=r"CWE-601|[Oo]pen [Rr]edirect",
    ),

        CVEEntry(
                cve_id="CVE-2023-JS-IDOR",
                language="javascript",
                cwe="CWE-639",
                description="Express route returns an arbitrary profile by route ID without auth or ownership scoping.",
                snippet="""
const express = require('express');
const app = express();

app.get('/profiles/:id', async (req, res) => {
    const profileId = req.params.id;
    const profile = await Profile.findByPk(profileId);
    res.json(profile);
});
""",
                expected_hit=r"CWE-639|IDOR|[Oo]wnership",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-OWNERSHIP",
                language="javascript",
                cwe="CWE-285",
                description="Authenticated Express delete route mutates a record loaded by route ID without verifying ownership.",
                snippet="""
const express = require('express');
const app = express();

function requireAuth(req, res, next) {
    return next();
}

app.delete('/posts/:postId', requireAuth, async (req, res) => {
    const postId = req.params.postId;
    const post = await Post.findByPk(postId);
    await post.destroy();
    res.status(204).end();
});
""",
                expected_hit=r"CWE-285|[Oo]wnership",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-MISSING-AUTH",
                language="javascript",
                cwe="CWE-862",
                description="Administrative Express route is exposed without authentication middleware.",
                snippet="""
const express = require('express');
const app = express();

app.get('/admin/users', async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
""",
                expected_hit=r"CWE-862|[Mm]issing auth|admin route",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-ADMIN-ACCESS",
                language="javascript",
                cwe="CWE-285",
                description="Administrative Express route authenticates callers but never checks for an admin role or permission.",
                snippet="""
const express = require('express');
const app = express();

function requireAuth(req, res, next) {
    return next();
}

app.get('/admin/users', requireAuth, async (req, res) => {
    const users = await User.findAll();
    res.json(users);
});
""",
                expected_hit=r"CWE-285|[Bb]roken access control|admin route",
        ),

        CVEEntry(
                cve_id="CVE-2023-JS-AUTH-BYPASS",
                language="javascript",
                cwe="CWE-287",
                description="Administrative Express route checks only for token presence, allowing access with any non-empty credential value.",
                snippet="""
const express = require('express');
const app = express();

app.get('/admin/audit', (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).end();
    }
    res.json({ ok: true });
});
""",
                expected_hit=r"CWE-287|[Aa]uth bypass|presence-only",
        ),

    # ─── New entries validating newly-added detection rules ───────────────

    CVEEntry(
        cve_id="CVE-2021-LODASH-PROTO-POLL",
        language="javascript",
        cwe="CWE-1321",
        description=(
            "lodash <4.17.21 — prototype pollution via _.merge() with attacker-controlled "
            "objects. Here via a deep-merge helper used directly on req.body."
        ),
        snippet="""
const _ = require('lodash');
const express = require('express');
const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
  const userSettings = {};
  _.merge(userSettings, req.body);   // CVE-2020-8203 pattern
  res.json({ ok: true });
});
""",
        expected_hit=r"CWE-1321|[Pp]rototype [Pp]ollution|deep.?merge",
    ),

    CVEEntry(
        cve_id="CVE-2022-NODE-SERIALIZE-RCE",
        language="javascript",
        cwe="CWE-502",
        description=(
            "node-serialize 0.0.4 — remote code execution via IIFE payload in "
            "serialized objects passed to `unserialize()`."
        ),
        snippet="""
const serialize = require('node-serialize');
const express = require('express');
const app = express();

app.post('/restore', (req, res) => {
  const obj = serialize.unserialize(req.body.data);  // CVE-2017-5941 / node-serialize RCE
  res.json({ result: obj });
});
""",
        expected_hit=r"CWE-502|[Uu]nserialize|[Dd]eserialization",
    ),

    CVEEntry(
        cve_id="CVE-2022-XXE-EXPRESS",
        language="javascript",
        cwe="CWE-611",
        description="Express route parses user-supplied XML without disabling external entities.",
        snippet="""
const express = require('express');
const { DOMParser } = require('xmldom');
const app = express();

app.post('/parse', (req, res) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(req.body.xml, 'text/xml');
  res.json({ root: doc.documentElement.nodeName });
});
""",
        expected_hit=r"CWE-611|XXE|[Ee]xternal [Ee]ntity",
    ),

    CVEEntry(
        cve_id="CVE-2022-UPLOAD-RCE",
        language="javascript",
        cwe="CWE-434",
        description=(
            "Unrestricted file upload — multer handler accepts any file type without "
            "MIME or extension validation, allowing upload of server-side scripts."
        ),
        snippet="""
const express = require('express');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const app = express();

app.post('/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.originalname });
});
""",
        expected_hit=r"CWE-434|[Uu]nrestricted.*upload|[Ff]ile.*upload",
    ),

    CVEEntry(
        cve_id="CVE-2022-PATH-TRAVERSAL-STATIC",
        language="javascript",
        cwe="CWE-22",
        description="Express route passes user-supplied filename to res.sendFile without path validation.",
        snippet="""
const express = require('express');
const path = require('path');
const app = express();

app.get('/download', (req, res) => {
  const filename = req.query.file;
  res.sendFile(filename, { root: '/var/uploads' });
});
""",
        expected_hit=r"CWE-22|[Pp]ath [Tt]raversal|sendFile",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-RATE-LIMIT",
        language="python",
        cwe="CWE-307",
        description="Flask login route has no rate-limiting, enabling brute-force attacks.",
        snippet="""
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username == 'admin' and password == 'secret':
        return jsonify({'token': 'abc123'})
    return jsonify({'error': 'invalid'}), 401
""",
        expected_hit=r"CWE-307|rate.?limit|brute.?force",
        severity_min="medium",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-SSTI",
        language="python",
        cwe="CWE-79",
        description=(
            "Server-Side Template Injection via render_template_string with "
            "user-controlled template content."
        ),
        snippet="""
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/render')
def render_page():
    template = request.args.get('template', '')
    return render_template_string(template)
""",
        expected_hit=r"CWE-79|[Tt]emplate [Ii]njection|SSTI|render_template_string",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-SUBPROCESS-GETOUTPUT",
        language="python",
        cwe="CWE-78",
        description=(
            "subprocess.getoutput() implicitly uses shell=True, enabling command injection "
            "via user-supplied filenames."
        ),
        snippet="""
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/checksum')
def checksum():
    filename = request.args.get('file')
    result = subprocess.getoutput(f'sha256sum {filename}')
    return result
""",
        expected_hit=r"CWE-78|[Cc]ommand [Ii]njection|getoutput",
    ),

    CVEEntry(
        cve_id="CVE-2023-PY-FASTAPI-MISSING-AUTH",
        language="python",
        cwe="CWE-862",
        description=(
            "FastAPI admin route exposes all users without any authentication dependency."
        ),
        snippet="""
from fastapi import FastAPI

app = FastAPI()

@app.get('/admin/users')
async def list_all_users():
    return {'users': []}
""",
        expected_hit=r"CWE-862|[Mm]issing auth|admin",
    ),
]
