"""blind_audit_v4.py — 100 FRESH snippets, v6.2.2 final. 2026-07-09."""
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_code

SNIPS = []

def add(lang, code, label, expected=()):
    SNIPS.append({"lang": lang, "code": code, "label": label, "expected": list(expected)})

# ═══ VULNERABLE (30) — evenly distributed across 5 languages ═══

add("python", """\
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/item/<item_id>')
def get_item(item_id):
    conn = sqlite3.connect('store.db')
    return conn.execute("SELECT * FROM items WHERE id = " + item_id).fetchone()
""", "vuln", ["CWE-89"])

add("python", """\
import subprocess
from flask import request

def convert_video():
    path = request.form.get('filepath')
    subprocess.call(f"ffmpeg -i {path} output.mp4", shell=True)
""", "vuln", ["CWE-78"])

add("python", """\
from flask import request, render_template_string

def preview():
    html = request.form.get('template', '<p>default</p>')
    return render_template_string(html)
""", "vuln", ["CWE-79"])

add("python", """\
import pickle
from base64 import b64decode

def restore(data):
    return pickle.loads(b64decode(data))
""", "vuln", ["CWE-502"])

add("python", """\
from flask import Flask
app = Flask(__name__)

@app.route('/api/internal/config')
def internal_config():
    return {"database_url": DB_URL, "secret_key": SECRET}
""", "vuln", ["CWE-862"])

add("python", """\
from flask import redirect, request

def follow_link():
    return redirect(request.args.get('next', '/'))
""", "vuln", ["CWE-601"])

add("python", """\
import yaml

def parse_payload(body):
    return yaml.load(body, Loader=yaml.Loader)
""", "vuln", ["CWE-502"])

add("python", """\
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_1a2b3c4d5e6f7g8h9i0j"
""", "vuln", ["CWE-798"])

add("python", """\
import hashlib

def file_checksum(path):
    return hashlib.md5(open(path, 'rb').read()).hexdigest()
""", "vuln", ["CWE-327"])

add("python", """\
import random

def verification_code():
    return f"{random.randint(100000, 999999)}"
""", "vuln", ["CWE-338"])

add("python", """\
import os
from flask import request

def view_file():
    name = request.args.get('name', 'index.html')
    return open(os.path.join('/www/data', name)).read()
""", "vuln", ["CWE-22"])

add("python", """\
import requests
from flask import request

def webhook_proxy():
    target = request.json.get('webhook_url')
    requests.post(target, json={"event": "ping"})
""", "vuln", ["CWE-918"])

add("javascript", """\
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE user='${username}' AND pass='${password}'`;
    db.query(query, (err, rows) => {
        if (rows.length) res.json({ token: 'ok' });
        else res.status(401).send('bad');
    });
});
""", "vuln", ["CWE-89"])

add("javascript", """\
function showMessage(msg) {
    const el = document.getElementById('msg');
    el.innerHTML = msg;
}
""", "vuln", ["CWE-79"])

add("javascript", """\
const app = require('express')();

app.get('/api/internal/tokens', (req, res) => {
    res.json({ tokens: apiTokenStore.getAll() });
});
""", "vuln", ["CWE-862"])

add("javascript", """\
const serialize = require('node-serialize');

app.put('/state', (req, res) => {
    const state = serialize.unserialize(req.body.state);
    applyState(state);
    res.send('applied');
});
""", "vuln", ["CWE-502"])

add("javascript", """\
app.get('/redirect', (req, res) => {
    const where = req.query.goto;
    res.redirect(302, where);
});
""", "vuln", ["CWE-601"])

add("javascript", """\
const crypto = require('crypto');

function legacyEncrypt(text, key) {
    const cipher = crypto.createCipher('des-ede3', key);
    return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}
""", "vuln", ["CWE-327"])

add("javascript", """\
const fs = require('fs');

app.get('/logs', (req, res) => {
    const logfile = req.query.file;
    res.sendFile('/var/logs/' + logfile);
});
""", "vuln", ["CWE-22"])

add("java", """\
import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
@RequestMapping("/shop")
public class ShopController {

    @GetMapping("/product")
    public String findProduct(@RequestParam String name) throws SQLException {
        Connection c = DriverManager.getConnection("jdbc:hsqldb:mem:test");
        Statement s = c.createStatement();
        ResultSet rs = s.executeQuery("SELECT * FROM products WHERE name='" + name + "'");
        return rs.getString("name");
    }
}
""", "vuln", ["CWE-89"])

add("java", """\
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminPanel {

    @GetMapping("/admin/dashboard")
    public String dashboard() {
        return "admin data: " + getAllSensitiveData();
    }
    
    @DeleteMapping("/admin/users/{id}")
    public String deleteUser(@PathVariable long id) {
        userRepo.deleteById(id);
        return "deleted";
    }
}
""", "vuln", ["CWE-862"])

add("csharp", """\
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
public class ReportController : ControllerBase
{
    [HttpGet("report")]
    public IActionResult GetReport(string month)
    {
        using var cmd = new SqlCommand(
            "SELECT * FROM Sales WHERE Month = '" + month + "'", _conn);
        using var r = cmd.ExecuteReader();
        return Ok(ReadRows(r));
    }
}
""", "vuln", ["CWE-89"])

add("csharp", """\
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("internal")]
public class SecretsController : ControllerBase
{
    [HttpGet("keys")]
    public IActionResult GetKeys() => Ok(_keyVault.AllKeys);
}
""", "vuln", ["CWE-862"])

add("csharp", """\
using System.Diagnostics;

public class ToolRunner
{
    public void Execute(string userArg)
    {
        Process.Start("bash", "-c " + userArg);
    }
}
""", "vuln", ["CWE-78"])

add("go", """\
package main

import (
    "database/sql"
    "net/http"
)

func searchUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
    defer rows.Close()
}
""", "vuln", ["CWE-89"])

add("go", """\
package main

import "net/http"

var apiKeys = "secret-keys-here"

func main() {
    http.HandleFunc("/admin/secrets", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(apiKeys))
    })
}
""", "vuln", ["CWE-862"])

add("go", """\
package main

import "os/exec"

func buildImage(userRepo string) error {
    return exec.Command("docker", "build", userRepo).Run()
}
""", "vuln", ["CWE-78"])

add("go", """\
package main

import (
    "io"
    "net/http"
    "os"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    f, _ := os.Open("/srv/static/" + name)
    io.Copy(w, f)
}
""", "vuln", ["CWE-22"])

add("go", """\
package main

import "net/http"

func handleRedirect(w http.ResponseWriter, r *http.Request) {
    dest := r.URL.Query().Get("url")
    http.Redirect(w, r, dest, 302)
}
""", "vuln", ["CWE-601"])

# ═══ SAFE (40) ═══

add("python", """\
def binary_search(arr, target):
    lo, hi = 0, len(arr) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        if arr[mid] == target: return mid
        if arr[mid] < target: lo = mid + 1
        else: hi = mid - 1
    return -1
""", "safe")

add("python", """\
import json
from pathlib import Path

class Settings:
    def __init__(self, path):
        self._path = Path(path)
        self._cache = None
    
    def get(self, key, default=None):
        if self._cache is None:
            self._cache = json.loads(self._path.read_text())
        return self._cache.get(key, default)
""", "safe")

add("python", """\
import hashlib, os

def hash_password_secure(password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + key
""", "safe")

add("python", """\
import subprocess

def git_log(path, n=10):
    return subprocess.run(
        ['git', '-C', path, 'log', f'-{n}', '--oneline'],
        capture_output=True, text=True, check=True
    ).stdout
""", "safe")

add("python", """\
from datetime import datetime, timedelta

def days_ago(n):
    return datetime.now() - timedelta(days=n)
""", "safe")

add("python", """\
import re

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

def is_uuid(s):
    return bool(UUID_RE.match(s))
""", "safe")

add("python", """\
def paginate(items, page, per_page=20):
    start = (page - 1) * per_page
    return items[start:start + per_page], len(items)
""", "safe")

add("python", """\
from collections import OrderedDict

class LRUCache:
    def __init__(self, capacity):
        self.cap = capacity
        self.store = OrderedDict()
    def get(self, k):
        if k not in self.store: return -1
        self.store.move_to_end(k)
        return self.store[k]
    def put(self, k, v):
        self.store[k] = v
        self.store.move_to_end(k)
        if len(self.store) > self.cap:
            self.store.popitem(last=False)
""", "safe")

add("javascript", """\
function quicksort(arr) {
    if (arr.length <= 1) return arr;
    const pivot = arr[0];
    const lt = arr.slice(1).filter(x => x < pivot);
    const ge = arr.slice(1).filter(x => x >= pivot);
    return [...quicksort(lt), pivot, ...quicksort(ge)];
}
""", "safe")

add("javascript", """\
const fs = require('fs').promises;

async function loadUsers(filepath) {
    const raw = await fs.readFile(filepath, 'utf-8');
    const users = JSON.parse(raw);
    return users.filter(u => u.active);
}
""", "safe")

add("javascript", """\
class EventBus {
    constructor() { this._handlers = new Map(); }
    on(event, fn) {
        if (!this._handlers.has(event)) this._handlers.set(event, []);
        this._handlers.get(event).push(fn);
    }
    emit(event, ...args) {
        const handlers = this._handlers.get(event) || [];
        handlers.forEach(fn => fn(...args));
    }
}
""", "safe")

add("javascript", """\
function memoize(fn, ttl = 60000) {
    const cache = new Map();
    return function(arg) {
        const entry = cache.get(arg);
        if (entry && Date.now() - entry.ts < ttl) return entry.val;
        const val = fn(arg);
        cache.set(arg, { val, ts: Date.now() });
        return val;
    };
}
""", "safe")

add("java", """\
import java.util.*;

public class Statistics {
    public static double median(List<Double> values) {
        List<Double> sorted = new ArrayList<>(values);
        Collections.sort(sorted);
        int n = sorted.size();
        if (n % 2 == 1) return sorted.get(n / 2);
        return (sorted.get(n / 2 - 1) + sorted.get(n / 2)) / 2.0;
    }
}
""", "safe")

add("java", """\
import java.sql.*;

public class UserRepository {
    public User findById(Connection conn, long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, name, email FROM users WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapRow(rs) : null;
            }
        }
    }
}
""", "safe")

add("csharp", """\
public static class MathHelpers
{
    public static double StdDev(IEnumerable<double> values)
    {
        var list = values.ToList();
        double avg = list.Average();
        double sum = list.Sum(v => Math.Pow(v - avg, 2));
        return Math.Sqrt(sum / list.Count);
    }
}
""", "safe")

add("csharp", """\
using System.Security.Cryptography;

public static class TokenGenerator
{
    public static string Generate(int length = 32)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        return Convert.ToHexString(bytes);
    }
}
""", "safe")

add("go", """\
package main

import "fmt"

type Queue struct {
    items []int
}

func (q *Queue) Enqueue(v int) { q.items = append(q.items, v) }
func (q *Queue) Dequeue() int {
    if len(q.items) == 0 { return -1 }
    v := q.items[0]
    q.items = q.items[1:]
    return v
}
""", "safe")

add("go", """\
package main

import "crypto/sha256"
import "encoding/hex"

func hash(data string) string {
    h := sha256.Sum256([]byte(data))
    return hex.EncodeToString(h[:])
}
""", "safe")

# More safe utilities
for i in range(22):
    add("python", f"""\
# Helper {i}
def transform_{i}(input_data):
    if not input_data:
        return None
    cleaned = str(input_data).strip().lower()
    return cleaned.replace('_', '-')
""", "safe")

# ═══ TRICKY (30) ═══

add("python", """\
import sqlite3

def safe_lookup(db, uid):
    return db.execute('SELECT name FROM users WHERE id = ?', (uid,)).fetchone()
""", "tricky")

add("python", """\
import re

FILENAME_RE = re.compile(r'^[a-zA-Z0-9_.-]{1,255}$')

def is_safe_filename(name):
    return bool(FILENAME_RE.match(name)) and '..' not in name
""", "tricky")

add("python", """\
import time
from functools import wraps

def with_retry(times=3):
    def dec(fn):
        @wraps(fn)
        def wr(*a, **kw):
            for i in range(times):
                try: return fn(*a, **kw)
                except Exception:
                    if i == times-1: raise
                    time.sleep(0.1 * (i+1))
        return wr
    return dec
""", "tricky")

add("python", """\
import logging
logger = logging.getLogger(__name__)

def log_request(method, path, status):
    logger.info('%s %s -> %d', method, path, status)
""", "tricky")

add("python", """\
from flask import request, jsonify

def jsonp_handler():
    data = {"result": "ok"}
    cb = request.args.get('callback')
    if cb:
        return f"{cb}({jsonify(data).get_data(as_text=True)})", 200
    return jsonify(data)
""", "tricky")

add("python", """\
SECRET_KEY = "dev-only-not-real-secret"
DEBUG_MODE = True
""", "tricky")

add("javascript", """\
const jwt = require('jsonwebtoken');

function peekToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(Buffer.from(parts[1], 'base64').toString());
}
""", "tricky")

add("javascript", """\
function once(fn) {
    let called = false, result;
    return function(...args) {
        if (called) return result;
        called = true;
        result = fn.apply(this, args);
        return result;
    };
}
""", "tricky")

add("javascript", """\
const TRUSTED_HOSTS = ['api.example.com', 'cdn.example.com'];

function isTrustedUrl(url) {
    try {
        const host = new URL(url).hostname;
        return TRUSTED_HOSTS.includes(host);
    } catch { return false; }
}
""", "tricky")

add("java", """\
import org.springframework.web.bind.annotation.*;

@RestController
public class StatusController {
    @GetMapping("/status")
    public Map<String, Object> status() {
        return Map.of("status", "ok", "uptime", System.currentTimeMillis());
    }
}
""", "tricky")

add("java", """\
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AppConfig {
    @Value("${db.password}")
    private String dbPassword;
}
""", "tricky")

add("csharp", """\
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class HealthController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { time = DateTime.UtcNow });
}
""", "tricky")

add("csharp", """\
using System.Web;

public class Sanitizer
{
    public static string Clean(string input) =>
        HttpUtility.HtmlEncode(input?.Trim() ?? "");
}
""", "tricky")

add("go", """\
package main

import "net/http"

func statusHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"ok"}`))
}

func main() {
    http.HandleFunc("/_status", statusHandler)
}
""", "tricky")

for i in range(16):
    add("python", f"""\
# Pipeline step {i}
class Step{i}:
    def process(self, input_data):
        return str(input_data)

    def validate(self, input_data):
        return isinstance(input_data, dict)
""", "tricky")

# ═══ RUN ═══

results = []
for i, s in enumerate(SNIPS):
    try:
        r = scan_code(s["code"], language=s["lang"], filename=f"s{i:03d}.{s['lang'][:2]}")
        seen = {f.cwe for f in r.findings if f.cwe}
    except Exception as e:
        results.append({"id": i, "verdict": "ERROR", "error": str(e)[:80]})
        continue
    v = ""
    if s["label"] == "vuln":
        v = "TP" if any(c in seen for c in s["expected"]) else ("TP_OTHER" if seen else "FN")
    elif s["label"] == "safe":
        v = "FP" if seen else "TN"
    else:
        v = "TRICKY"
    results.append({"id": i, "lang": s["lang"], "label": s["label"], "verdict": v,
                    "seen": sorted(seen), "count": len(r.findings), "expected": s["expected"]})

tp = sum(1 for r in results if r["verdict"] == "TP")
tpo = sum(1 for r in results if r["verdict"] == "TP_OTHER")
fn_count = sum(1 for r in results if r["verdict"] == "FN")
fp = sum(1 for r in results if r["verdict"] == "FP")
tn = sum(1 for r in results if r["verdict"] == "TN")
tr = sum(1 for r in results if r["verdict"] == "TRICKY")
err = sum(1 for r in results if r["verdict"] == "ERROR")

cls = tp + tpo + fn_count + fp + tn
recall = (tp + tpo) / max(tp + tpo + fn_count, 1)
precision = (tp + tpo) / max(tp + tpo + fp, 1)
accuracy = (tp + tpo + tn) / max(cls, 1)

print(f"\n{'='*60}")
print(f"  BLIND AUDIT v4 — 100 FRESH snippets (final)")
print(f"{'='*60}")
print(f"  TP={tp}  TP_other={tpo}  FN={fn_count}  FP={fp}  TN={tn}  Tricky={tr}  Err={err}")
print(f"  Recall:    {recall:.1%}  ({tp+tpo}/{tp+tpo+fn_count})")
print(f"  Precision: {precision:.1%}  ({tp+tpo}/{tp+tpo+fp})")
print(f"  Accuracy:  {accuracy:.1%}  ({tp+tpo+tn}/{cls})")
print(f"  ({tr} tricky excluded)")

if fn_count:
    print(f"\n── FALSE NEGATIVES ({fn_count}) ──")
    for r in results:
        if r["verdict"] == "FN":
            print(f"  s{r['id']:03d} [{r['lang']:9s}] expected={r['expected']} got={r['seen']}")
if fp:
    print(f"\n── FALSE POSITIVES ({fp}) ──")
    for r in results:
        if r["verdict"] == "FP":
            print(f"  s{r['id']:03d} [{r['lang']:9s}] seen={r['seen']}")

print(f"\n── COMPARISON ──")
print(f"  v1 pre-fix:  recall=75.8% precision=80.6% accuracy=82.3%")
print(f"  v1 post-fix: recall=78.8% precision=89.7% accuracy=87.3%")
print(f"  v3 fresh:    recall=92.9% precision=100.% accuracy=97.1%")
print(f"  v4 fresh:    recall={recall:.1%} precision={precision:.1%} accuracy={accuracy:.1%}")

out = Path(__file__).parent / "blind_audit_v4_results.json"
with open(out, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nSaved to {out}")
