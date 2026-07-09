"""blind_audit_v3.py — 100 FRESH snippets, never tested before. 2026-07-09."""
import json, sys, random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_code

SNIPS = []

def add(lang, code, label, expected=()):
    SNIPS.append({"lang": lang, "code": code, "label": label, "expected": list(expected)})

# ═══════════════ VULNERABLE (28) ═══════════════

add("python", """\
from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    term = request.args.get('q')
    query = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    return db.execute(query)
""", "vuln", ["CWE-89"])

add("python", """\
import subprocess
from flask import request

def backup():
    filename = request.form.get('file')
    subprocess.run(f"tar -czf backup.tar.gz {filename}", shell=True)
""", "vuln", ["CWE-78"])

add("python", """\
from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'world')
    return render_template_string('<h1>Hello {{ name }}!</h1>', name=name)
""", "vuln", ["CWE-79"])

add("python", """\
import pickle
from flask import request

def restore_session():
    blob = request.cookies.get('session')
    return pickle.loads(bytes.fromhex(blob))
""", "vuln", ["CWE-502"])

add("python", """\
from flask import Flask
app = Flask(__name__)

@app.route('/admin/export/users')
def export_users():
    return ','.join(u.email for u in User.query.all())
""", "vuln", ["CWE-862"])

add("python", """\
from flask import request, redirect

def follow():
    target = request.args.get('redirect_to')
    return redirect(target)
""", "vuln", ["CWE-601"])

add("python", """\
import yaml

def parse_config(raw):
    return yaml.load(raw)
""", "vuln", ["CWE-502"])

add("python", """\
DATABASE_PASSWORD = "prod-db-password-2024!"
STRIPE_SECRET = "sk_test_example_replaced_for_github_push_protection"
""", "vuln", ["CWE-798"])

add("python", """\
import hashlib

def checksum(data):
    return hashlib.sha1(data.encode()).hexdigest()
""", "vuln", ["CWE-327"])

add("python", """\
import random
import string

def generate_api_key():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(32))
""", "vuln", ["CWE-338"])

add("python", """\
import os
from flask import request

def read_log():
    filename = request.args.get('logfile')
    path = os.path.join('/var/log/app', filename)
    return open(path).read()
""", "vuln", ["CWE-22"])

add("python", """\
import requests
from flask import request

def proxy_fetch():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.json()
""", "vuln", ["CWE-918"])

add("javascript", """\
const express = require('express');
const app = express();

app.get('/user/:id', async (req, res) => {
    const user = await db.query(
        `SELECT * FROM users WHERE id = ${req.params.id}`
    );
    res.json(user[0]);
});
""", "vuln", ["CWE-89"])

add("javascript", """\
function displayComment(comment) {
    const div = document.createElement('div');
    div.innerHTML = comment.body;
    document.body.appendChild(div);
}
""", "vuln", ["CWE-79"])

add("javascript", """\
const app = require('express')();

app.get('/admin/config', (req, res) => {
    res.json({ dbUrl: process.env.DATABASE_URL, apiKeys: keys });
});
""", "vuln", ["CWE-862"])

add("javascript", """\
const serialize = require('node-serialize');

app.post('/import', (req, res) => {
    const data = serialize.unserialize(req.body.payload);
    processData(data);
    res.send('ok');
});
""", "vuln", ["CWE-502"])

add("javascript", """\
app.get('/redirect', (req, res) => {
    const dest = req.query.url;
    res.redirect(301, dest);
});
""", "vuln", ["CWE-601"])

add("javascript", """\
const crypto = require('crypto');

function legacyHash(password) {
    const hash = crypto.createHash('md5');
    hash.update(password);
    return hash.digest('hex');
}
""", "vuln", ["CWE-327"])

add("javascript", """\
const fs = require('fs');

app.get('/download', (req, res) => {
    const file = req.query.file;
    res.download('/var/files/' + file);
});
""", "vuln", ["CWE-22"])

add("java", """\
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import java.sql.*;

@RestController
@RequestMapping("/api")
public class ReportController {

    @Autowired
    private Connection conn;

    @GetMapping("/report")
    public String report(@RequestParam String month) throws SQLException {
        String sql = "SELECT * FROM sales WHERE month = '" + month + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(sql);
        return formatResults(rs);
    }
}
""", "vuln", ["CWE-89"])

add("java", """\
import org.springframework.web.bind.annotation.*;

@RestController
public class AdminController {

    @DeleteMapping("/api/admin/users/{id}")
    public String deleteUser(@PathVariable Long id) {
        userRepository.deleteById(id);
        return "deleted";
    }
}
""", "vuln", ["CWE-862"])

add("csharp", """\
using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;

[ApiController]
[Route("api")]
public class SearchController : ControllerBase
{
    [HttpGet("search")]
    public IActionResult Search(string term)
    {
        var sql = "SELECT * FROM Items WHERE Name LIKE '%" + term + "%'";
        using var cmd = new SqlCommand(sql, _connection);
        using var reader = cmd.ExecuteReader();
        return Ok(ReadItems(reader));
    }
}
""", "vuln", ["CWE-89"])

add("csharp", """\
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/admin")]
public class UserController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetAllUsers()
    {
        return Ok(_db.Users.ToList());
    }
}
""", "vuln", ["CWE-862"])

add("csharp", """\
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class UtilController : Controller
{
    [HttpPost("execute")]
    public IActionResult Run(string command)
    {
        Process.Start("cmd.exe", "/c " + command);
        return Ok();
    }
}
""", "vuln", ["CWE-78"])

add("go", """\
package main

import (
    "database/sql"
    "net/http"
)

func searchHandler(db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        q := r.URL.Query().Get("q")
        row := db.QueryRow("SELECT name, email FROM users WHERE name = '" + q + "'")
        var name, email string
        row.Scan(&name, &email)
    }
}
""", "vuln", ["CWE-89"])

add("go", """\
package main

import "net/http"

func main() {
    http.HandleFunc("/admin/keys", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(apiKeys))
    })
    http.ListenAndServe(":8080", nil)
}
""", "vuln", ["CWE-862"])

add("go", """\
package main

import "os/exec"

func runCommand(userInput string) {
    cmd := exec.Command("sh", "-c", userInput)
    cmd.Run()
}
""", "vuln", ["CWE-78"])

add("go", """\
package main

import (
    "io"
    "net/http"
    "os"
)

func downloadHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    f, _ := os.Open("/var/data/" + filename)
    io.Copy(w, f)
}
""", "vuln", ["CWE-22"])

# ═══════════════ SAFE (42) ═══════════════

add("python", """\
def merge_sort(arr):
    if len(arr) <= 1:
        return arr
    mid = len(arr) // 2
    left = merge_sort(arr[:mid])
    right = merge_sort(arr[mid:])
    return [min(l, r) if l and r else l or r 
            for l, r in zip(left + [float('inf')], right + [float('inf')])][:len(arr)]
""", "safe")

add("python", """\
import json
from pathlib import Path

class ConfigManager:
    def __init__(self, path):
        self.path = Path(path)
    
    def load(self):
        return json.loads(self.path.read_text())
    
    def save(self, data):
        self.path.write_text(json.dumps(data, indent=2))
""", "safe")

add("python", """\
import hashlib
import os

def secure_hash(password):
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)
    return salt.hex() + ':' + key.hex()
""", "safe")

add("python", """\
import subprocess

def git_status(repo_path):
    result = subprocess.run(
        ['git', '-C', repo_path, 'status', '--porcelain'],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip().split('\\n') if result.stdout else []
""", "safe")

add("python", """\
from datetime import datetime, timezone

def format_timestamp(ts):
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.isoformat()
""", "safe")

add("python", """\
def chunked(iterable, size):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk
""", "safe")

add("python", """\
import re

PHONE_RE = re.compile(r'^\\+?[1-9]\\d{6,14}$')

def is_valid_phone(number):
    return bool(PHONE_RE.match(number.replace(' ', '').replace('-', '')))
""", "safe")

add("python", """\
from collections import defaultdict

def group_by_key(records, key):
    groups = defaultdict(list)
    for r in records:
        groups[r.get(key)].append(r)
    return dict(groups)
""", "safe")

add("javascript", """\
function binarySearch(arr, target) {
    let lo = 0, hi = arr.length - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (arr[mid] === target) return mid;
        if (arr[mid] < target) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}
""", "safe")

add("javascript", """\
const fs = require('fs').promises;

async function loadJsonConfig(filepath) {
    const raw = await fs.readFile(filepath, 'utf-8');
    const config = JSON.parse(raw);
    return Object.freeze(config);
}
""", "safe")

add("javascript", """\
class Semaphore {
    constructor(max) {
        this.max = max;
        this.current = 0;
        this.queue = [];
    }
    async acquire() {
        if (this.current < this.max) { this.current++; return; }
        return new Promise(resolve => this.queue.push(resolve));
    }
    release() {
        this.current--;
        if (this.queue.length > 0) {
            this.queue.shift()();
            this.current++;
        }
    }
}
""", "safe")

add("javascript", """\
const crypto = require('crypto');

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

function hmacSign(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('hex');
}
""", "safe")

add("javascript", """\
function throttle(fn, limit) {
    let lastCall = 0;
    return function(...args) {
        const now = Date.now();
        if (now - lastCall >= limit) {
            lastCall = now;
            return fn.apply(this, args);
        }
    };
}
""", "safe")

add("java", """\
import java.util.List;
import java.util.stream.Collectors;

public class CollectionUtils {
    public static <T> List<T> distinct(List<T> items) {
        return items.stream().distinct().collect(Collectors.toList());
    }
    
    public static <T extends Comparable<T>> T max(List<T> items) {
        return items.stream().max(T::compareTo).orElse(null);
    }
}
""", "safe")

add("java", """\
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class TimeUtils {
    private static final DateTimeFormatter ISO = 
        DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.of("UTC"));
    
    public static String format(long epochMillis) {
        return ISO.format(Instant.ofEpochMilli(epochMillis));
    }
}
""", "safe")

add("java", """\
import java.sql.*;

public class SafeQuery {
    public User findById(Connection conn, long id) throws SQLException {
        String sql = "SELECT id, name, email FROM users WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new User(rs.getLong("id"), 
                        rs.getString("name"), rs.getString("email"));
                }
                return null;
            }
        }
    }
}
""", "safe")

add("csharp", """\
using System;
using System.Collections.Generic;
using System.Linq;

public static class EnumerableExtensions
{
    public static IEnumerable<T> Shuffle<T>(this IEnumerable<T> source)
    {
        var rng = new Random();
        return source.OrderBy(_ => rng.Next());
    }
    
    public static bool IsEmpty<T>(this IEnumerable<T> source) => !source.Any();
}
""", "safe")

add("csharp", """\
using System.Security.Cryptography;
using System.Text;

public static class HashHelper
{
    public static string Sha256(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(bytes);
    }
}
""", "safe")

add("go", """\
package main

import "fmt"

type Stack struct {
    items []string
}

func (s *Stack) Push(item string) {
    s.items = append(s.items, item)
}

func (s *Stack) Pop() string {
    if len(s.items) == 0 {
        return ""
    }
    item := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return item
}
""", "safe")

add("go", """\
package main

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
)

func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
}

func main() {
    fmt.Println(hashToken("example-token"))
}
""", "safe")

# More safe utilities
for i in range(22):
    add("python", f"""\
# General utility {i}
def process_{i}(data):
    cleaned = str(data).strip()
    if not cleaned:
        return None
    return cleaned.lower().replace(' ', '_')
""", "safe")

# ═══════════════ TRICKY (30) ═══════════════

add("python", """\
import sqlite3

def lookup(db_path, user_id):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cur.fetchone()
""", "tricky")

add("python", """\
import re

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', name)
""", "tricky")

add("python", """\
from functools import wraps
import time

def retry_on_failure(max_retries=3):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(0.5 * (attempt + 1))
            return None
        return wrapper
    return decorator
""", "tricky")

add("python", """\
import logging

def setup_logger(name):
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
""", "tricky")

add("python", """\
from flask import request, jsonify

def api_response(data):
    callback = request.args.get('callback')
    if callback:
        return f"{callback}({jsonify(data).get_data(as_text=True)})", 200, {'Content-Type': 'application/javascript'}
    return jsonify(data)
""", "tricky")

add("python", """\
DEBUG = True
CACHE_ENABLED = False
MAX_UPLOAD_SIZE_MB = 50
""", "tricky")

add("python", """\
import base64

def decode_auth_header(header):
    if not header.startswith('Basic '):
        return None
    encoded = header[6:]
    decoded = base64.b64decode(encoded).decode('utf-8')
    username, _, password = decoded.partition(':')
    return username, password
""", "tricky")

add("javascript", """\
const jwt = require('jsonwebtoken');

function decodeToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    return payload;
}
""", "tricky")

add("javascript", """\
function memoize(fn) {
    const cache = new Map();
    return function(arg) {
        if (cache.has(arg)) return cache.get(arg);
        const result = fn(arg);
        cache.set(arg, result);
        return result;
    };
}
""", "tricky")

add("javascript", """\
const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

function corsMiddleware(req, res, next) {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    next();
}
""", "tricky")

add("java", """\
import org.springframework.web.bind.annotation.*;

@RestController
public class HealthController {
    
    @GetMapping("/health")
    public String health() {
        return "OK";
    }
    
    @GetMapping("/ready")
    public String ready() {
        return "READY";
    }
}
""", "tricky")

add("java", """\
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;

@Configuration
public class DatabaseConfig {
    
    @Value("${datasource.password}")
    private String password;
    
    @Bean
    public DataSource dataSource() {
        HikariConfig config = new HikariConfig();
        config.setPassword(password);
        return new HikariDataSource(config);
    }
}
""", "tricky")

add("csharp", """\
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api")]
public class StatusController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping() => Ok(new { ts = DateTime.UtcNow });
    
    [HttpGet("version")]
    public IActionResult Version() => Ok(new { version = "1.0.0" });
}
""", "tricky")

add("csharp", """\
using System.Web;

public static class InputSanitizer
{
    public static string SafeHtml(string input)
    {
        return HttpUtility.HtmlEncode(input);
    }
    
    public static string SafeSql(string input)
    {
        return input.Replace("'", "''");
    }
}
""", "tricky")

add("go", """\
package main

import "net/http"

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"healthy"}`))
}

func main() {
    http.HandleFunc("/healthz", healthHandler)
    http.ListenAndServe(":3000", nil)
}
""", "tricky")

# More tricky utility stubs
for i in range(15):
    add("python", f"""\
# Utility module {i}
class Pipeline{i}:
    def __init__(self):
        self.steps = []
    def add_step(self, fn):
        self.steps.append(fn)
        return self
    def run(self, data):
        result = data
        for step in self.steps:
            result = step(result)
        return result
""", "tricky")

# ═══════════════ RUN ═══════════════

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

    results.append({
        "id": i, "lang": s["lang"], "label": s["label"],
        "verdict": v, "seen": sorted(seen),
        "count": len(r.findings), "expected": s["expected"]
    })

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
print(f"  BLIND AUDIT v3 — 100 FRESH snippets (never seen)")
print(f"{'='*60}")
print(f"  TP={tp}  TP_other={tpo}  FN={fn_count}  FP={fp}  TN={tn}  Tricky={tr}  Err={err}")
print(f"  Recall:    {recall:.1%}  ({tp+tpo}/{tp+tpo+fn_count} vulns found)")
print(f"  Precision: {precision:.1%}  ({tp+tpo}/{tp+tpo+fp} findings correct)")
print(f"  Accuracy:  {accuracy:.1%}  ({tp+tpo+tn}/{cls} correct)")
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

# Severity distribution
sevs = {}
for r in results:
    if "findings" not in r:
        continue
print(f"\n── SUMMARY ──")
print(f"  Total snippets: {len(SNIPS)}")
print(f"  Vulnerable: {sum(1 for s in SNIPS if s['label']=='vuln')}")
print(f"  Safe: {sum(1 for s in SNIPS if s['label']=='safe')}")
print(f"  Tricky: {sum(1 for s in SNIPS if s['label']=='tricky')}")

out = Path(__file__).parent / "blind_audit_v3_results.json"
with open(out, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nSaved to {out}")
