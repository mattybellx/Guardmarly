"""
blind_audit_100.py — Scan 100 varied code snippets and audit every finding.

Generates a diverse mix of:
- Clearly vulnerable code (20%)
- Clearly safe code (25%)
- Tricky/ambiguous code (20%)
- Random utility/config code (20%)
- Real-world-ish snippets (15%)

Languages: Python, JavaScript, Java, C#, Go
"""
from __future__ import annotations

import json, sys, textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ansede_static import scan_code
from ansede_static._types import Finding

# ── Snippet catalog ──────────────────────────────────────────────────────
# Each: (id, language, code, expected_label, expected_cwes, notes)
# expected_label: "vuln" = should fire, "safe" = should not fire, "tricky" = edge case

SNIPPETS = []

def _add(lang, code, label, expected_cwes=(), notes=""):
    sid = f"s{len(SNIPPETS)+1:03d}"
    SNIPPETS.append((sid, lang, textwrap.dedent(code).strip(), label, tuple(expected_cwes), notes))

# ── Clearly Vulnerable (should fire) ────────────────────────────────────

_add("python", """
from flask import request
import sqlite3
def search():
    q = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    conn.execute(f"SELECT * FROM items WHERE name = '{q}'")
""", "vuln", ("CWE-89",), "SQL injection via f-string in Flask route")

_add("python", """
from flask import request
import os
def ping():
    host = request.args.get('host')
    os.system(f"ping -c 1 {host}")
""", "vuln", ("CWE-78",), "Command injection via os.system")

_add("python", """
from flask import request, render_template_string
def hello():
    name = request.args.get('name')
    return render_template_string('<h1>Hello ' + name + '</h1>')
""", "vuln", ("CWE-79",), "Reflected XSS via render_template_string")

_add("python", """
from flask import request
import pickle
def load_state():
    data = request.args.get('state')
    return pickle.loads(bytes.fromhex(data))
""", "vuln", ("CWE-502",), "Unsafe deserialization via pickle.loads")

_add("python", """
from flask import Flask
app = Flask(__name__)
@app.route('/admin/delete/<user_id>')
def delete_user(user_id):
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    return 'ok'
""", "vuln", ("CWE-862",), "Admin route without auth check")

_add("python", """
from flask import request, redirect
def go():
    next_url = request.args.get('next', '/')
    return redirect(next_url)
""", "vuln", ("CWE-601",), "Open redirect")

_add("python", """
from flask import request
import yaml
def load():
    data = request.form.get('yaml')
    return yaml.load(data)
""", "vuln", ("CWE-502",), "Unsafe YAML load")

_add("python", """
TOKEN = "ghp_abc123def456ghi789jkl012mno345pqr678stu"
API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuv"
""", "vuln", ("CWE-798",), "Hardcoded GitHub token and API key")

_add("python", """
import hashlib
def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()
""", "vuln", ("CWE-327",), "Weak MD5 hashing")

_add("python", """
import random
def gen_token():
    return ''.join(str(random.randint(0,9)) for _ in range(6))
""", "vuln", ("CWE-338",), "Weak PRNG for token generation")

_add("javascript", """
const express = require('express');
const app = express();
app.get('/search', (req, res) => {
    const q = req.query.q;
    const sql = `SELECT * FROM products WHERE name = '${q}'`;
    db.query(sql, (err, rows) => res.json(rows));
});
""", "vuln", ("CWE-89",), "JS SQL injection via template literal")

_add("javascript", """
app.get('/admin/all-users', (req, res) => {
    User.find({}).then(users => res.json(users));
});
""", "vuln", ("CWE-862",), "JS admin route with no auth middleware")

_add("javascript", """
function display(userInput) {
    document.getElementById('output').innerHTML = userInput;
}
""", "vuln", ("CWE-79",), "DOM XSS via innerHTML")

_add("javascript", """
const serialize = require('node-serialize');
app.post('/load', (req, res) => {
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
});
""", "vuln", ("CWE-502",), "node-serialize unsafe deserialization")

_add("javascript", """
function redirect(req, res) {
    res.redirect(req.query.next);
}
""", "vuln", ("CWE-601",), "Open redirect in JS")

_add("javascript", """
const crypto = require('crypto');
function encrypt(data) {
    const cipher = crypto.createCipher('des', 'mykey');
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
""", "vuln", ("CWE-327",), "Weak DES encryption")

_add("java", """
@RestController
public class UserController {
    @Autowired
    private JdbcTemplate jdbc;
    
    @GetMapping("/admin/users")
    public List<User> listUsers() {
        return jdbc.query("SELECT * FROM users", new UserRowMapper());
    }
}
""", "vuln", ("CWE-862",), "Spring admin route without @PreAuthorize")

_add("java", """
@RestController
public class SearchController {
    @GetMapping("/search")
    public List<Item> search(@RequestParam String q) {
        String sql = "SELECT * FROM items WHERE name LIKE '%" + q + "%'";
        return jdbc.query(sql, new ItemRowMapper());
    }
}
""", "vuln", ("CWE-89",), "Java SQL injection via string concat")

_add("csharp", """
[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetUsers()
    {
        var users = _db.Users.ToList();
        return Ok(users);
    }
}
""", "vuln", ("CWE-862",), "C# admin controller without [Authorize]")

_add("go", """
package main
import "net/http"
func main() {
    http.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`{"users": []}`))
    })
    http.ListenAndServe(":8080", nil)
}
""", "vuln", ("CWE-862",), "Go admin handler without auth middleware")

# ── Clearly Safe (should not fire) ──────────────────────────────────────

_add("python", """
def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
""", "safe", (), "Pure math function, no security concerns")

_add("python", """
import json
def load_config(path):
    with open(path) as f:
        return json.load(f)
""", "safe", (), "Loading JSON config from file")

_add("python", """
from pathlib import Path
def list_files(directory):
    base = Path(directory).resolve()
    return [str(p.relative_to(base)) for p in base.rglob("*.txt")]
""", "safe", (), "Safe file listing with path resolution")

_add("python", """
def parse_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
""", "safe", (), "Safe integer parsing")

_add("python", """
import csv
def read_csv(filepath):
    with open(filepath, newline='') as f:
        return list(csv.DictReader(f))
""", "safe", (), "Reading CSV file")

_add("python", """
from collections import defaultdict
def word_count(text):
    counts = defaultdict(int)
    for word in text.lower().split():
        counts[word] += 1
    return dict(counts)
""", "safe", (), "Word frequency counter")

_add("python", """
import re
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
def is_valid_email(email):
    return bool(EMAIL_RE.match(email))
""", "safe", (), "Email validation regex")

_add("python", """
def merge_dicts(a, b):
    result = dict(a)
    result.update(b)
    return result
""", "safe", (), "Dictionary merge utility")

_add("python", """
import hashlib, os
def hash_password(password):
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
""", "safe", (), "Secure password hashing with PBKDF2")

_add("python", """
import subprocess
def get_git_version():
    return subprocess.run(['git', '--version'], capture_output=True, text=True, check=True).stdout.strip()
""", "safe", (), "Safe subprocess with list args and no shell")

_add("javascript", """
function sumArray(arr) {
    return arr.reduce((a, b) => a + b, 0);
}
module.exports = { sumArray };
""", "safe", (), "Pure array utility")

_add("javascript", """
function formatDate(date) {
    return date.toISOString().split('T')[0];
}
""", "safe", (), "Date formatting utility")

_add("javascript", """
const fs = require('fs').promises;
async function readJsonFile(filepath) {
    const data = await fs.readFile(filepath, 'utf-8');
    return JSON.parse(data);
}
""", "safe", (), "Reading JSON from local file")

_add("javascript", """
function debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}
""", "safe", (), "Debounce utility")

_add("javascript", """
import { createHash } from 'crypto';
function sha256(data) {
    return createHash('sha256').update(data).digest('hex');
}
""", "safe", (), "SHA-256 hashing")

_add("java", """
public class MathUtils {
    public static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }
}
""", "safe", (), "Simple math utility class")

_add("java", """
import java.util.List;
import java.util.stream.Collectors;
public class StringUtils {
    public static List<String> toUpperCase(List<String> items) {
        return items.stream().map(String::toUpperCase).collect(Collectors.toList());
    }
}
""", "safe", (), "Stream processing utility")

_add("java", """
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
public class DateFormatter {
    public static String format(LocalDate date) {
        return date.format(DateTimeFormatter.ISO_DATE);
    }
}
""", "safe", (), "Date formatting utility")

_add("csharp", """
public static class MathHelpers
{
    public static double Average(IEnumerable<int> numbers)
    {
        return numbers.Average();
    }
}
""", "safe", (), "Simple C# utility")

_add("go", """
package main
import "fmt"
func factorial(n int) int {
    if n <= 1 { return 1 }
    return n * factorial(n-1)
}
func main() {
    fmt.Println(factorial(5))
}
""", "safe", (), "Simple Go factorial")

_add("go", """
package main
import "strings"
func sanitizeFilename(name string) string {
    return strings.Map(func(r rune) rune {
        if r == '/' || r == '\\' { return '_' }
        return r
    }, name)
}
""", "safe", (), "Go filename sanitizer")

# ── Tricky / Ambiguous ──────────────────────────────────────────────────

_add("python", """
# This LOOKS like SQL injection but the query is static
def get_user(cursor, user_id):
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
""", "tricky", (), "Parameterized query — should NOT fire CWE-89")

_add("python", """
# Using exec() but with a static string
def create_function(name):
    code = f"def {name}(): pass"
    exec(code)
""", "tricky", (), "exec() with dynamic name — borderline CWE-94")

_add("python", """
from flask import request
import subprocess

def run_validated():
    tool = request.args.get('tool', 'git')
    allowed = {'git', 'npm', 'pip'}
    if tool in allowed:
        subprocess.run([tool, '--version'], check=True)
""", "tricky", (), "Command injection with allowlist validation")

_add("python", """
# YAML loading but with SafeLoader
import yaml
def load_doc(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
""", "tricky", (), "yaml.load with SafeLoader — borderline")

_add("python", """
# Path join with user input but validated
import os
from pathlib import Path
BASE = Path('/var/data')
def read_file(filename):
    full = (BASE / filename).resolve()
    if not str(full).startswith(str(BASE)):
        raise ValueError('path escape')
    return full.read_text()
""", "tricky", (), "Path traversal with resolve() guard")

_add("python", """
# Auth check exists but in weird pattern
from flask import Flask, g
app = Flask(__name__)
@app.route('/admin/stats')
def stats():
    if not hasattr(g, 'user'):
        return 'Unauthorized', 401
    return compute_stats()
""", "tricky", (), "Auth via hasattr — unusual pattern, should check for CWE-862")

_add("python", """
# Random used for non-security purpose
import random
def shuffle_deck(cards):
    return random.sample(cards, len(cards))
""", "tricky", (), "random for card shuffling — not CWE-338 if non-security")

_add("python", """
# Hardcoded but looks like a test value
TEST_API_KEY = "test_key_12345"
DEBUG_SECRET = "dev-secret-do-not-use-in-prod"
""", "tricky", (), "Test credentials — should it fire CWE-798?")

_add("python", """
# logging.info with user data but not a password
import logging
from flask import request
def log_search():
    query = request.args.get('q', '')
    logging.info(f'Search query: {query}')
""", "tricky", (), "Logging user input — not sensitive data")

_add("python", """
# HTTP URL in config but clearly dev
SERVICE_URL = "http://localhost:8000/api"
""", "tricky", (), "Localhost URL — CWE-319?")

_add("javascript", """
// eval with static string
const fn = eval('(x) => x * 2');
""", "tricky", (), "eval with static string — should it fire?")

_add("javascript", """
// SQL with parameterized query
const query = 'SELECT * FROM users WHERE id = $1';
await db.query(query, [req.params.id]);
""", "tricky", (), "Parameterized query — should NOT fire CWE-89")

_add("javascript", """
// Route with auth middleware inline
app.get('/api/data', authenticate, authorize('read'), (req, res) => {
    res.json(data);
});
""", "tricky", (), "Auth middleware present — should NOT fire CWE-862")

_add("javascript", """
// eval via Function constructor
const fn = new Function('return ' + userExpr);
""", "tricky", (), "new Function with user input — borderline code injection")

_add("java", """
@RestController
@RequestMapping("/api")
public class HealthController {
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }
}
""", "tricky", (), "Public health endpoint — should NOT fire CWE-862")

_add("java", """
@Service
public class CryptoService {
    private static final String KEY = System.getenv("ENCRYPTION_KEY");
    public String encrypt(String data) { return AES.encrypt(data, KEY); }
}
""", "tricky", (), "Key from env var — should NOT fire CWE-798 or CWE-327")

_add("csharp", """
[HttpGet("public/status")]
public IActionResult Status() => Ok(new { status = "healthy" });
""", "tricky", (), "Public status endpoint — should NOT fire CWE-862")

_add("csharp", """
var sanitized = HttpUtility.HtmlEncode(userInput);
return Content($"<div>{sanitized}</div>", "text/html");
""", "tricky", (), "HtmlEncode used — should NOT fire CWE-79")

_add("go", """
func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("ok"))
}
func main() {
    http.HandleFunc("/health", healthHandler)
}
""", "tricky", (), "Public health endpoint — should NOT fire CWE-862")

# ── Random Utility / Config / Data Processing ──────────────────────────

_add("python", """
# Configuration loader
import os, json
class Config:
    _instance = None
    def __init__(self):
        self.data = {}
        for key, val in os.environ.items():
            if key.startswith('APP_'):
                self.data[key[4:].lower()] = val
config = Config()
""", "safe", (), "Config from env vars")

_add("python", """
# Data transformation pipeline
def transform(records):
    return [
        {k: str(v).strip().lower() for k, v in r.items()}
        for r in records
        if r.get('active', False)
    ]
""", "safe", (), "Data cleaning utility")

_add("python", """
# Retry decorator
import time, functools
def retry(max_attempts=3, delay=1):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception:
                    if attempt == max_attempts - 1:
                        raise
                    time.sleep(delay)
        return wrapper
    return decorator
""", "safe", (), "Retry decorator utility")

_add("python", """
# LRU cache implementation
from collections import OrderedDict
class LRUCache:
    def __init__(self, capacity):
        self.cache = OrderedDict()
        self.capacity = capacity
    def get(self, key):
        if key not in self.cache:
            return -1
        self.cache.move_to_end(key)
        return self.cache[key]
    def put(self, key, value):
        self.cache[key] = value
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)
""", "safe", (), "LRU cache data structure")

_add("python", """
# Simple HTTP client wrapper
import urllib.request
import json
def fetch_json(url):
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode())
""", "tricky", (), "HTTP client — SSRF if url is user-controlled but unknown here")

_add("python", """
# Command-line argument parser
import argparse
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--input', required=True)
    p.add_argument('--output', default='out.txt')
    p.add_argument('--verbose', action='store_true')
    return p.parse_args()
""", "safe", (), "Argument parser")

_add("python", """
# Database migration helper
def migrate(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE
    )''')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_email ON users(email)')
""", "safe", (), "Static DDL migration")

_add("javascript", """
// Event emitter pattern
class EventEmitter {
    constructor() { this.handlers = {}; }
    on(event, fn) {
        (this.handlers[event] = this.handlers[event] || []).push(fn);
    }
    emit(event, ...args) {
        (this.handlers[event] || []).forEach(fn => fn(...args));
    }
}
""", "safe", (), "Event emitter pattern")

_add("javascript", """
// Rate limiter using token bucket
class RateLimiter {
    constructor(maxTokens, refillRate) {
        this.tokens = maxTokens;
        this.maxTokens = maxTokens;
        this.refillRate = refillRate;
        this.lastRefill = Date.now();
    }
    allow() {
        const now = Date.now();
        this.tokens = Math.min(this.maxTokens,
            this.tokens + (now - this.lastRefill) * this.refillRate / 1000);
        this.lastRefill = now;
        if (this.tokens >= 1) { this.tokens--; return true; }
        return false;
    }
}
""", "safe", (), "Rate limiter implementation")

_add("javascript", """
// Simple JWT decode (no verification — just parsing)
function decodeJWT(token) {
    const parts = token.split('.');
    return JSON.parse(Buffer.from(parts[1], 'base64').toString());
}
""", "tricky", (), "JWT decode without verification — info disclosure?")

_add("javascript", """
// Environment-based config
const config = {
    port: process.env.PORT || 3000,
    dbUrl: process.env.DATABASE_URL,
    apiKey: process.env.API_KEY,
    nodeEnv: process.env.NODE_ENV || 'development',
};
module.exports = config;
""", "safe", (), "Config from env vars")

_add("java", """
// Builder pattern
public class HttpResponse {
    private int status;
    private String body;
    private Map<String, String> headers = new HashMap<>();
    
    public static class Builder {
        private HttpResponse response = new HttpResponse();
        public Builder status(int code) { response.status = code; return this; }
        public Builder body(String b) { response.body = b; return this; }
        public Builder header(String k, String v) { response.headers.put(k, v); return this; }
        public HttpResponse build() { return response; }
    }
}
""", "safe", (), "Builder pattern")

_add("java", """
// Simple dependency injection
@Component
public class EmailService {
    private final MailSender mailSender;
    public EmailService(MailSender mailSender) {
        this.mailSender = mailSender;
    }
    public void sendWelcome(String to) {
        mailSender.send(to, "Welcome!", "Thanks for joining.");
    }
}
""", "safe", (), "DI service class")

_add("java", """
// CORS configuration
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://example.com")
            .allowedMethods("GET", "POST");
    }
}
""", "safe", (), "CORS config with specific origin")

_add("csharp", """
// Extension method
public static class StringExtensions
{
    public static string Truncate(this string value, int maxLength)
    {
        return value?.Length > maxLength ? value[..maxLength] : value;
    }
}
""", "safe", (), "Extension method")

_add("csharp", """
// Configuration binding
public class AppSettings
{
    public string ConnectionString { get; set; }
    public int MaxRetries { get; set; } = 3;
}
""", "safe", (), "Config POCO")

_add("go", """
// Simple middleware
func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Printf("%s %s", r.Method, r.URL.Path)
        next.ServeHTTP(w, r)
    })
}
""", "safe", (), "Logging middleware")

_add("go", """
// Worker pool
func worker(id int, jobs <-chan int, results chan<- int) {
    for j := range jobs {
        results <- j * 2
    }
}
""", "safe", (), "Worker pool goroutine")

# ── Real-world-ish snippets ────────────────────────────────────────────

_add("python", """
# FastAPI route with proper auth
from fastapi import FastAPI, Depends, HTTPException
from app.auth import get_current_user

app = FastAPI()

@app.get("/api/me")
async def get_profile(user = Depends(get_current_user)):
    return {"id": user.id, "email": user.email}
""", "safe", (), "FastAPI with Depends auth")

_add("python", """
# Flask route uploading a file — path traversal risk?
from flask import Flask, request
import os
UPLOAD_DIR = '/var/uploads'
app = Flask(__name__)
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return 'ok'
""", "vuln", ("CWE-22",), "File upload without filename sanitization")

_add("python", """
# SSRF via requests with user URL
from flask import request
import requests
def proxy():
    url = request.args.get('url')
    resp = requests.get(url, timeout=5)
    return resp.text
""", "vuln", ("CWE-918",), "SSRF via requests.get")

_add("python", """
# Django view with @login_required
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def dashboard(request):
    return render(request, 'dashboard.html', {'user': request.user})
""", "safe", (), "Django view with login_required")

_add("python", """
# Celery task with eval — dangerous
from celery import shared_task

@shared_task
def evaluate(expression, context=None):
    return eval(expression, {"__builtins__": {}}, context or {})
""", "vuln", ("CWE-95",), "eval in Celery task")

_add("javascript", """
// Express route with input validation
const { body, validationResult } = require('express-validator');
app.post('/register',
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json(errors);
        createUser(req.body);
    }
);
""", "safe", (), "Express with input validation")

_add("javascript", """
// React component with dangerouslySetInnerHTML
function Comment({ text }) {
    return <div dangerouslySetInnerHTML={{ __html: text }} />;
}
""", "vuln", ("CWE-79",), "React dangerouslySetInnerHTML XSS")

_add("javascript", """
// Node.js file read without path validation
const fs = require('fs');
app.get('/file', (req, res) => {
    const filename = req.query.file;
    res.sendFile(`/var/data/${filename}`);
});
""", "vuln", ("CWE-22",), "Path traversal via res.sendFile")

_add("java", """
// Spring Boot actuator without security
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
""", "tricky", (), "Spring Boot app — actuator endpoints exposed?")

_add("java", """
// JDBC with PreparedStatement
public User getUser(Connection conn, int id) throws SQLException {
    String sql = "SELECT * FROM users WHERE id = ?";
    try (PreparedStatement stmt = conn.prepareStatement(sql)) {
        stmt.setInt(1, id);
        ResultSet rs = stmt.executeQuery();
        return mapUser(rs);
    }
}
""", "safe", (), "PreparedStatement — should NOT fire CWE-89")

_add("java", """
// Hardcoded JDBC password
@Configuration
public class DatabaseConfig {
    @Bean
    public DataSource dataSource() {
        return DataSourceBuilder.create()
            .url("jdbc:postgresql://localhost:5432/mydb")
            .username("admin")
            .password("SuperSecret123!")
            .build();
    }
}
""", "vuln", ("CWE-798",), "Hardcoded database password")

_add("csharp", """
// ASP.NET with antiforgery
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult UpdateProfile(ProfileModel model)
{
    _service.Update(model);
    return RedirectToAction("Index");
}
""", "safe", (), "ASP.NET with antiforgery token")

_add("csharp", """
// Raw SQL in EF Core
public async Task<User> GetUser(string username)
{
    return await _context.Users
        .FromSqlRaw($"SELECT * FROM Users WHERE Username = '{username}'")
        .FirstOrDefaultAsync();
}
""", "vuln", ("CWE-89",), "SQL injection via FromSqlRaw with interpolation")

_add("go", """
// Gin handler with user-controlled file path
func downloadHandler(c *gin.Context) {
    filename := c.Query("file")
    c.File("/var/files/" + filename)
}
""", "vuln", ("CWE-22",), "Path traversal via Gin c.File")

_add("go", """
// Go prepared statement
func getUser(db *sql.DB, id int) (*User, error) {
    row := db.QueryRow("SELECT * FROM users WHERE id = $1", id)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    return &u, err
}
""", "safe", (), "Prepared statement — should NOT fire CWE-89")

# ── Additional random snippets for volume ─────────────────────────────

_add("python", """
# Webhook handler
from flask import Flask, request, jsonify
import hmac, hashlib
app = Flask(__name__)
@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-Signature')
    computed = hmac.new(b'secret', request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, computed):
        return 'invalid', 403
    process(request.json)
    return jsonify({'ok': True})
""", "safe", (), "Webhook with HMAC verification")

_add("python", """
# Password reset token generator
import secrets
def generate_reset_token():
    return secrets.token_urlsafe(32)
""", "safe", (), "Secure token generation with secrets module")

_add("python", """
# GraphQL resolver exposing internal IDs
def resolve_user(root, info, id):
    return User.objects.get(pk=id)
""", "vuln", ("CWE-639",), "IDOR via GraphQL resolver")

_add("javascript", """
// GraphQL mutation without auth
const resolvers = {
    Mutation: {
        deleteUser: (_, { id }) => {
            return User.findByIdAndDelete(id);
        }
    }
};
""", "vuln", ("CWE-862",), "GraphQL mutation without auth check")

_add("javascript", """
// Lodash template injection risk
const _ = require('lodash');
const template = _.template('<div><%= user.name %></div>');
""", "safe", (), "Lodash template with escaped interpolation")

_add("java", """
// Command injection via ProcessBuilder
public void runCommand(String userInput) {
    ProcessBuilder pb = new ProcessBuilder("sh", "-c", userInput);
    pb.start();
}
""", "vuln", ("CWE-78",), "Command injection via ProcessBuilder")

_add("csharp", """
// Process.Start with user input
public void Execute(string command)
{
    Process.Start("cmd.exe", "/c " + command);
}
""", "vuln", ("CWE-78",), "Command injection via Process.Start")

_add("go", """
// exec.Command with user input
func run(userCmd string) {
    cmd := exec.Command("sh", "-c", userCmd)
    cmd.Run()
}
""", "vuln", ("CWE-78",), "Command injection via exec.Command")

# ── Totals ──────────────────────────────────────────────────────────────
print(f"Generated {len(SNIPPETS)} snippets")
vc = sum(1 for _,_,_,l,_,_ in SNIPPETS if l == "vuln")
sc = sum(1 for _,_,_,l,_,_ in SNIPPETS if l == "safe")
tc = sum(1 for _,_,_,l,_,_ in SNIPPETS if l == "tricky")
print(f"  Vulnerable: {vc}, Safe: {sc}, Tricky: {tc}")


# ── Audit engine ────────────────────────────────────────────────────────

def audit():
    results = []
    for sid, lang, code, label, expected_cwes, notes in SNIPPETS:
        try:
            result = scan_code(code, language=lang, filename=f"{sid}.{lang[:2]}")
        except Exception as exc:
            results.append({
                "id": sid, "lang": lang, "label": label, "notes": notes,
                "expected_cwes": list(expected_cwes),
                "error": str(exc),
                "findings": [], "verdict": "ERROR",
            })
            continue

        seen_cwes = {f.cwe for f in result.findings if f.cwe}
        seen_rule_ids = {f.rule_id for f in result.findings if f.rule_id}
        findings_detail = []
        for f in result.findings:
            findings_detail.append({
                "cwe": f.cwe, "rule_id": f.rule_id, "severity": str(f.severity.value),
                "title": f.title, "confidence": f.confidence,
                "analysis_kind": f.analysis_kind or "",
                "has_trace": bool(f.trace and len(f.trace) > 0),
            })

        # Classification
        verdict = ""
        if label == "vuln":
            if any(cwe in seen_cwes for cwe in expected_cwes):
                verdict = "TP"  # True positive — expected vuln found
            elif seen_cwes:
                verdict = "TP_OTHER"  # Found vuln but different CWE
            else:
                verdict = "FN"  # False negative — missed
        elif label == "safe":
            if seen_cwes:
                verdict = "FP"  # False positive — safe code flagged
            else:
                verdict = "TN"  # True negative — correctly quiet
        elif label == "tricky":
            verdict = "TRICKY"  # Edge case — manual review needed

        results.append({
            "id": sid, "lang": lang, "label": label, "notes": notes,
            "expected_cwes": list(expected_cwes),
            "verdict": verdict,
            "finding_count": len(result.findings),
            "seen_cwes": sorted(seen_cwes),
            "findings": findings_detail,
        })

    # ── Summary ──────────────────────────────────────────────────────
    tp = sum(1 for r in results if r["verdict"] == "TP")
    tp_other = sum(1 for r in results if r["verdict"] == "TP_OTHER")
    fn = sum(1 for r in results if r["verdict"] == "FN")
    fp = sum(1 for r in results if r["verdict"] == "FP")
    tn = sum(1 for r in results if r["verdict"] == "TN")
    tricky = sum(1 for r in results if r["verdict"] == "TRICKY")
    errors = sum(1 for r in results if r["verdict"] == "ERROR")

    total_classified = tp + tp_other + fn + fp + tn
    recall = (tp + tp_other) / max(tp + tp_other + fn, 1)
    precision = (tp + tp_other) / max(tp + tp_other + fp, 1)
    accuracy = (tp + tp_other + tn) / max(total_classified, 1)

    print(f"\n{'='*60}")
    print(f"  BLIND AUDIT RESULTS — 100 Random Snippets")
    print(f"{'='*60}")
    print(f"  True Positives:      {tp}")
    print(f"  TP (other CWE):      {tp_other}")
    print(f"  False Negatives:     {fn}")
    print(f"  False Positives:     {fp}")
    print(f"  True Negatives:      {tn}")
    print(f"  Tricky (manual):     {tricky}")
    print(f"  Errors:              {errors}")
    print(f"{'='*60}")
    print(f"  Recall:    {recall:.1%}  ({tp+tp_other}/{tp+tp_other+fn} vulns found)")
    print(f"  Precision: {precision:.1%}  ({tp+tp_other}/{tp+tp_other+fp} findings correct)")
    print(f"  Accuracy:  {accuracy:.1%}  ({tp+tp_other+tn}/{total_classified} correct)")
    print(f"{'='*60}")

    # Print FN details
    if fn:
        print(f"\n── FALSE NEGATIVES (missed vulnerabilities) ──")
        for r in results:
            if r["verdict"] == "FN":
                print(f"  {r['id']} [{r['lang']}] {r['notes']}")
                print(f"    Expected: {r['expected_cwes']}, Got: {r['seen_cwes']}")

    # Print FP details
    if fp:
        print(f"\n── FALSE POSITIVES (safe code flagged) ──")
        for r in results:
            if r["verdict"] == "FP":
                print(f"  {r['id']} [{r['lang']}] {r['notes']}")
                for f in r["findings"]:
                    print(f"    → {f['cwe']} ({f['severity']}) {f['title'][:80]}")

    # Print tricky
    if tricky:
        print(f"\n── TRICKY CASES (need manual review) ──")
        for r in results:
            if r["verdict"] == "TRICKY":
                print(f"  {r['id']} [{r['lang']}] {r['notes']}")
                if r["seen_cwes"]:
                    for f in r["findings"]:
                        print(f"    → {f['cwe']} ({f['severity']}) conf={f['confidence']:.0%} {f['title'][:80]}")
                else:
                    print(f"    (no findings)")

    # Severity distribution
    sevs = {}
    for r in results:
        for f in r["findings"]:
            s = f.get("severity", "?")
            sevs[s] = sevs.get(s, 0) + 1
    print(f"\n── SEVERITY DISTRIBUTION ──")
    for s in ("critical", "high", "medium", "low", "info"):
        if s in sevs:
            print(f"  {s}: {sevs[s]}")

    # Save full JSON
    out_path = Path(__file__).parent / "blind_audit_100_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nFull results → {out_path}")

    return results


if __name__ == "__main__":
    audit()
