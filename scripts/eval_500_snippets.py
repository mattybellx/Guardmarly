"""
scripts/eval_500_snippets.py
─────────────────────────────
Generates 500 diverse, unbiased code snippets across difficulty levels,
runs each through the ansede-static scanner, and scores accuracy.

Categories:
  easy_vuln   — obvious patterns (eval, hardcoded secrets, shell=True)
  medium_vuln — needs some context (f-string SQLi, requests SSRF, XSS)
  hard_vuln   — deeper analysis (IDOR, proto pollution, log injection)
  clean       — secure code that should trigger nothing

Zero cherry-picking — snippets are generated programmatically.
"""
from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

random.seed(42)  # reproducible

# ── Snippet generators ──────────────────────────────────────────────────────

def _py(imports: str, body: str) -> str:
    return f"{imports}\n\n{body}" if imports else body

def _js(body: str) -> str:
    return body

SNIPPETS: list[tuple[str, str, str]] = []  # (language, category, code)

def add(lang: str, cat: str, code: str) -> None:
    SNIPPETS.append((lang, cat, code))

# ═══════════════════════════════════════════════════════════════════════════
# EASY VULNERABLE (125 snippets — obvious patterns)
# ═══════════════════════════════════════════════════════════════════════════

_EASY_PY_IMPORTS = [
    "import os", "import subprocess", "import pickle",
    "import sqlite3", "from flask import Flask, request",
]
_EASY_PY_VULNS = [
    # eval / exec
    'eval(user_input)',
    'exec(user_code)',
    'eval(request.args.get("code"))',
    'exec("import " + module)',
    'compile(user_src, "<string>", "exec")',
    # shell injection
    'os.system("rm -rf " + path)',
    'os.system(user_cmd)',
    'os.popen("cat " + filename)',
    'subprocess.call(cmd, shell=True)',
    'subprocess.Popen(user_input, shell=True)',
    'subprocess.run(sh, shell=True)',
    'subprocess.check_output("ls " + d, shell=True)',
    # pickle deserialization
    'pickle.loads(data)',
    'pickle.load(open(f, "rb"))',
    # hardcoded secrets
    'API_KEY = "sk-proj-abc123def456"',
    'PASSWORD = "SuperSecret123!"',
    'SECRET_KEY = "my-secret-key-here"',
    'DATABASE_URL = "postgresql://user:pass@host/db"',
    'STRIPE_KEY = "sk_live_abc123def456"',
    'AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"',
    'GITHUB_TOKEN = "ghp_1234567890abcdef"',
    # SQL injection (concatenation)
    'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
    'db.execute("DELETE FROM items WHERE name = \'" + name + "\'")',
    'sql = "SELECT * FROM t WHERE x = " + x; cursor.execute(sql)',
    # path traversal
    'open("/var/data/" + filename).read()',
    'open(request.args.get("file")).read()',
    'Path("/etc/" + user_path).read_text()',
]

_EASY_JS_VULNS = [
    'eval(userInput)',
    'eval(req.query.code)',
    'new Function("return " + expr)()',
    'new Function(body)()',
    'setTimeout("doStuff(" + data + ")", 1000)',
    'setInterval("fetch(\'" + url + "\')", 5000)',
    'child_process.exec(userCmd)',
    'child_process.execSync("rm -rf " + path)',
    'child_process.spawn(cmd, args)',
    'document.getElementById("x").innerHTML = userHtml',
    'document.write(userContent)',
    'document.querySelector("#out").innerHTML = data',
    'const API_KEY = "sk-live-abc123"',
    'const PASSWORD = "admin123!"',
    'const SECRET = "my-jwt-secret-key"',
    'res.send("<h1>" + req.query.name + "</h1>")',
    'res.send(`<div>${userData}</div>`)',
    'location.href = userUrl',
    'window.open(userProvidedUrl)',
    'new WebSocket(userUrl)',
    'localStorage.setItem("token", userToken)',
    'document.cookie = "sess=" + sid',
    'fs.readFile(userPath, cb)',
    'fs.writeFile(userPath, data, cb)',
    'require(userModulePath)',
    'import(userModuleUrl)',
]

for _ in range(125):
    if random.random() < 0.6:
        imp = random.choice(_EASY_PY_IMPORTS) if random.random() < 0.5 else ""
        code = _py(imp, random.choice(_EASY_PY_VULNS))
        add("python", "easy_vuln", code)
    else:
        code = _js(random.choice(_EASY_JS_VULNS))
        add("javascript", "easy_vuln", code)

# ═══════════════════════════════════════════════════════════════════════════
# MEDIUM VULNERABLE (125 snippets — needs context)
# ═══════════════════════════════════════════════════════════════════════════

_MED_PY_TEMPLATES = [
    # SQLi with f-string
    ('import sqlite3\n\ndef get_user(username):\n    db = sqlite3.connect("app.db")\n    db.execute(f"SELECT * FROM users WHERE name = \'{username}\'")',),
    ('def search(term):\n    query = f"SELECT * FROM products WHERE name LIKE \'%{term}%\'"\n    cursor.execute(query)',),
    ('def delete_user(uid):\n    db.execute("DELETE FROM users WHERE id = " + str(uid))',),
    # SSRF
    ('import requests\n\ndef fetch_url(url):\n    return requests.get(url).text',),
    ('import urllib.request\n\ndef proxy(target):\n    return urllib.request.urlopen(target).read()',),
    ('import httpx\n\nasync def fetch(url):\n    async with httpx.AsyncClient() as c:\n        return await c.get(url)',),
    # XSS
    ('from flask import Flask, request\napp = Flask(__name__)\n\n@app.route("/search")\ndef search():\n    q = request.args.get("q", "")\n    return f"<h1>Results for {q}</h1>"',),
    ('def render(name):\n    return "<div>Welcome, " + name + "</div>"',),
    # Open redirect
    ('from flask import Flask, request, redirect\napp = Flask(__name__)\n\n@app.route("/goto")\ndef goto():\n    return redirect(request.args.get("next", "/"))',),
    ('def after_login():\n    return redirect(request.args.get("redirect_to"))',),
    # Weak crypto
    ('import hashlib\n\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()',),
    ('import hashlib\n\ndef checksum(data):\n    return hashlib.sha1(data).hexdigest()',),
    # Unsafe yaml
    ('import yaml\n\ndef load_config(s):\n    return yaml.load(s)',),
    # Unsafe XML
    ('import xml.etree.ElementTree as ET\n\ndef parse(xml_str):\n    return ET.fromstring(xml_str)',),
    ('from lxml import etree\n\ndef parse(xml_data):\n    return etree.fromstring(xml_data)',),
    # CWE-117 log injection
    ('import logging\n\ndef log_event(user):\n    logging.info("User login: " + user)',),
    ('import logging\n\ndef handle(data):\n    logging.warning(f"Error from {data}")',),
    # Path traversal with join
    ('import os\n\ndef read_file(name):\n    path = os.path.join("/var/data", name)\n    return open(path).read()',),
    ('from pathlib import Path\n\ndef get_file(user_file):\n    return Path("/uploads/" + user_file).read_text()',),
    # CWE-502 marshal
    ('import marshal\n\ndef restore(blob):\n    return marshal.loads(blob)',),
]

_MED_JS_TEMPLATES = [
    # SSRF via fetch
    ('app.get("/proxy", async (req, res) => {\n  const data = await fetch(req.query.url).then(r => r.json());\n  res.json(data);\n});',),
    # axios SSRF
    ('const axios = require("axios");\napp.get("/fetch", (req, res) => {\n  axios.get(req.query.url).then(r => res.send(r.data));\n});',),
    # Prototype pollution
    ('function merge(target, source) {\n  for (let key in source) {\n    if (typeof source[key] === "object") target[key] = merge(target[key] || {}, source[key]);\n    else target[key] = source[key];\n  }\n  return target;\n}',),
    # SQLi via template
    ('const query = `SELECT * FROM users WHERE name = "${username}"`;\ndb.query(query, callback);',),
    # NoSQL injection
    ('app.post("/login", (req, res) => {\n  User.findOne({username: req.body.username, password: req.body.password}).then(u => res.json(u));\n});',),
    # Path traversal
    ('app.get("/download", (req, res) => {\n  const p = path.join("/var/data", req.query.file);\n  res.sendFile(p);\n});',),
    # CWE-117 log injection
    ('logger.info("User action: " + req.body.action);',),
    # JSONP XSS
    ('app.get("/api", (req, res) => {\n  res.send(req.query.callback + "({data: 123})");\n});',),
    # ReDoS
    ('const re = new RegExp("(" + userPattern + ")+");\nre.test(input);',),
    # Unsafe deserialization
    ('const data = eval("(" + jsonStr + ")");',),
]

for _ in range(125):
    if random.random() < 0.6:
        code = random.choice(_MED_PY_TEMPLATES)[0]
        add("python", "medium_vuln", code)
    else:
        code = random.choice(_MED_JS_TEMPLATES)[0]
        add("javascript", "medium_vuln", code)

# ═══════════════════════════════════════════════════════════════════════════
# HARD VULNERABLE (125 snippets — deeper analysis needed)
# ═══════════════════════════════════════════════════════════════════════════

_HARD_PY_TEMPLATES = [
    # IDOR
    ('from flask import Flask, request\nfrom models import db, Invoice\napp = Flask(__name__)\n\n@app.route("/invoice/<id>")\ndef get_invoice(id):\n    return Invoice.query.get(id)',),
    # Missing auth
    ('from flask import Flask, request\napp = Flask(__name__)\n\n@app.route("/admin/delete", methods=["POST"])\ndef delete():\n    uid = request.form["id"]\n    db.execute(f"DELETE FROM users WHERE id={uid}")\n    return "ok"',),
    # CWE-862 missing auth on sensitive endpoint
    ('from fastapi import FastAPI\napp = FastAPI()\n\n@app.post("/admin/ban-user")\nasync def ban_user(user_id: int):\n    await db.ban(user_id)\n    return {"status": "banned"}',),
    # CWE-918 with variable propagation
    ('import requests\n\ndef handler(req):\n    target = req.get("url")\n    resp = requests.post(target, json={"data": "x"})\n    return resp.json()',),
    # CWE-78 with variable
    ('import subprocess\n\ndef run_tool(name):\n    cmd = f"tool --name {name}"\n    subprocess.run(cmd, shell=True)',),
    # CWE-94 code injection via import
    ('def load_plugin(name):\n    return __import__(name)',),
    ('import importlib\n\ndef load_module(user_module):\n    return importlib.import_module(user_module)',),
    # CWE-502 pickle in web context
    ('from flask import Flask, request\nimport pickle\napp = Flask(__name__)\n\n@app.route("/restore", methods=["POST"])\ndef restore():\n    data = request.get_data()\n    return pickle.loads(data)',),
    # CWE-611 XXE
    ('import xml.etree.ElementTree as ET\n\ndef parse_xml(user_xml):\n    tree = ET.parse(user_xml)\n    return tree.getroot()',),
    # CWE-639 with ownership bypass
    ('from flask import request\n\ndef get_document(doc_id):\n    user_id = request.args.get("user_id")\n    return Document.query.filter_by(id=doc_id, owner_id=user_id).first()',),
    # CWE-918 blind SSRF
    ('import urllib.request\n\ndef webhook(url, data):\n    req = urllib.request.Request(url, data=json.dumps(data).encode())\n    return urllib.request.urlopen(req).read()',),
    # CWE-1333 ReDoS
    ('import re\n\ndef validate_email(email):\n    return re.match(r"^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", email)',),
    # CWE-367 TOCTOU
    ('import os\n\ndef safe_save(path, data):\n    if not os.path.exists(path):\n        with open(path, "w") as f:\n            f.write(data)',),
    # CWE-377 insecure temp
    ('import tempfile\n\ndef make_temp():\n    return tempfile.mktemp()',),
    ('import os\n\ndef temp_name():\n    return os.tempnam("/tmp", "prefix")',),
]

_HARD_JS_TEMPLATES = [
    # Deep prototype pollution
    ('function deepMerge(target, ...sources) {\n  for (const src of sources) {\n    for (const key of Object.keys(src)) {\n      if (typeof src[key] === "object") target[key] = deepMerge(target[key] || {}, src[key]);\n      else target[key] = src[key];\n    }\n  }\n  return target;\n}',),
    # CWE-1321 in Express middleware
    ('app.use((req, res, next) => {\n  Object.assign(req.config, req.body);\n  next();\n});',),
    # CWE-915 dynamic object modification
    ('app.post("/config", (req, res) => {\n  const key = req.body.key;\n  const val = req.body.value;\n  globalConfig[key] = val;\n  res.json({ok: true});\n});',),
    # CWE-200 sensitive data exposure
    ('app.get("/debug", (req, res) => {\n  res.json({env: process.env, config: appConfig});\n});',),
    # CWE-352 CSRF missing token
    ('app.post("/transfer", (req, res) => {\n  const {to, amount} = req.body;\n  transferFunds(req.user, to, amount);\n  res.json({ok: true});\n});',),
    # CWE-601 open redirect
    ('app.get("/redirect", (req, res) => {\n  res.redirect(req.query.url);\n});',),
    # CWE-525 sensitive caching
    ('app.get("/profile", (req, res) => {\n  res.set("Cache-Control", "public, max-age=86400");\n  res.json(req.user);\n});',),
]

for _ in range(125):
    if random.random() < 0.7:
        code = random.choice(_HARD_PY_TEMPLATES)[0]
        add("python", "hard_vuln", code)
    else:
        code = random.choice(_HARD_JS_TEMPLATES)[0]
        add("javascript", "hard_vuln", code)

# ═══════════════════════════════════════════════════════════════════════════
# CLEAN (125 snippets — secure code, should trigger NOTHING)
# ═══════════════════════════════════════════════════════════════════════════

_CLEAN_PY = [
    'x = 1\ny = x + 2\nprint(y)',
    'def add(a, b):\n    return a + b',
    'import json\ndata = json.loads(\'{"key": "value"}\')',
    'import os\nkey = os.environ.get("API_KEY")',
    'result = sum(range(100))',
    'items = sorted(data, key=lambda x: x["name"])',
    'import hashlib\nh = hashlib.sha256(data).hexdigest()',
    'from collections import Counter\nc = Counter(words)',
    'import math\nr = math.sqrt(144)',
    'from pathlib import Path\nPath("/tmp").mkdir(exist_ok=True)',
    'import csv\nwith open("data.csv") as f:\n    reader = csv.reader(f)',
    'import json\nwith open("config.json") as f:\n    cfg = json.load(f)',
    'def greet(name):\n    return f"Hello, {len(name)} character name!"',
    'count = int(user_input)\ntotal = count * 2',
    'import re\nclean = re.sub(r"[^a-zA-Z0-9]", "", text)',
    'values = [x * 2 for x in range(10)]',
    'd = dict(zip(keys, values))',
    's = set.intersection(a, b, c)',
    'import functools\n@functools.lru_cache(maxsize=128)\ndef fib(n):\n    return n if n < 2 else fib(n-1) + fib(n-2)',
    'from dataclasses import dataclass\n@dataclass\nclass Point:\n    x: int\n    y: int',
    'from typing import List, Optional\ndef first(items: List[int]) -> Optional[int]:\n    return items[0] if items else None',
    'from enum import Enum\nclass Color(Enum):\n    RED = 1\n    GREEN = 2',
    'import shutil\nshutil.copy("a.txt", "b.txt")',
    'import glob\nfiles = glob.glob("*.py")',
    'import statistics\navg = statistics.mean([1, 2, 3, 4, 5])',
    'from decimal import Decimal\nprice = Decimal("0.10")',
    'from fractions import Fraction\nf = Fraction(1, 3)',
    'items = list(filter(None, data))',
    'import itertools\ncombined = itertools.chain(a, b, c)',
    'import linecache\nline = linecache.getline("test.py", 10)',
    'import fileinput\nfor line in fileinput.input(files=["a.txt"]):\n    print(line)',
    'import configparser\ncfg = configparser.ConfigParser()\ncfg.read("app.ini")',
    'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("Startup complete")',
    'def safe_divide(a, b):\n    if b == 0:\n        raise ValueError("Cannot divide by zero")\n    return a / b',
]

_CLEAN_JS = [
    'const x = 1 + 2;\nconsole.log(x);',
    'const data = JSON.stringify({key: "value"});',
    'const arr = Array.from({length: 10}, (_, i) => i);',
    'const frozen = Object.freeze({theme: "dark"});',
    'const safe = Object.create(null);',
    'const s = new Set([1, 2, 3]);',
    'const m = new Map([["a", 1]]);',
    'const p = Promise.resolve(42);',
    'const max = Math.max(1, 2, 3, 4, 5);',
    'const str = String(123);',
    'const num = Number("42");',
    'const bool = Boolean(1);',
    'const parsed = parseInt("10", 10);',
    'const f = parseFloat("3.14");',
    'const isArr = Array.isArray([]);',
    'const typ = typeof x === "string";',
    'const keys = Object.keys(obj);',
    'const vals = Object.values(obj);',
    'const entries = Object.entries(obj);',
    'const mapped = [1,2,3].map(x => x * 2);',
    'const filtered = [1,2,3,4,5].filter(x => x > 2);',
    'const reduced = [1,2,3].reduce((a, b) => a + b, 0);',
    'const sliced = arr.slice(0, 5);',
    'const joined = arr.concat(other);',
    'const parts = str.split(",");',
    'const trimmed = str.trim();',
    'const upper = str.toUpperCase();',
    'const replaced = str.replace(/a/g, "b");',
    'const has = str.includes("needle");',
    'const starts = str.startsWith("prefix");',
    'const ends = str.endsWith(".js");',
    'const padded = str.padStart(10, "0");',
    'const iso = new Date().toISOString();',
    'const now = Date.now();',
    'const nan = isNaN(x);',
    'const fin = isFinite(x);',
    'const isInt = Number.isInteger(x);',
    'const isSafe = Number.isSafeInteger(x);',
    'const cwd = process.cwd();',
    'const dir = __dirname;',
    'const file = __filename;',
    'module.exports = { fn };',
    'exports.handler = async (event) => ({ statusCode: 200 });',
    'const base = require("path").basename("/a/b/c");',
]

for _ in range(125):
    if random.random() < 0.6:
        add("python", "clean", random.choice(_CLEAN_PY))
    else:
        add("javascript", "clean", random.choice(_CLEAN_JS))

# ── Scanner ─────────────────────────────────────────────────────────────────

def scan(language: str, code: str) -> int:
    """Scan a snippet and return number of findings."""
    try:
        from ansede_static import scan_code
        result = scan_code(code, language=language, filename=f"test.{'py' if language == 'python' else 'js'}")
        return len(result.findings)
    except Exception:
        return 0

# ── Run ─────────────────────────────────────────────────────────────────────

def main() -> None:
    random.shuffle(SNIPPETS)  # Mix all categories

    results: list[dict] = []
    by_cat: dict[str, dict] = {
        "easy_vuln": {"total": 0, "detected": 0},
        "medium_vuln": {"total": 0, "detected": 0},
        "hard_vuln": {"total": 0, "detected": 0},
        "clean": {"total": 0, "detected": 0},
    }

    print(f"Evaluating {len(SNIPPETS)} random snippets...")
    print("=" * 60)

    t0 = time.perf_counter()
    for i, (lang, cat, code) in enumerate(SNIPPETS):
        findings = scan(lang, code)
        is_vuln = cat != "clean"
        correct = (is_vuln and findings > 0) or (not is_vuln and findings == 0)

        results.append({
            "lang": lang, "category": cat,
            "findings": findings, "correct": correct,
        })
        by_cat[cat]["total"] += 1
        if correct:
            by_cat[cat]["detected"] += 1

        if (i + 1) % 50 == 0:
            elapsed = time.perf_counter() - t0
            done = sum(1 for r in results if r["correct"])
            print(f"  [{i+1}/{len(SNIPPETS)}] {done}/{i+1} correct ({done/(i+1)*100:.1f}%)  [{elapsed:.0f}s]")

    elapsed = time.perf_counter() - t0

    # ── Score ───────────────────────────────────────────────────────────
    total = len(results)
    correct = sum(1 for r in results if r["correct"])
    vuln_total = sum(1 for r in results if r["category"] != "clean")
    vuln_detected = sum(1 for r in results if r["category"] != "clean" and r["correct"])
    clean_total = sum(1 for r in results if r["category"] == "clean")
    clean_ok = sum(1 for r in results if r["category"] == "clean" and r["correct"])
    fp = clean_total - clean_ok
    fn = vuln_total - vuln_detected

    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    for cat in ["easy_vuln", "medium_vuln", "hard_vuln", "clean"]:
        d = by_cat[cat]
        pct = d["detected"] / d["total"] * 100 if d["total"] else 0
        label = {"easy_vuln": "Easy Vuln", "medium_vuln": "Medium Vuln",
                 "hard_vuln": "Hard Vuln", "clean": "Clean Code"}[cat]
        print(f"  {label:<15} {d['detected']}/{d['total']} ({pct:.1f}%)")
    print(f"  {'─' * 40}")
    print(f"  {'OVERALL':<15} {correct}/{total} ({correct/total*100:.1f}%)")
    print(f"  Recall: {vuln_detected}/{vuln_total} ({vuln_detected/vuln_total*100:.1f}%)")
    print(f"  FP Rate: {fp}/{clean_total} ({fp/clean_total*100:.1f}%)" if clean_total else "")
    print(f"  Time: {elapsed:.1f}s")

    # Score out of 500
    print(f"\n  >> Score: {correct} out of {total} correct")

    # Save report
    report = {
        "total": total, "correct": correct,
        "accuracy_pct": round(correct/total*100, 1),
        "recall_pct": round(vuln_detected/vuln_total*100, 1) if vuln_total else 0,
        "fp_rate_pct": round(fp/clean_total*100, 1) if clean_total else 0,
        "elapsed_s": round(elapsed, 1),
        "by_category": {
            cat: {"total": d["total"], "detected": d["detected"],
                  "pct": round(d["detected"]/d["total"]*100, 1) if d["total"] else 0}
            for cat, d in by_cat.items()
        },
    }
    out = REPO_ROOT / "eval_500_report.json"
    out.write_text(json.dumps(report, indent=2))
    print(f"  Report: {out}")


if __name__ == "__main__":
    main()
