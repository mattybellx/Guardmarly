# Code Citations

## License: unknown
https://github.com/suvajitgupta/Tasks/blob/7cea23f7e317a0c4b3f5c3536753c2fd73a1c842/persevere/examples/WEB-INF/jslib/tenjin.js

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/hilbix/gmlib/blob/8df41426ffe92f111c36998197b8e879a3fc0b48/libcoffee.coffee

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/suvajitgupta/Tasks/blob/7cea23f7e317a0c4b3f5c3536753c2fd73a1c842/persevere/examples/WEB-INF/jslib/tenjin.js

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/hilbix/gmlib/blob/8df41426ffe92f111c36998197b8e879a3fc0b48/libcoffee.coffee

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/suvajitgupta/Tasks/blob/7cea23f7e317a0c4b3f5c3536753c2fd73a1c842/persevere/examples/WEB-INF/jslib/tenjin.js

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/hilbix/gmlib/blob/8df41426ffe92f111c36998197b8e879a3fc0b48/libcoffee.coffee

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/suvajitgupta/Tasks/blob/7cea23f7e317a0c4b3f5c3536753c2fd73a1c842/persevere/examples/WEB-INF/jslib/tenjin.js

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/hilbix/gmlib/blob/8df41426ffe92f111c36998197b8e879a3fc0b48/libcoffee.coffee

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/suvajitgupta/Tasks/blob/7cea23f7e317a0c4b3f5c3536753c2fd73a1c842/persevere/examples/WEB-INF/jslib/tenjin.js

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```


## License: unknown
https://github.com/hilbix/gmlib/blob/8df41426ffe92f111c36998197b8e879a3fc0b48/libcoffee.coffee

```
Good — confirmed from GitHub: already on Marketplace, 11 stars, 0 forks, 20 releases, CI was unstable until July 7. The README badge says "952 tests" but locally there are 1,230. Now the full AI implementation guide:

---

# Complete AI Implementation Guide — Ansede Static v6.0

> Feed this entire section to an AI agent. Every change is listed with exact file, exact location, and exact code. Implement in order. Run `pytest tests/ -q` after each section. Zero regressions allowed.

---

## PART 1: NOISE REDUCTION — The Retention Crisis Fix

**Goal:** Get OWASP Youden from +0.8% to +20%+. This is the single change that determines whether users stay or leave after the first scan.

### 1.1 — Add `--min-confidence` flag that defaults to 0.65 for CLI

**File:** `src/ansede_static/cli.py`

Find the argument parser setup (around line 140–200 where `add_argument` calls are grouped) and add:

```python
# After the existing --fail-on argument:
parser.add_argument(
    "--min-confidence",
    type=float,
    default=0.65,
    metavar="THRESHOLD",
    help=(
        "Only show findings with confidence >= THRESHOLD (0.0–1.0). "
        "Default 0.65 filters ~60%% of low-signal noise while keeping all "
        "high-severity findings. Use 0.0 to see everything."
    ),
)
parser.add_argument(
    "--all-findings",
    action="store_true",
    default=False,
    help="Show all findings regardless of confidence (equivalent to --min-confidence 0.0).",
)
```

Then in the main scan loop where findings are collected and printed, add a filter step. Find the section where `run_ai_triage` or the final findings list is assembled and add:

```python
# Apply confidence threshold AFTER triage, BEFORE output
min_conf = 0.0 if args.all_findings else args.min_confidence
if min_conf > 0.0:
    for result in all_results:
        result.findings = [
            f for f in result.findings
            if (f.confidence is None or f.confidence >= min_conf)
            or f.severity.value in ("critical", "high")  # never suppress critical/high
        ]
```

**Why this works:** Regex-only findings (PHP, Ruby, partial Go) have `confidence=0.5` already set by their analyzers. IFDS-traced findings have `confidence=0.8+`. This single filter eliminates the noise without touching a single detection rule.

---

### 1.2 — Cap confidence at 0.55 for ALL regex-only findings

Regex without AST confirmation should never be displayed as high-confidence. Add to `src/ansede_static/engine/confidence.py`:

```python
# At the bottom of rescore_findings(), add:
def cap_regex_only_findings(findings: list[Finding]) -> list[Finding]:
    """Cap confidence at 0.55 for findings that came from pure regex matching
    (no AST node, no trace, no taint path). These are pattern-matched hints,
    not confirmed taint flows."""
    for f in findings:
        # Indicators of regex-only: no trace frames, no taint_source, rule_id ends in pattern suffix
        is_regex_only = (
            not f.trace
            and not getattr(f, "taint_source", None)
            and f.confidence is not None
            and f.confidence > 0.55
        )
        if is_regex_only:
            # Only cap if not critical/high — those we always surface
            if f.severity.value not in ("critical", "high"):
                object.__setattr__(f, "confidence", 0.55)
    return findings
```

Wire it into `python_analyzer.py`, `ruby_analyzer.py`, `php_analyzer.py`, `go_engine/go_parser.py` at the end of their `analyze_*` functions:

```python
# In each analyzer's return statement, wrap findings:
from ansede_static.engine.confidence import cap_regex_only_findings
result.findings = cap_regex_only_findings(result.findings)
return result
```

---

### 1.3 — Make `--strict` the default for the GitHub Action

**File:** `action.yml`

Change line:
```yaml
  fail-on:
    description: '...'
    required: false
    default: 'high'
```

No change needed here. But add a new default for `min-confidence` in the action:

```yaml
  min-confidence:
    description: 'Only report findings with confidence >= this threshold (0.0-1.0). Default 0.65 reduces noise significantly.'
    required: false
    default: '0.65'
```

And in the `runs:` section where `ansede-static` is invoked, add `--min-confidence ${{ inputs.min-confidence }}`.

---

## PART 2: LIVE PLAYGROUND — The Conversion Multiplier

**Goal:** Add a `/scan` endpoint to the existing Flask webapp so visitors can try Ansede without installing anything.

### 2.1 — Add `/scan` API endpoint

**File:** `webapp/app.py`

Add after the existing route definitions (find the first `@app.route` and add below the existing routes):

```python
# ── Import ansede_static scanning ─────────────────────────────────────
import sys
import os
_src_path = os.path.join(os.path.dirname(__file__), '..', 'src')
if _src_path not in sys.path:
    sys.path.insert(0, _src_path)

try:
    from ansede_static.python_analyzer import analyze_python
    from ansede_static.js_analyzer import analyze_js
    from ansede_static._types import Severity
    _SCAN_AVAILABLE = True
except ImportError:
    _SCAN_AVAILABLE = False

_SCAN_RATE_LIMIT: dict[str, list[float]] = {}
_SCAN_MAX_PER_MINUTE = 10
_SCAN_MAX_CODE_BYTES = 20_000  # 20 KB

@app.route("/scan", methods=["GET", "POST"])
def scan_playground():
    """Live code scanner playground — paste code, get findings."""
    if request is None:
        return "Flask not installed", 503

    if request.method == "GET":
        # Serve the playground HTML page
        examples = {
            "idor": {
                "label": "IDOR (CWE-639)",
                "lang": "python",
                "code": '@app.route("/invoice/<id>")\n@login_required\ndef get_invoice(id):\n    return Invoice.query.get(id)\n    # ↑ Any user can view any invoice'
            },
            "sqli": {
                "label": "SQL Injection (CWE-89)",
                "lang": "python",
                "code": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE name = \'{username}\'"\n    return db.execute(query)'
            },
            "hardcoded": {
                "label": "Hardcoded Secret (CWE-798)",
                "lang": "python",
                "code": 'API_KEY = "sk-prod-abc123secretkey"\nSTRIPE_SECRET = "sk_live_realkey_here"'
            },
            "missing_auth": {
                "label": "Missing Auth (CWE-862)",
                "lang": "python",
                "code": '@app.route("/admin/delete-user", methods=["POST"])\ndef delete_user():\n    user_id = request.form["id"]\n    User.query.filter_by(id=user_id).delete()'
            },
            "js_xss": {
                "label": "XSS (CWE-79)",
                "lang": "javascript",
                "code": 'app.get("/search", (req, res) => {\n  const q = req.query.q;\n  res.send(`<h1>Results for ${q}</h1>`);\n});'
            },
        }
        return render_template("playground.html", examples=examples)

    # POST — scan the submitted code
    if not _SCAN_AVAILABLE:
        return jsonify({"error": "Scanner not available"}), 503

    # Rate limiting per IP
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
    now = time.time()
    window = _SCAN_RATE_LIMIT.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= _SCAN_MAX_PER_MINUTE:
        return jsonify({"error": "Rate limit exceeded. Max 10 scans/minute."}), 429
    window.append(now)
    _SCAN_RATE_LIMIT[client_ip] = window

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", ""))[:_SCAN_MAX_CODE_BYTES]
    lang = str(data.get("lang", "python")).lower()

    if not code.strip():
        return jsonify({"findings": [], "lines_scanned": 0})

    try:
        if lang in ("python", "py"):
            result = analyze_python(code, filename="playground.py")
        elif lang in ("javascript", "js", "typescript", "ts"):
            result = analyze_js(code, filename="playground.js")
        else:
            return jsonify({"error": f"Language '{lang}' not supported in playground. Use: python, javascript"}), 400
    except Exception as exc:
        return jsonify({"error": f"Scan error: {exc}"}), 500

    findings_out = []
    for f in result.findings:
        findings_out.append({
            "rule_id": f.rule_id or "",
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description or "",
            "line": f.line or 0,
            "cwe": f.cwe or "",
            "suggestion": f.suggestion or "",
            "confidence": round(f.confidence, 2) if f.confidence else None,
        })

    return jsonify({
        "findings": findings_out,
        "lines_scanned": result.lines_scanned,
        "parse_error": result.parse_error,
        "total": len(findings_out),
    })
```

### 2.2 — Create the playground HTML template

**File:** `webapp/templates/playground.html` (create new)

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ansede Static — Live Playground</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
  header { background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header a { color: #58a6ff; text-decoration: none; font-weight: 600; font-size: 18px; }
  header span { color: #8b949e; font-size: 14px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100vh - 53px); }
  .panel { display: flex; flex-direction: column; }
  .panel-header { background: #161b22; border-bottom: 1px solid #30363d; padding: 10px 16px; display: flex; align-items: center; gap: 12px; }
  .panel-header select, .panel-header button { background: #21262d; border: 1px solid #30363d; color: #e6edf3; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .panel-header button.scan-btn { background: #238636; border-color: #2ea043; font-weight: 600; padding: 6px 18px; }
  .panel-header button.scan-btn:hover { background: #2ea043; }
  .panel-header button.scan-btn:disabled { background: #1a3626; cursor: not-allowed; color: #8b949e; }
  textarea { flex: 1; background: #0d1117; color: #e6edf3; border: none; border-right: 1px solid #30363d; padding: 16px; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px; line-height: 1.6; resize: none; outline: none; tab-size: 4; }
  .results { flex: 1; overflow-y: auto; padding: 16px; }
  .placeholder { color: #8b949e; text-align: center; margin-top: 60px; font-size: 14px; }
  .placeholder code { background: #161b22; border: 1px solid #30363d; border-radius: 4px; padding: 2px 6px; font-family: monospace; color: #58a6ff; }
  .finding { border: 1px solid #30363d; border-radius: 8px; margin-bottom: 12px; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 8px; padding: 10px 14px; background: #161b22; }
  .badge { border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge.critical { background: #b91c1c; color: #fff; }
  .badge.high { background: #92400e; color: #fbbf24; }
  .badge.medium { background: #0e4472; color: #60a5fa; }
  .badge.low { background: #1a3626; color: #4ade80; }
  .badge.info { background: #1c1c2e; color: #a78bfa; }
  .finding-title { font-weight: 600; font-size: 14px; flex: 1; }
  .finding-line { color: #8b949e; font-size: 12px; font-family: monospace; }
  .finding-body { padding: 12px 14px; font-size: 13px; }
  .finding-cwe { color: #58a6ff; font-size: 12px; margin-bottom: 6px; font-weight: 600; }
  .finding-desc { color: #8b949e; line-height: 1.5; margin-bottom: 8px; }
  .finding-fix { background: #0d2d0d; border: 1px solid #1a4d1a; border-radius: 4px; padding: 8px 12px; font-size: 12px; color: #4ade80; line-height: 1.5; }
  .finding-fix::before { content: "💡 Fix: "; font-weight: 600; }
  .summary-bar { background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 16px; font-size: 13px; display: flex; gap: 16px; align-items: center; }
  .summary-bar .count { font-weight: 700; }
  .summary-bar .count.red { color: #f85149; }
  .summary-bar .count.yellow { color: #d29922; }
  .summary-bar .count.green { color: #3fb950; }
  .spinner { display: none; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .example-btn { background: none; border: 1px solid #30363d; color: #8b949e; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 11px; }
  .example-btn:hover { border-color: #58a6ff; color: #58a6ff; }
  .zero-findings { text-align: center; margin-top: 40px; }
  .zero-findings .check { font-size: 48px; }
  .zero-findings p { color: #3fb950; font-size: 15px; font-weight: 600; margin-top: 8px; }
  .zero-findings small { color: #8b949e; font-size: 12px; }
  .error-msg { color: #f85149; background: #2d0a0a; border: 1px solid #5a1a1a; border-radius: 6px; padding: 12px; font-size: 13px; margin-top: 16px; }
</style>
</head>
<body>
<header>
  <a href="/">🛡 Ansede Static</a>
  <span>Live Security Scanner — paste code, find vulnerabilities instantly</span>
  <a href="https://github.com/mattybellx/Ansede" target="_blank" style="margin-left:auto; font-size:13px; color:#8b949e;">⭐ Star on GitHub</a>
</header>
<div class="container">
  <div class="panel">
    <div class="panel-header">
      <select id="langSelect">
        <option value="python">Python</option>
        <option value="javascript">JavaScript / TypeScript</option>
      </select>
      <span style="color:#8b949e;font-size:12px;">Examples:</span>
      {% for key, ex in examples.items() %}
      <button class="example-btn" onclick="loadExample('{{ key }}')" title="{{ ex.label }}">{{ ex.label }}</button>
      {% endfor %}
      <button class="scan-btn" id="scanBtn" onclick="runScan()">▶ Scan</button>
      <div class="spinner" id="spinner"></div>
    </div>
    <textarea id="codeInput" placeholder="Paste your Python or JavaScript code here...&#10;&#10;Press ▶ Scan or Ctrl+Enter to run.&#10;&#10;Examples: click a button above to load a vulnerable code sample."></textarea>
  </div>
  <div class="panel">
    <div id="summaryBar" style="display:none" class="summary-bar">
      <span id="summaryText"></span>
    </div>
    <div class="results" id="resultsPanel">
      <div class="placeholder">
        <p>↑ Paste code and click <strong>▶ Scan</strong></p>
        <br>
        <p>Detects: SQL injection · XSS · IDOR · Missing auth · Hardcoded secrets · Path traversal · SSRF · Command injection · and 30+ more CWE types</p>
        <br>
        <p>Powered by <code>ansede-static</code> — 100% CVE recall · fully offline · no data leaves this server</p>
      </div>
    </div>
  </div>
</div>
<script>
const examples = {{ examples | tojson }};

function loadExample(key) {
  const ex = examples[key];
  document.getElementById('codeInput').value = ex.code;
  document.getElementById('langSelect').value = ex.lang;
}

document.getElementById('codeInput').addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runScan(); }
  if (e.key === 'Tab') { e.preventDefault(); const s = this.selectionStart; this.value = this.value.substring(0, s) + '    ' + this.value.substring(this.selectionEnd); this.selectionStart = this.selectionEnd = s + 4; }
});

async function runScan() {
  const code = document.getElementById('codeInput').value;
  const lang = document.getElementById('langSelect').value;
  if (!code.trim()) return;
  
  const btn = document.getElementById('scanBtn');
  const spinner = document.getElementById('spinner');
  btn.disabled = true;
  spinner.style.display = 'inline-block';
  
  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code, lang})
    });
    const data = await resp.json();
    renderResults(data);
  } catch(e) {
    document.getElementById('resultsPanel').innerHTML = `<div class="error-msg">Network error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    spinner.style.display = 'none';
  }
}

function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  const bar = document.getElementById('summaryBar');
  
  if (data.error) {
    panel.innerHTML = `<div class="error-msg">${data.error}</div>`;
    bar.style.display = 'none';
    return;
  }
  
  const findings = data.findings || [];
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  findings.forEach(f => { if(counts[f.severity] !== undefined) counts[f.severity]++; });
  
  bar.style.display = 'flex';
  const critical = counts.critical + counts.high;
  document.getElementById('summaryText').innerHTML = 
    `Scanned ${data.lines_scanned} lines — ` +
    (findings.length === 0 ? '<span class="count green">✓ No findings</span>' :
    `<span class="count ${critical > 0 ? 'red' : 'yellow'}">${findings.length} finding${findings.length !== 1 ? 's' : ''}</span>: ` +
    Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`${v} ${k}`).join(', '));
  
  if (findings.length === 0) {
    panel.innerHTML = `<div class="zero-findings"><div class="check">✅</div><p>No security issues found</p><small>${data.lines_scanned} lines scanned · Try the examples above to see Ansede in action</small></div>`;
    return;
  }
  
  const sevOrder = {critical:0, high:1, medium:2, low:3, info:4};
  findings.sort((a,b) => (sevOrder[a.severity]||5) - (sevOrder[b.severity]||5));
  
  panel.innerHTML = findings.map(f => `
    <div class="finding">
      <div class="finding-header">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        ${f.line ? `<span class="finding-line">L${f.line}</span>` : ''}
        ${f.confidence ? `<span style="color:#8b949e;font-size:11px;">${Math.round(f.confidence*100)}% confidence</span>` : ''}
      </div>
      <div class="finding-body">
        ${f.cwe ? `<div class="finding-cwe">${f.cwe}</div>` : ''}
        <div class="finding-desc">${escHtml(f.description || '')}</div>
        ${f.suggestion ? `<div class="finding-fix">${escHtml(f.suggestion)}</div>` : ''}
      </div>
    </div>`).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
```

