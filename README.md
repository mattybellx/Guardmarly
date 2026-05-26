<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <img alt="Ansede Static — Offline SAST" src="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png" width="800">
  </picture>
</p>

<p align="center">
  <strong>Offline SAST engine.</strong><br>
  35 repos validated. 5 languages. Zero dependencies. LLM-assisted triage. <code>pip install ansede-static</code>
</p>

<p align="center">
  <a href="https://pypi.org/project/ansede-static"><img src="https://img.shields.io/pypi/v/ansede-static?label=pypi&color=0078D4" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/Repos%20Scanned-35-blue" alt="35 repos scanned"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/CWE%20Types-33%2B-yellow" alt="33+ CWE types"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License MIT"></a>
</p>

---

## Install & Scan

```bash
pip install ansede-static
ansede-static src/                  # scan a directory
ansede-static src/ --format sarif   # GitHub Code Scanning output
ansede-static src/ --format json    # JSON for scripting
ansede-static src/ --fail-on high   # only fail CI on high+
ansede-static src/ --incremental    # git-diff mode (monorepo-friendly)
```

Zero config. No cloud. No telemetry.

---
## What Makes It Different

Ansede models **routes, auth guards, and ownership patterns at the AST level** — catching access-control bugs that regex-only tools miss:

```python
@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    # CWE-639 IDOR: no owner filter → any user sees any invoice
    # Bandit/Semgrep OSS: silent.  ansede: CRITICAL
```

```python
@app.route("/admin/users")
def list_users():      # no @login_required
    return User.query.all()
    # CWE-862 missing auth → unauthenticated admin access
    # Bandit/Semgrep OSS: silent.  ansede: HIGH
```

---

## Benchmarks (May 2026)

Full details: [`BENCHMARKS.md`](BENCHMARKS.md)

### Real-World: 35 Open-Source Repos

| Metric | Small (25 repos, ≤2MB) | Medium (10 repos, 2-10MB) | **Combined** |
|---|---|---:|---:|
| Zero failures | ✅ | ✅ | **✅ 35/35** |
| Files / Lines | 2,873 / 333.8k | 9,499 / 1.43M | **12,372 / 1.76M** |
| Source | 12.30 MB | 58.95 MB | **71.25 MB** |
| Total findings | 1,037 | 3,612 | **4,649** |
| Findings/kLOC | 3.11 | 2.53 | **2.64** |
| CWE types | 25+ | 33 | **35+** |

**Top CWEs across all repos:**
CWE-862 (missing auth), CWE-1333 (ReDoS), CWE-798 (hardcoded creds), CWE-352 (CSRF), CWE-95 (eval injection), CWE-79 (XSS), CWE-89 (SQLi), CWE-287 (improper auth), CWE-470 (unsafe reflection), CWE-22 (path traversal)

### Synthetic Benchmarks

| Test | Result |
|---|---|
| CVE snippet recall | 100% (115/115) |
| Web-wild F1 | 92.31% |
| LLM auto-classification | 95.9% (632 findings, 7 langs) |
| Languages | Python · JS/TS · Go · Java · C# |

---

## Detection Coverage (33+ CWE types verified in real scans)

| Category | CWEs | Example |
|---|---|---|
| Missing Auth / Broken Access | 862, 287, 639, 285 | Route w/o `@login_required`, IDOR |
| Injection | 89, 78, 95, 94 | SQLi, command injection, eval |
| ReDoS | 1333 | Catastrophic backtracking |
| Hardcoded Secrets | 798 | API keys, passwords in source |
| CSRF | 352 | Missing tokens on mutating routes |
| XSS | 79 | Unsafe `innerHTML` |
| Path Traversal / SSRF | 22, 918 | Unsanitized file paths, user-controlled URLs |
| Open Redirect | 601 | User-controlled `next` param |
| Deserialization | 502 | `pickle.loads()` on untrusted input |
| Prototype Pollution | 1321 | Unsafe object merge |
| Weak Crypto | 327, 328 | MD5/SHA1 for passwords |
| Log Injection | 117 | Unsanitized input in logs |

Run `ansede-static --list-rules` for the full catalog.

---

## vs Other Tools

| | ansede-static | Bandit | Semgrep OSS | CodeQL |
|---|---|---|---|---|
| Real repos validated | **35** | 1 (Python) | Community | Limited |
| Interprocedural taint | **Full** | ❌ | ❌ (Pro) | ✅ |
| Route/auth analysis | **11 checkers** | ❌ | Basic | Limited |
| Auto-triage + clustering | **✅ 49% reduction** | ❌ | ❌ | ❌ |
| Zero dependencies | ✓ | ✗ | ✗ | ✗ |
| Offline | ✓ | ✓ | ✗ | ✗ |
| IDOR / Auth bypass | **✓** | ✗ | Partial | Partial |
| Languages | 5 | 1 | 20+ | 7 |

---

## GitHub Action

```yaml
- uses: mattybellx/Ansede@v2.3.1
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

---

## Pricing

| | Free | Pro (£4.99) |
|---|---|---|
| Scans/day | 500 | Unlimited |
| SARIF / SBOM / HTML | — | ✓ |
| IDE plugins | ✓ (VS Code, IntelliJ, VS) | ✓ |

---

## Features

**Incremental** — `--incremental` (git diff) or `--incremental-sha256` for monorepos  
**Baseline** — freeze legacy debt with `--baseline baseline.json`  
**Auto-fix** — `--apply-fixes` for safe inline patches  
**AI triage** — `--ai-triage` suppresses test/fixture FPs  
**Extras** — entropy scanning, inline suppressions, LSP server, community YAML rules, SBOM output, HTML dashboards

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q
```

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/mattybellx">Matty Bell</a>. MIT licensed. Zero telemetry. No cloud dependency.</sub>
</p>
