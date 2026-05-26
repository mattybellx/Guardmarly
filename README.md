<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <img alt="Ansede Static — World's Best Offline SAST" src="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png" width="800">
  </picture>
</p>

<p align="center">
  <strong>Offline static application security testing engine.</strong><br>
  Zero dependencies. Real-world validated. 5 languages. LLM-assisted triage. Ships as a single <code>.exe</code>.
</p>

<p align="center">
  <a href="https://github.com/mattybellx/Ansede/releases"><img src="https://img.shields.io/github/v/release/mattybellx/Ansede?display_name=tag&sort=semver&label=release&color=0078D4" alt="Release"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/v/ansede-static?label=pypi&color=0078D4" alt="PyPI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=downloads&color=107C10" alt="Downloads"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/Real%20Repos%20Scanned-35-blue" alt="35 real repos scanned"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/CWE%20Types-33%2B-yellow" alt="33+ CWE types"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/LLM%20Triage-96%25%20auto-yellowgreen" alt="LLM Auto 96%"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License MIT"></a>
  <a href="https://github.com/mattybellx/Ansede/stargazers"><img src="https://img.shields.io/github/stars/mattybellx/Ansede?style=social" alt="Stars"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#what-makes-it-different">Why Ansede</a> ·
  <a href="#verified-performance">Benchmarks</a> ·
  <a href="#detection-coverage">Coverage</a> ·
  <a href="#comparison">vs Bandit/Semgrep/CodeQL</a> ·
  <a href="#pricing">Pricing</a>
</p>

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/
```

That's it. No config files. No cloud. No telemetry.

[![PyPI version](https://img.shields.io/pypi/v/ansede-static?label=pypi&color=0078D4)](https://pypi.org/project/ansede-static/)
[![Downloads](https://img.shields.io/pypi/dm/ansede-static?label=downloads&color=107C10)](https://pypi.org/project/ansede-static/)
[![CI](https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mattybellx/Ansede/actions/workflows/ci.yml)

---
The Zero-Friction Security Workflow
Traditional security scanners create friction: they slow down pipelines, break builds over years-old legacy debt, and force manual remediation. Ansede is engineered differently. Scanning at a verified 0.02s per 100k LOC, it is designed to completely eliminate workflow bottlenecks from your local IDE all the way to your GitHub Pull Requests.
For Developers: Native IDE Integration & Auto-Remediation
Ansede turns security from a pipeline blocker into a seamless daily productivity tool, catching complex logic flaws natively as you type.
Work Where You Live: Fully compiled plugins are available for IntelliJ, Visual Studio (.vsix), and VS Code.
Heuristic Auto-Remediation: Stop manually hunting for fixes. Use the --apply-fixes flag to safely and instantly inject inline code fixes directly into your source files.
Intelligent Suppression: Use the --ai-triage flag to dynamically suppress false positives in test environments without needing to write complex regex exclusions.
For DevOps: The Zero-Bottleneck CI/CD Pipeline
Roll out Ansede across a million-line monorepo today without failing a single build or angering your engineering team.
Freeze Legacy Debt: Use the free --baseline baseline.json flag to ignore every existing bug in your codebase. Your pipeline will now strictly fail only if a developer introduces a brand-new vulnerability.
Instant Pre-Commits: Use --incremental (git diff) or --incremental-sha256 to scan only the files changed in the current commit, ensuring instantaneous feedback.
Ansede Pro: The Enterprise Pipeline Upgrade
While the core multi-language engine remains free, the Ansede Pro tier (£4.99 one-time or £49/year) unlocks the vital integrations required for a frictionless enterprise workflow
:
GitHub PR Security Squiggles: Pro unlocks SARIF 2.1.0 output. Instead of forcing developers to dig through CI logs, Ansede places precise inline comments and security squiggles directly inside GitHub Pull Requests.
Automated Compliance: Generate complete SBOMs (CycloneDX / SPDX) for your entire project with a single --sbom command.
Security Observability: Generate interactive HTML dashboards (--format html) for security teams to track vulnerability reduction and noise quotients over time.
Stop wasting engineering hours on manual remediation and pipeline bottlenecks.

**[Upgrade to Pro →](https://ansede.onrender.com)**
## What makes it different

Existing SAST tools detect `subprocess(shell=True)`. They miss the bugs that actually appear in CVE databases:

```python
# CWE-639 — Insecure Direct Object Reference
# Bandit: silent.   Semgrep OSS: silent.   ansede-static: CRITICAL

@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    #     ^ no WHERE user_id = current_user.id  →  any user can see any invoice
```

```python
# CWE-862 — Missing Authentication on admin endpoint
# Bandit: silent.   Semgrep OSS: silent.   ansede-static: HIGH

@app.route("/admin/users")
def list_users():      # no @login_required, no permission check
    return User.query.all()
```

```python
# CWE-285 — Missing Ownership Check on destructive action
# Bandit: silent.   Semgrep OSS: silent.   ansede-static: HIGH

@app.route("/post/<post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    Post.query.filter_by(id=post_id).delete()
    # no if post.author_id != current_user.id: abort(403)
```

**ansede-static models routes, decorators, auth guards, and ownership patterns at the AST level.** This is how it catches access-control vulnerabilities that regex-only tools miss.

---

## Install

```bash
pip install ansede-static

# Or download the standalone .exe (zero Python required):
# https://github.com/mattybellx/Ansede/releases/latest
```

```bash
# Scan a directory
ansede-static src/

# SARIF for GitHub Code Scanning
ansede-static src/ --format sarif --output results.sarif

# JSON for scripting
ansede-static src/ --format json --output findings.json

# Only fail CI on critical findings
ansede-static src/ --fail-on critical

# Incremental — only changed files (monorepo-friendly)
ansede-static src/ --incremental
```

---

## Verified Performance — May 2026

For the full methodology and raw data, see [`BENCHMARKS.md`](BENCHMARKS.md).

### Real-World Validation — 35 Repos Scanned

ansede-static has been run against **35 real open-source repos** totaling over **71 MB of supported source code** across **5 languages**. Every finding was classified by the audit engine.

| Metric | 25 Small (≤2MB) | 10 Medium (2-10MB) | **Combined** |
|---|---|---:|---:|
| Repos scanned | 25 | 10 | **35** |
| Zero failures | ✅ | ✅ | **✅ 35/35** |
| Files scanned | 2,873 | 9,499 | **12,372** |
| Lines scanned | 333,811 | 1,426,143 | **1,759,954** |
| Source MB | 12.30 | 58.95 | **71.25 MB** |
| Total findings | 1,037 | 3,612 | **4,649** |
| Findings per kLOC | 3.11 | 2.53 | **2.64** |
| CWE types detected | 25+ | 33 | **35+** |
| True Positives | — | 11 | **11+** |
| NEEDS_REVIEW | — | 1,224 | **1,224+** |

**Top CWEs detected across all repos:** CWE-862 (missing auth), CWE-1333 (ReDoS), CWE-798 (hardcoded creds), CWE-352 (CSRF), CWE-95 (eval injection), CWE-79 (XSS), CWE-89 (SQLi).

### Synthetic Benchmarks

| Benchmark | Result |
|---|---|
| NVD CVE snippet recall | **100%** (115/115 synthetic cases) |
| Web-wild recall | **100%** (6/6 vulnerable-by-design apps) |
| Web-wild F1 | **92.31%** |
| LLM auto-classification | **95.9%** across 632 findings, 7 languages |
| Languages | Python · JavaScript · TypeScript · Go · Java · C# |

**Honest note:** CVE snippet benchmarks measure pattern coverage, not real-world field performance. The real-world benchmark data above is the best measure of actual field behavior.

---

## Detection Coverage

| Category | CWEs detected (verified in fresh benchmark) | Example |
|---|---|---|---|
| Missing Authentication | CWE-862, CWE-287 | Route missing `@login_required` |
| IDOR / Broken Access Control | CWE-639, CWE-285 | No ownership check on DB query |
| Injection (SQL, Command, Eval) | CWE-89, CWE-78, CWE-95, CWE-94 | SQLi via f-string, `subprocess(shell=True)`, eval injection |
| ReDoS | CWE-1333 | Catastrophic backtracking in regex patterns |
| Hardcoded Credentials | CWE-798 | API tokens, AWS keys, passwords in source |
| CSRF | CWE-352 | Missing CSRF tokens on mutating routes |
| XSS | CWE-79 | `innerHTML` with user data |
| Path Traversal & SSRF | CWE-22, CWE-918 | Unsanitized `os.path.join`, user-controlled URLs |
| Open Redirect | CWE-601 | User-controlled `next` in `redirect()` |
| Deserialization | CWE-502 | `pickle.loads()` on untrusted input |
| Prototype Pollution | CWE-1321 | Unsafe object merge |
| Log Injection | CWE-117 | Unsanitized input in log messages |
| Weak Cryptography | CWE-327, CWE-328 | MD5/SHA1 for passwords |
| And more | 33+ CWE types detected in one 10-repo run | See `ansede-static --list-rules` |

---

## GitHub Action

```yaml
# .github/workflows/security.yml
- uses: mattybellx/Ansede@v2.2.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
    license-key: ${{ secrets.ANSEDE_LICENSE_KEY }}
```

---

## Pricing

| | Free | Pro |
|---|---|---|
| Scans per day | 500 | Unlimited |
| Languages | 5 | 5 |
| Text & JSON output | ✓ | ✓ |
| SARIF (GitHub Code Scanning) | — | ✓ |
| SBOM (CycloneDX / SPDX) | — | ✓ |
| HTML dashboard | — | ✓ |
| CI/CD recipes | — | ✓ |
| Price | Free | [£4.99 one-time](https://ansede.onrender.com) or [£49/year](https://ansede.onrender.com) |

**[Upgrade to Pro →](https://ansede.onrender.com)**

---

## Features

- **Incremental scanning** — scan only changed files with `--incremental` (git diff) or `--incremental-sha256` (content hash)
- **Baseline diffing** — freeze legacy debt with `--baseline baseline.json`, only fail on new findings
- **Auto-fix** — apply safe inline fixes with `--apply-fixes`
- **AI triage** — suppress test/mock/fixture false positives with `--ai-triage`
- **Parallel workers** — speed up large repos with `--parallel`
- **Entropy scanning** — detect hardcoded secrets in string literals with `--entropy`
- **`ansede.json` config** — per-project rules, exclusions, and custom sinks via `--init`
- **Inline suppression** — `# ansede: ignore[CWE-862]` on any line
- **LSP server** — IDE integration via `--lsp`
- **VS Code extension** — [Install from Marketplace](https://marketplace.visualstudio.com/items?itemName=ansede.ansede-static)
- **Community rules** — YAML-based custom rule packs under `~/.ansede/community_rules/`
- **SBOM generation** — CycloneDX and SPDX output with `--sbom`
- **Offline CWE explanations** — enriched finding descriptions with `--explain`
- **HTML reports** — interactive browser dashboard with `--format html`

---

## Comparison

| | ansede-static | Bandit OSS | Semgrep OSS | CodeQL CLI |
|---|---|---|---|---|
| Real repos validated | **35** | 1 (Python only) | Community | Limited |
| CWE types detected | **33+** in one run | ~10 | ~15-25 | ~25-40 |
| Interprocedural taint | **Full** | ❌ | ❌ (Pro only) | ✅ |
| Route/auth analysis | **11 checkers** | ❌ | Basic patterns | Limited |
| Auto-triage + clustering | **✅ 49% reduction** | ❌ | ❌ | ❌ |
| Offline (no network) | ✓ | ✓ | ✗ | ✗ |
| Zero dependencies | ✓ | ✗ | ✗ | ✗ |
| Single binary (.exe) | ✓ | ✗ | ✗ | ✗ |
| IDOR / Auth bypass | **✓** | ✗ | Partial | Partial |
| Languages | 5 | 1 | 20+ | 7 |
| Install size | <5 MB | ~15 MB | ~200 MB | ~600 MB |

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines, [`docs/writing-rules.md`](docs/writing-rules.md) for building custom rules, and [`docs/zero-friction-ci-rollout.md`](docs/zero-friction-ci-rollout.md) for adoption playbooks.

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/mattybellx">Matty Bell</a>. MIT licensed. Zero telemetry. No cloud dependency.</sub>
</p>
