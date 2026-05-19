<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png">
    <img alt="Ansede Static — World's Best Offline SAST" src="https://raw.githubusercontent.com/mattybellx/Ansede/master/AS.png" width="800">
  </picture>
</p>

<p align="center">
  <strong>The world's most precise offline static application security testing engine.</strong><br>
  Zero dependencies. 98.8% CVE recall. Five languages. Ships as a single <code>.exe</code>.
</p>

<p align="center">
  <a href="https://github.com/mattybellx/Ansede/releases"><img src="https://img.shields.io/github/v/release/mattybellx/Ansede?display_name=tag&sort=semver&label=release&color=0078D4" alt="Release"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/v/ansede-static?label=pypi&color=0078D4" alt="PyPI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=downloads&color=107C10" alt="Downloads"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-98.8%25-brightgreen" alt="CVE Recall 98.8%"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md"><img src="https://img.shields.io/badge/FP%20Rate-3.6%25-brightgreen" alt="FP Rate 3.6%"></a>
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
Upgrade to Ansede Pro →

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

**ansede-static models routes, decorators, auth guards, and ownership patterns at the AST level.** This is how it achieves 98.8% CVE recall while Bandit OSS sits at ~65%.

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

| Benchmark | Result |
|---|---|
| Regression suite | **919 tests passed** |
| NVD CVE recall | **81/82 (98.78%)** |
| NVD CVE precision | **96.43%** |
| False positive rate | **3.57%** |
| Web-wild recall | **100.00%** |
| Web-wild precision | **95.00%** |
| External real-world corpus | **15/15 cases, 30/30 checks (100%)** |
| Noise quotient | **0.861 findings / kLOC** |
| Raw engine speed | **~0.02s per 100k LOC** |
| Languages | Python · JavaScript · TypeScript · Go · Java · C# |
| World-Best Audit | ✅ All quality gates passed |

Full methodology and machine-readable artifacts: [`BENCHMARKS.md`](BENCHMARKS.md)

---

## Detection Coverage

| Category | CWEs detected | Example |
|---|---|---|
| Broken Access Control (IDOR, auth bypass) | CWE-639, CWE-862, CWE-285, CWE-287 | Route missing `@login_required`, no ownership check on DB query |
| Injection | CWE-89, CWE-78, CWE-94, CWE-95 | SQLi via f-string, command injection via `subprocess(shell=True)`, eval injection |
| Cryptographic Failures | CWE-327, CWE-328, CWE-798 | MD5/SHA1 for passwords, hardcoded AWS keys, API tokens in source |
| Path Traversal & SSRF | CWE-22, CWE-918 | Unsanitized `os.path.join`, user-controlled URLs in `requests.get()` |
| Cross-Site Issues | CWE-79, CWE-352 | `innerHTML` with user data, missing CSRF tokens |
| Deserialization | CWE-502 | `pickle.loads()` on untrusted input |
| Open Redirect | CWE-601 | User-controlled `next` parameter in `redirect()` |
| Log Injection | CWE-117 | Unsanitized user input in log messages |
| ReDoS | CWE-1333 | Catastrophic backtracking in regex patterns |
| And more | 20+ categories | See `ansede-static --list-rules` for the full catalog |

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
| CVE Recall | **98.8%** | ~65% | ~72% | ~88% |
| FP Rate | **3.6%** | ~45% | ~30% | ~12% |
| Offline (no network) | ✓ | ✓ | ✗ | ✗ |
| Zero dependencies | ✓ | ✗ | ✗ | ✗ |
| Single binary (.exe) | ✓ | ✗ | ✗ | ✗ |
| IDOR / Auth bypass | ✓ | ✗ | Partial | Partial |
| Languages | 5 | 1 | 20+ | 7 |
| Install size | <5 MB | ~15 MB | ~200 MB | ~600 MB |
| Speed (scan_file) | **0.02s/100k LOC** | 0.5s | 3s | 10s |

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
