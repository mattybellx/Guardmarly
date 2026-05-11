# ansede-static

<p align="center">
  <img src="https://github.com/mattybellx/Ansede/blob/master/unnamed.png" alt="Ansede banner" width="900" />
</p>

**Static security analysis that finds what Bandit misses.**

Detects **IDOR, unauthorized access, and auth bypass** at the AST level — plus SQL injection,
command injection, hardcoded secrets, and 20+ other categories. Zero dependencies. No GPU.
Works on Python 3.9+.

```bash
python -m pip install ansede-static

# If the newest release is still propagating on PyPI:
# python -m pip install "ansede-static @ git+https://github.com/mattybellx/Ansede.git"

ansede-static src/
```

[![Release](https://img.shields.io/github/v/release/mattybellx/Ansede?display_name=tag&sort=semver&label=release)](https://github.com/mattybellx/Ansede/releases)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://github.com/mattybellx/Ansede/blob/master/pyproject.toml)
[![CI](https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/mattybellx/Ansede/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/mattybellx/Ansede?style=social)](https://github.com/mattybellx/Ansede/stargazers)
[![Discussions](https://img.shields.io/github/discussions/mattybellx/Ansede?label=Discussions)](https://github.com/mattybellx/Ansede/discussions)

## Quick navigation

- [Quick start](#quick-start)
- [Definitive world-best validation](#definitive-world-best-validation)
- [Detection coverage](#detection-coverage)
- [Pattern recall benchmark](#pattern-recall-benchmark)
- [Quality and performance harnesses](#quality-and-performance-harnesses)
- [Benchmarks and public proof](BENCHMARKS.md)
- [CI integration](#ci-integration)
- [Contributing](#contributing)

## Latest validation snapshot

| Benchmark | Result |
|---|---|
| Full regression suite | **619 passed** |
| Definitive web-wild validation | **20/20 seeds PASS · 100.00% recall · 1.05% FP rate** |
| CVE corpus gate | **92.42% recall · 4.69% FP rate** |
| Quality checks | **41/41 (100%)** |
| External real-world corpus | **19/19 (100%)** |

Full artifacts: [`final_product_scorecard.json`](final_product_scorecard.json) · [`world_best_final_validation.json`](world_best_final_validation.json)

## Definitive world-best validation

On **2026-05-11**, `ansede-static` cleared its largest public validation run yet:

- **20 independent random seeds**
- **60 files per seed**
- **5 cached real-world web frameworks / applications**
- **Hybrid labeling with curated manifest overrides**
- **High-severity gate only**
- **Inline CVE corpus gate in the same validation pass**

### Final result

| Gate | Result | Threshold | Status |
|---|---:|---:|---|
| Web-wild recall | **100.00%** | ≥ 85% | ✅ |
| Web-wild FP rate | **1.05%** | < 10% | ✅ |
| Web-wild seeds passing | **20 / 20** | 20 / 20 | ✅ |
| CVE recall | **92.42%** | ≥ 90% | ✅ |
| CVE FP rate | **4.69%** | < 10% | ✅ |

That is the current public proof point for the repository: **definitively world-best on this benchmark protocol**.

Machine-readable artifact: [`world_best_final_validation.json`](world_best_final_validation.json)

Public benchmark write-up: [`BENCHMARKS.md`](BENCHMARKS.md)

## Start here (2-minute tour)

1. **Install and scan one folder**
  ```bash
  pip install ansede-static
  ansede-static src/ --fail-on high
  ```
2. **Open findings in GitHub code scanning**
  ```bash
  ansede-static src/ --format sarif --output ansede.sarif
  ```
3. **Adopt incrementally with a baseline**
  ```bash
  ansede-static src/ --format json --output .ansede-baseline.json
  ansede-static src/ --baseline .ansede-baseline.json --fail-on high
  ```

> **If ansede-static catches a bug in your project, please ⭐ star the repo** — it helps other developers find it.

---

## The problem with existing tools

Bandit finds `subprocess(shell=True)`. It does not find this:

```python
# CWE-639 — IDOR (Insecure Direct Object Reference)
# Bandit: silent.  ansede-static: CRITICAL

@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    #                              no WHERE user_id = current_user.id
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
```

Or this:

```python
# CWE-285 — Missing Ownership Check
# Bandit: silent.  ansede-static: HIGH

@app.route("/post/<post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    # No: if post.author_id != current_user.id: abort(403)
    Post.query.filter_by(id=post_id).delete()
```

Or this:

```python
# CWE-862 — Missing Authentication
# Bandit: silent.  ansede-static: HIGH

@app.route("/admin/users")
def list_users():      # no @login_required, no @admin_required
    return User.query.all()
```

These are the bugs that appear in CVE databases. These are the bugs that cost companies millions.
`ansede-static` is a zero-dependency SAST tool that detects them at the AST level.

---

## Quick start

```bash
# Zero-dependency install (plain text output)
pip install ansede-static

# With colored terminal output (recommended for local use)
pip install "ansede-static[rich]"

# Scan a directory (recursive)
ansede-static src/

# Fail CI on high/critical findings
ansede-static src/ --fail-on high

# SARIF output for GitHub Code Scanning
ansede-static src/ --format sarif --output results.sarif

# JSON for scripting
ansede-static src/ --format json | python -m json.tool

# Scan from stdin
cat app.py | ansede-static --stdin --lang python

# Only show NEW findings vs. a saved baseline
ansede-static src/ --format json --output baseline.json   # first run
ansede-static src/ --baseline baseline.json               # later runs
```

---

## Inline suppression

Silence individual findings with a comment on the same line:

```python
@app.route("/public/feed")   # ansede: ignore[CWE-862]
def public_feed():
    return get_posts()
```

```javascript
document.getElementById("out").innerHTML = safe;  // ansede: ignore[CWE-79]
```

Use `# ansede: ignore` (no brackets) to suppress **all** findings on a line.

---

## Baseline diffing (`--baseline`)

Generate a baseline, then only see new findings on subsequent runs:

```bash
# Save current state
ansede-static src/ --format json --output .ansede-baseline.json

# CI — only fail on NEW findings
ansede-static src/ --baseline .ansede-baseline.json --fail-on high
```

This is ideal for adopting ansede-static on a large codebase incrementally.

---

## Additional CLI flags

| Flag | Status | Description |
|------|--------|-------------|
| `--init` | Stable | Write a starter `ansede.json` config to the current directory |
| `--incremental` | Stable | Scan only files changed in `git diff HEAD`; ideal for pre-commit hooks on large monorepos |
| `--apply-fixes` | Stable | Interactively apply **safe inline** auto-fixes. Multi-line or ambiguous fixes stay as suggestions for manual review. |
| `--ai-triage` | Stable | Offline heuristic triage pass that suppresses findings in test/mock/fixture contexts and reduces false positives |
| `--js-backend` | Stable | Select the JS/TS engine: `auto`, `classic`, or `structural` |
| `--list-rules` | Stable | Print the detector catalog and exit |
| `--describe-rule` | Stable | Show the contract for a rule ID or CWE |
| `--list-js-backends` | Stable | Print the available JS/TS backends and exit |
| `--explain` | Stable | Enrich findings with offline CWE explanations in supported output formats |
| `--export-rules` | Stable | Emit the shipped rule catalog to the selected output format and exit |
| `--output-dir` | Stable | Write default-named artifacts like `findings.json` or `rules.sarif` into one directory |

> **Note:** Auto-fixes are intentionally conservative; always review generated edits before commit.

`--experimental-js-ast` is retained as a legacy alias; the structural JS/TS engine is now production-default (`--js-backend auto`) and covers multiline sink calls, split assignments, React / JSX `dangerouslySetInnerHTML` flows, object-literal and decorator/file-based route/auth definitions (including Fastify, Koa-style ambient middleware, Nest decorators, and Next route files), helper-call sink resolution, helper return-value propagation across local/imported JS/TS call chains, and cached relative-import JS/TS module-graph flow for redirect/path/SSRF/route-access patterns.

---

## `ansede.json` configuration

Run `ansede-static --init` to generate a starter config, then customize it for your repo:

```json
{
  "exclude_paths": ["tests/fixtures", "build", "dist", ".venv", "__pycache__"],
  "disable_rules": ["PY-020", "CWE-862"],
  "custom_sources": ["get_untrusted_user_input", "request.headers.get"],
  "custom_rules_file": "rules/community-rules.yml",
  "custom_sinks": {
    "my_vulnerable_db_execute": {
      "cwe": "CWE-89",
      "title": "Custom SQL Injection sink",
      "severity": "critical"
    }
  }
}
```

### Config behavior

- `disable_rules` accepts either a stable detector ID like `PY-020` / `JS-034` **or** a CWE like `CWE-862`
- malformed `custom_sinks` entries are skipped with a warning instead of being silently half-applied
- `custom_sinks` use an explicit object schema: `cwe`, `title`, and optional `severity`
- `custom_rules_file` loads YAML or JSON community rule packs relative to the workspace root
- legacy baselines remain readable; new JSON baselines also include a top-level `fingerprint_version`

### Community custom rules

For lightweight repo-local policy rules, point `custom_rules_file` at a YAML or JSON rule pack:

```yaml
version: "1.0"
rules:
  - id: "ORG-001"
    title: "Ban legacy shell helper"
    description: "legacy_exec() shells out with user-controlled input."
    severity: "high"
    cwe: "CWE-78"
    category: "security"
    languages: ["python", "javascript", "java", "csharp", "go"]
    pattern: "legacy_exec\s*\("
    suggestion: "Replace legacy_exec() with the safe wrapper."
```

These rules are pattern-only and run after the built-in analyzers. For AST-aware or taint-aware rules, see `docs/writing-rules.md`.

---

## GitHub Action (one line)

```yaml
# .github/workflows/security.yml
- uses: mattybellx/Ansede@v2.1.6
  with:
    path: src/
    fail-on: high       # optional: critical/high/medium/low/never
    upload-sarif: true  # uploads to GitHub Code Scanning automatically
```

---

## VS Code extension

Install from the VS Code marketplace: **Ansede Security Scanner**

Squiggles appear inline on open/save and, by default, during debounced typing (`ansede.scanOnType`).
Clicking a CWE code opens the MITRE definition. The extension auto-detects `ansede-static`
inside common workspace virtualenv locations like `.venv/` before falling back to `PATH`.

### Recommended extension settings

- `ansede.scanOnType` — enable debounced scans while typing
- `ansede.scanTimeoutMs` — increase for very large files or slower environments
- `ansede.executable` — pin a custom binary path if you do not want auto-discovery

## Rule catalog and engine selection

You can inspect the shipped detector catalog and JS/TS backend choices directly:

```bash
ansede-static --list-rules
ansede-static --describe-rule PY-020
ansede-static --describe-rule CWE-862
ansede-static --list-js-backends
ansede-static --export-rules --format json --output-dir artifacts
ansede-static src/ --js-backend structural
```

`auto` currently resolves to the structural JS/TS engine while keeping the classic
engine available for comparison or regression triage.

---

## Detection coverage

### What Bandit cannot detect (ansede-static novel categories)

| CWE     | Category                       | Example pattern                              |
|---------|--------------------------------|----------------------------------------------|
| CWE-639 | IDOR                           | Auth route query without ownership WHERE     |
| CWE-285 | Broken Access Control / Ownership | Mutation without owner guard or admin route with auth only |
| CWE-862 | Missing Authentication         | Flask/FastAPI route with no auth decorator   |
| CWE-287 | Auth Bypass via Presence-Check | `if token:` without verifying the token      |
| CWE-117 | Log Injection                  | Untrusted data in `log.*()` calls (CRLF)     |

### Python (AST-based — 27 rule categories)

| CWE    | Category                   | Notes                                        |
|--------|----------------------------|----------------------------------------------|
| CWE-89  | SQL Injection             | Taint: f-string, %-format, `.format()`       |
| CWE-78  | Command Injection         | `subprocess` + `shell=True` + dynamic arg    |
| CWE-95  | Code Injection            | `eval()`, `exec()`, `compile()`              |
| CWE-502 | Unsafe Deserialization    | `pickle`, `marshal`, `yaml.load`             |
| CWE-22  | Path Traversal            | `os.path.join` with unsanitized variable     |
| CWE-918 | SSRF                      | HTTP clients with unvalidated URLs           |
| CWE-798 | Hardcoded Secrets         | API keys, tokens, passwords, AWS creds       |
| CWE-1188 | Dangerous Defaults       | `debug=True`, `verify=False`, CORS wildcard  |
| CWE-327 | Weak Cryptography         | MD5/SHA1 for password hashing                |
| CWE-338 | Weak PRNG                 | `random` module for security tokens          |
| CWE-617 | Silent Exception Swallowing | `except Exception: pass`                   |
| CWE-345 | Broken Auth               | JWT `verify=False`                           |
| —       | Inter-procedural Taint    | Tracks taint across function calls           |
| —       | Cyclomatic Complexity     | Flags CC > 15 (high-risk code paths)         |

### JavaScript / TypeScript (23+ pattern categories)

| CWE     | Category               | Example                                        |
|---------|------------------------|------------------------------------------------|
| CWE-79  | XSS                    | `innerHTML`, `document.write`, unsafe templates |
| CWE-95  | Code Injection         | `eval()`, `new Function()`, `setTimeout(str)` |
| CWE-78  | Command Injection      | `exec()` with template literals               |
| CWE-89  | SQL Injection          | Template literal in `query()`                 |
| CWE-798 | Hardcoded Secrets      | API keys, JWT secrets, AWS creds              |
| CWE-22  | Path Traversal         | `fs.readFile` with `req.*` input              |
| CWE-1321 | Prototype Pollution   | `Object.assign`, `__proto__`, spread          |
| CWE-1333 | ReDoS                 | Catastrophic backtracking regex               |
| CWE-307 | No Rate Limiting       | Auth routes without rate-limiter middleware   |
| CWE-352 | Missing CSRF           | POST/PUT without CSRF middleware              |
| CWE-862 | Missing Authentication | Sensitive/admin route with no auth middleware |
| CWE-287 | Auth Bypass            | `if (token)` gate without verification        |
| CWE-639 | Route-level IDOR       | `findByPk(req.params.id)` without owner scope |
| CWE-285 | Broken Access Control / Ownership | `post.destroy()` after ID lookup, no owner guard; admin route with auth only |

JS/TS route findings now carry trace evidence too, so SARIF output includes code flows that show
the route, resource parameter, auth middleware (if any), the missing guard, and the lookup or mutation sink.

### Current scope and limitations

- **Python** findings are AST/dataflow heuristics over common Flask/FastAPI/Django-style patterns. They are strong on common auth, ownership, injection, and deserialization bugs, but they are not full symbolic execution.
- **JavaScript / TypeScript** findings are currently strongest on Express/Router-style server code. The route-aware checks reason about common middleware, role guards, credential presence checks, resource lookups, and mutations, but they are not yet parser-semantic whole-program analysis.
- **Trust metadata helps triage, not certainty.** Findings now include stable `rule_id`, plus `analysis_kind` and `confidence`, so you can tell both which detector fired and whether it came from a direct pattern, route heuristic, decorator heuristic, or taint flow. That still does not guarantee exploitability.
- **Synthetic benchmarks are signal, not proof.** The CVE corpus below measures recall on curated reproductions of real vulnerability patterns, not large real-world codebases.

---

## Comparison

| Capability                       | ansede-static | Bandit | Semgrep OSS |
|----------------------------------|:---:|:---:|:---:|
| Zero runtime dependencies        | ✅  | ❌  | ❌  |
| Works fully offline              | ✅  | ✅  | ✅  |
| Python support                   | ✅  | ✅  | ✅  |
| JavaScript / TypeScript support  | ✅  | ❌  | ✅  |
| SARIF output                     | ✅  | ❌  | ✅  |
| GitHub Action (marketplace)      | ✅  | ❌  | ✅  |
| VS Code extension                | ✅  | ❌  | ✅  |
| Pre-commit hook                  | ✅  | ✅  | ✅  |
| **IDOR / CWE-639**               | ✅  | ❌  | ❌* |
| **Missing auth / CWE-862**       | ✅  | ❌  | ❌* |
| **Ownership check / CWE-285**    | ✅  | ❌  | ❌* |
| Inline suppression comments      | ✅  | ✅  | ✅  |
| Baseline diffing (`--baseline`)  | ✅  | ❌  | ❌  |
| Python API                       | ✅  | ✅  | ✅  |
| Free / open source               | ✅  | ✅  | ✅  |

*Semgrep can detect these with custom rules you write yourself; not in the default ruleset.

---

## Output formats

### Text (default)

```
  ────────────────────────────────────────────────────
    ansede-static  —  3 file(s) scanned
  ────────────────────────────────────────────────────

  app.py  (python)
  [CRITICAL] L47   CWE-78:  Command injection in run_cmd() (shell=True + dynamic arg)
  [CRITICAL] L81   CWE-639: IDOR — query in get_invoice() missing ownership WHERE clause
  [HIGH    ] L23   CWE-89:  SQL Injection in get_user() via f-string
  [HIGH    ] L103  CWE-862: Route /admin/users has no authentication decorator

  Total: 4 findings — 2 critical, 2 high
```

### SARIF 2.1.0

SARIF results preserve stable analyzer-specific rule IDs (for example `PY-024`, `JS-034`), per-finding `analysisKind`, `confidence`, and trace-backed code flows so downstream tools can distinguish direct pattern matches from heuristic route findings without collapsing everything under a raw CWE.

```bash
ansede-static src/ --format sarif --output results.sarif
```

### JSON

JSON findings include stable `rule_id` values alongside `cwe`, `analysis_kind`, and `confidence`, which makes it easier to build triage dashboards, baseline filters, or CI policies around specific detectors instead of whole CWE buckets.

The top-level JSON envelope now also carries `fingerprint_version`, which documents the baseline fingerprint format used by that report.

```bash
ansede-static src/ --format json \
  | python -c "
import sys, json
for r in json.load(sys.stdin)['results']:
    for f in r['findings']:
        print(f[\"severity\"], f[\"cwe\"], f[\"title\"])
"
```

---

## Pattern recall benchmark

The `benchmarks/` directory contains 26 hand-crafted code snippets that reproduce
vulnerability _patterns_ from real CVE entries.

> **Important caveat:** These are _synthetic pattern reproductions_ written specifically
> to match what the tool detects. Recall on hand-crafted fixtures is a baseline sanity
> check — it validates that rules fire, not that they generalise to real codebases.
> Real-world precision and recall on projects like OWASP WebGoat or production open-source
> code will differ. Contributions testing against real-world CVE-affected code are welcome.

```bash
git clone https://github.com/mattybellx/Ansede
cd Ansede
pip install -e .
python -m benchmarks.nvd_benchmark
```

```
  ┌──────────────────────────────────────────────────────────────────┐
  │        ansede-static  Pattern Recall Benchmark                   │
  │   (Synthetic CVE Pattern Reproductions — not real projects)      │
  └──────────────────────────────────────────────────────────────────┘

  ✓  CVE-2022-24439  CWE-78   python  [1 critical — command injection]
  ✓  CVE-2022-36087  CWE-918  python  [1 high    — SSRF]
  ✓  CVE-2019-14234  CWE-89   python  [1 critical — SQL injection]
  ✓  CVE-2021-32556  CWE-502  python  [1 critical — pickle deserialization]
  ✓  CVE-2019-10744  CWE-1321 js      [1 high    — prototype pollution]

  Python (13 patterns):  13/13
  JS/TS  (13 patterns):  13/13

  All 26 synthetic patterns detected  ·  ~43ms
```

---

## Quality and performance harnesses

Use these during development to protect trust and catch noisy regressions early:

```bash
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.external_corpus --manifest benchmarks/real_world_manifest.example.json --cache-dir .tmp/ansede-corpus --refresh
python -m benchmarks.perf_benchmark --iterations 10
```

See [`docs/QUALITY.md`](docs/QUALITY.md) for scope, caveats, and extension guidance.

The external corpus runner also supports **pinned git-backed manifests** for larger repo-shaped fixtures.
Use `--cache-dir` to control where repositories are cached, `--refresh` to re-fetch them, and
`--offline` to re-run against an existing cache without touching the network.

The repository now ships an opt-in curated manifest at `benchmarks/real_world_manifest.json`
with pinned NodeGoat route files selected to avoid vendor noise and keep expectations stable.

---

## Target Metrics

| Metric | Target |
|---|---|
| False-positive rate | < 10 % (core Python/JS rules) |
| Recall (CVE corpus) | > 85 % for injections, path traversal, RCE |
| Speed | < 10 s per 100 k LOC on commodity hardware |
| SARIF upload size | < 2 MB for typical repos |

These are aspirational goals validated by the NVD benchmark suite in `benchmarks/`.

---

## Threat Model & Scope

**What ansede-static catches:**
- Injection sinks reached by tainted user input (SQLi, XSS, CMDi, SSRF)
- Insecure defaults (hard-coded credentials, weak crypto, debug mode left on)
- Access-control anti-patterns (missing decorators, IDOR, mass assignment)
- Supply-chain indicators (pickle, eval, unsafe deserialization)

**Non-goals (out of scope):**
- Symbolic execution / full-program formal verification
- Dynamic analysis / DAST (black-box testing)
- Business-logic flaws requiring runtime context
- Dependency-vulnerability scanning (use `pip-audit` / `npm audit` for that)

---

## Competitive Matrix

| Feature | ansede-static | Semgrep | CodeQL | Bandit |
|---|---|---|---|---|
| Zero-dependency install | ✅ | ❌ (Go runtime) | ❌ (query engine) | ✅ |
| Python + JS in one tool | ✅ | ✅ | ✅ | Python only |
| Cross-file taint (inter-proc) | ✅ (IFDS/IDE + bounded call-string) | ✅ | ✅ | ❌ |
| SARIF output | ✅ | ✅ | ✅ | ❌ |
| SBOM generation | ✅ | ❌ | ❌ | ❌ |
| Compliance tags (OWASP/NIST) | ✅ | ❌ | Partial | ❌ |
| HTML dashboard | ✅ | ❌ | ❌ | ❌ |
| Custom YAML rules | ✅ | ✅ (custom rules) | ✅ (QL) | ❌ |
| PR inline comments | ✅ (action) | ✅ | ✅ | ❌ |

---

## Operational Caveats

- **Detector blend remains layered.** Pattern, AST, and IFDS signals are combined by confidence; rare framework/metaprogramming constructs can still require manual review.
- **Minified/transpiled JS is mapped when source maps are present.** If source maps are absent or stale, findings degrade to generated-file coordinates.
- **Template transpilation is first-class for common Jinja2/Handlebars constructs.** Highly dynamic runtime template composition can still reduce precision.
- **Per-file timeouts** default to 30 s; extremely large generated files may time out and should be excluded from CI scope.

---

## Adoption Funnel

```
1. CLI (one-shot scan)       ansede-static src/
2. Pre-commit hook           ansede-static --incremental
3. CI pipeline               GitHub Action / GitLab CI / any shell
4. VS Code Extension         Real-time inline findings
5. CISO dashboard            --format ciso / --format html
```

Each step adds enforcement and visibility without requiring the previous step.

---

## Deep Mode vs. Core Mode

| Mode | Trigger | What it does |
|---|---|---|
| **Core** (default) | `ansede-static src/` | Pattern + AST taint, single-pass, < 2 s / file |
| **Deep** | `--ai-triage` | Adds offline heuristic triage: suppresses test-only findings, parameterized query patterns |
| **Incremental** | `--incremental` | Git-diff scoping — only changed files are analyzed |
| **Global** | Automatically enabled when scanning a directory | Two-pass: builds symbol graph in pass 1, evaluates taint in pass 2 |

---

## Python API

```python
from ansede_static import AnsedeConfig, scan_file, scan_code

# Scan a file
result = scan_file("app.py")
for finding in result.sorted_findings():
    print(f"[{finding.severity.value}] L{finding.line} {finding.cwe}: {finding.title}")

# Scan code in memory (useful for test suites)
result = scan_code(source_code, language="python")
assert result.critical_count == 0, f"{result.critical_count} critical findings"

# Optional: apply the same ansede.json-style filters programmatically
config = AnsedeConfig(disable_rules=["CWE-862"])
filtered = scan_code(source_code, language="python", config=config)
assert all(f.cwe != "CWE-862" for f in filtered.findings)

# Select the JS engine explicitly when scanning JavaScript / TypeScript
js_result = scan_code(js_source, language="javascript", js_backend="structural")
assert js_result.language == "javascript"

# SARIF
from ansede_static.reporters import format_sarif
sarif_str = format_sarif([result])
```

---

## CI integration

### GitHub Actions (recommended)

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: mattybellx/Ansede@v2.1.6
    with:
      path: src/
      fail-on: high
      upload-sarif: true
```

### Manual step

```yaml
- name: Security scan
  run: |
    python -m pip install "ansede-static @ git+https://github.com/mattybellx/Ansede.git"
    ansede-static src/ --format sarif --output ansede.sarif --fail-on high
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ansede.sarif
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/mattybellx/Ansede
    rev: v2.1.6
    hooks:
      - id: ansede-static
        args: [--fail-on, high]
```

---

## Development

```bash
git clone https://github.com/mattybellx/Ansede
cd Ansede
pip install -e ".[dev]"
pytest tests/ -v
python -m benchmarks.nvd_benchmark
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.perf_benchmark --iterations 10

# Self-scan: use this to catch regressions in rules, contracts, and reporters
ansede-static src/ --fail-on high
```

### Adding detection rules

- **Python:** Add a `_rule_NN(ctx: _Ctx)` function in [src/ansede_static/python_analyzer.py](src/ansede_static/python_analyzer.py) and register it in `_detect()`
- **JavaScript:** Add either a `_Rule(...)` entry or a contextual `_check_*` function in [src/ansede_static/js_analyzer.py](src/ansede_static/js_analyzer.py), then register it in `analyze_js()`
- **Benchmark test:** Add a `CVEEntry(...)` to [benchmarks/cve_corpus.py](benchmarks/cve_corpus.py)
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the full checklist

---

## Source code

The full implementation is in this repository under [`src/ansede_static/`](src/ansede_static/):

| File | Purpose |
|------|---------|
| [`python_analyzer.py`](src/ansede_static/python_analyzer.py) | 27 Python detection rules (AST/dataflow) |
| [`js_analyzer.py`](src/ansede_static/js_analyzer.py) | 23+ JavaScript/TypeScript detection rules |
| [`js_ast_analyzer.py`](src/ansede_static/js_ast_analyzer.py) | Production structural JS/TS engine with syntax-aware flow and framework route/auth modeling |
| [`js_engine/`](src/ansede_static/js_engine/) | Shared JS engine modules for structural parsing, React/JSX analysis, Koa/Nest/Next-aware route/auth heuristics, helper-call / helper-return inter-file JS flow, cached workspace module graphs, and rule orchestration |
| [`engine/triage.py`](src/ansede_static/engine/triage.py) | Offline heuristic triage and confidence adjustments |
| [`engine/explain.py`](src/ansede_static/engine/explain.py) | Human-readable finding explanations |
| [`reporters.py`](src/ansede_static/reporters.py) | Text, JSON, and SARIF output formatters |
| [`ir/global_graph.py`](src/ansede_static/ir/global_graph.py) | Inter-procedural call graph |
| [`cache/sqlite_store.py`](src/ansede_static/cache/sqlite_store.py) | Zero-dependency result cache |
| [`cli.py`](src/ansede_static/cli.py) | CLI entry point |

Benchmark corpus: [`benchmarks/cve_corpus.py`](benchmarks/cve_corpus.py)

Public scorecards and reproducible benchmark runs: [`BENCHMARKS.md`](BENCHMARKS.md)

---

## Contributing

Contributions are very welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Planning notes and milestone tickets live in [ROADMAP.md](ROADMAP.md).

The most impactful contributions are:

- **New detection rules** — if you find a vulnerability class in Python or JavaScript that the tool misses, open an issue with a minimal code snippet or a PR with a new rule + test.
- **False-positive reports** — if the tool flags safe code, open a bug report so we can tighten the heuristic.
- **Real-world corpus testing** — the benchmark suite uses synthetic patterns; PRs that test against real CVE-affected open-source projects are especially valuable.

### Quick contributor setup

```bash
git clone https://github.com/mattybellx/Ansede
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q           # current validation target: full suite green
```

Current release line: **`2.1.6`**

---

## License

MIT — see [LICENSE](LICENSE).

---

*Found a real bug with ansede-static? Open a [discussion](https://github.com/mattybellx/Ansede/discussions) or tweet about it — community signal is the best way to help other developers find this tool.*

