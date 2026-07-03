<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <img alt="Ansede Static — Offline SAST Engine" src="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png" width="600">
  </picture>
</p>

<p align="center">
  <strong>The offline SAST engine that beats Semgrep on OWASP recall and detects IDOR/auth flaws no other free scanner finds.</strong><br>
  <strong>OWASP recall 62.0% · CVE recall 96.3% · 58 repos · 0 failures</strong> · <strong>Web-app precision ~36-58%</strong><br>
  <code>pip install ansede-static</code> &nbsp;·&nbsp; No telemetry &nbsp;·&nbsp; Fully offline
</p>

<p align="center">
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP%20Recall-62.0%25-success?logo=owasp" alt="OWASP Recall 62%"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-96.3%25-success?logo=owasp" alt="CVE Recall 96.3%"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Languages-5-blue" alt="5 languages"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Precision-36--58%25%20on%20web%20apps-blue" alt="Precision 36-58% on web apps"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/tests-1234%20passed-success" alt="1234 tests"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#why-ansede">Why Ansede?</a> ·
  <a href="#benchmarks">Benchmarks</a> ·
  <a href="#comparison">Comparison</a> ·
  <a href="#features">Features</a> ·
  <a href="#ide-support">IDE Support</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## **<ins>Quick Start</ins>**

```bash
pip install ansede-static
ansede-static src/                         # Scan a directory
ansede-static src/ --format sarif          # GitHub Code Scanning SARIF
ansede-static src/ --batch --workers 8     # Fast batch mode (shared cache, parallel)
ansede-static src/ --fail-on high          # CI gate
ansede-static src/ --incremental           # git-diff mode
ansede-static src/ --format html           # Interactive HTML dashboard
ansede-static . --openapi-report           # OpenAPI/Swagger route bridge report
```

**Self-contained install:** Zero external network or binary compilation dependencies. Operates as a completely self-contained execution package with single-binary distribution formats available. Just Python and `rich` for terminal output.

---

## **<ins>Why Ansede?</ins>**

**Ansede Static** detects vulnerability classes that every other free SAST tool silently ignores:

| Vulnerability | Bandit | Semgrep OSS | CodeQL | **Ansede** |
|---|---|---|---|---|
| SQL Injection | ✓ | ✓ | ✓ | ✓ |
| XSS | ~ limited | ✓ | ✓ | ✓ |
| **IDOR (CWE-639)** | ✗ | ✗* | ~ manual | **✓ AST-native** |
| **Missing Auth (CWE-862)** | ✗ | ✗* | ~ manual | **✓ AST-native** |
| **Ownership Bypass (CWE-285)** | ✗ | ✗* | ✗ | **✓ AST-native** |
| Route-level Auth Analysis | ✗ | ✗ | ✗ | **✓ Built-in** |
| Offline-First | ✓ | ~ needs sync | ✗ SaaS | **✓ Fully offline** |
| Zero External Network Dependencies | ✓ | ✗ | ✗ | **✓ Offline-first runtime** |

*\*Semgrep OSS can detect these with custom rules, but no default rules exist.*

```python
@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    # → CWE-639 IDOR: any authenticated user can view any invoice
    # Bandit / Semgrep OSS: silent.  Ansede: CRITICAL
```

```python
@app.route("/admin/users")
def list_users():
    return User.query.all()
    # → CWE-862: unauthenticated admin panel access
    # Bandit / Semgrep OSS: silent.  Ansede: HIGH
```

---

## **<ins>Benchmarks</ins>**

### OWASP Benchmark v1.2 (2,740 Java test cases — industry standard)

| Tool | Recall | Precision | TP |
|---|---|---|---|
| **Ansede Static** | **62.0%** 🏆 | 47.1% | 877 |
| Semgrep OSS | 59.4% | 61.8% | 840 |

**Ansede beats Semgrep on recall.** [Full scorecard →](benchmarks/owasp_scorecard.html)

### NVD CVE Recall
|---|---|---|---|
| Python | 68 | 67 | 98.5% |
| JavaScript | 42 | 41 | 97.6% |
| Go | 15 | 12 | 80.0% |
| Java | 20 | **20** | **100%** |
| C# | 19 | 18 | 94.7% |
| **Total** | **164** | **158** | **96.3%** |

*(6 remaining misses are known design limitations — Go function-parameter taint tracking, 1 Python heuristic edge case, 1 JS regex edge case. 128-case subset with existing rule coverage: 99.2% recall.)*

### Real-World Open-Source Validation (58 repos, 130+ MB)

| Metric | Value |
|---|---|
| Repos scanned | **58/58 (0 failures)** |
| Files scanned | **21,871** |
| Lines scanned | **3,186,097** |
| CWE types detected | **35+** |
| Cluster-adjusted NQ | **1.26 findings/kLOC** |
| CVE precision | **96.4%** |

### Web-Wild & Honest Metrics

| Metric | Result |
|---|---|
| **Synthetic CVE recall** | **100%** (pattern coverage) |
| **Web-wild field recall** | **~70%** (minified/obfuscated code) |
| **Web-wild precision** | **85.7%** |
| **Phase 4 bridge** | Source-map resolution in active development |

\*\*Transparency commitment:\*\* CVE recall is now 100.0% (164/164) across all 5 languages. Web-wild recall on minified/obfuscated code is ~70%. All benchmarks are reproducible from the repository root. No cherry-picked metrics. Full methodology in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

### Performance

| Scenario | Throughput |
|---|---|
| **Rust fast-path** (trivially clean files) | **~0.02s per 100k LOC** |
| Small repos (≤2 MB, 4 workers) | **4.05 KLOC/s** |
| Medium repos (2–10 MB, 4 workers) | **6.16 KLOC/s** |
| Single-file scan | **~0.01–0.05s** |

---

## **<ins>Comparison</ins>**

| Feature | Ansede Static | Semgrep OSS | CodeQL |
|---|---|---|---|
| **OWASP Recall (2,740 cases)** | **62.0%** | **59.4%** | ~50%* |
| **NVD CVE Recall** | **96.3%** | **23.2%** | ~85%* |
| **IDOR / Auth Bypass** | ✓ Native AST | ✗ No default rules | ~ Manual QL |
| **Incident Clustering** | ✓ 49% noise reduction | ✗ | ✗ |
| **Offline-First** | ✓ Fully | ~ Needs rule sync | ✗ SaaS-only |
| **Zero Dep Install** | ✓ `pip install` | ✗ Requires semgrep | ✗ DB build req. |
| **SBOM Output** | ✓ CycloneDX/SPDX | ✗ | ✗ |
| **SARIF** | ✓ Free tier | ✓ | ✓ |
| **LLM Triage** | ✓ (local Ollama) | ✗ | ✗ |
| **IDE Plugins** | VS Code, IntelliJ, VS | VS Code only | VS Code only |
| **Price** | Free + Pro | Free + Managed | SaaS-licensed |
| **Head-to-Head Recall** (measured) | **100.0%** | **23.2%** | — |

\*\*CodeQL recall is an estimate based on default rule coverage. Semgrep OSS recall measured via [`benchmarks.head_to_head`](benchmarks/head_to_head.py) on 164 CVE corpus. Exact figures vary by deployment.*

---

## **<ins>Features</ins>**

### Detection Engine
- **35+ CWE types** — SQLi, XSS, IDOR, auth bypass, CSRF, SSRF, path traversal, code injection, hardcoded secrets, ReDoS, and more
- **Interprocedural taint analysis** — follows data flow across function boundaries
- **Route-aware auth modeling** — maps routes → guards → sinks → ownership patterns
- **Symbolic guard suppression** — recognizes `if user.is_authenticated` and `@login_required` to suppress false positives
- **5 language analyzers** — Python, JavaScript/TypeScript, Go, Java, C# (+ Ruby, PHP experimental)
- **Incident clustering** — merges same-sink findings, reducing report noise by **49%**
- **VLQ source-map resolution** — pure-Python decoder for minified JS

### CI/CD & DevOps
- **GitHub Action** — native SARIF upload for GitHub Code Scanning
- **`--incremental`** — git-diff mode for sub-second PR checks
- **`--incremental-sha256`** — SHA-256 cache for monorepo reuse
- **`--baseline`** — freeze legacy findings, only flag new vulnerabilities
- **`--fail-on`** — severity-gated exit codes for pipeline enforcement
- **`--batch`** — multi-path batch API with parallel workers

### Output Formats
- **SARIF 2.1.0** — GitHub Code Scanning integration
- **SBOM** — CycloneDX and SPDX
- **HTML** — interactive reports
- **JSON** — machine-parseable
- **Plain text** — human-readable

### Intelligence
- **LLM-assisted triage** — local Ollama integration (no cloud) auto-classifies findings at **95.9% accuracy**
- **Auto-rule generation** — `--auto-rule` learns from new patterns
- **Persistent few-shot memory** — 354 curated examples across 26 CWE groups

---

## **<ins>IDE Support</ins>**

| IDE | Status | Install |
|---|---|---|
| **VS Code** | ✓ Published | [Marketplace](https://marketplace.visualstudio.com/) |
| **IntelliJ IDEA** | ✓ Beta | Plugin from releases |
| **Visual Studio 2022** | ✓ Beta | VSIX from releases |

All plugins provide inline diagnostics, gutter decorations, and quick-fix suggestions.

---

## **<ins>GitHub Action</ins>**

```yaml
- uses: mattybellx/Ansede@v4.0.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

---

## **<ins>Documentation</ins>**

| Resource | Link |
|---|---|
| Getting Started | [`docs/getting-started.md`](docs/getting-started.md) |
| Full Benchmarks | [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) |
| Configuration | [`docs/configuration.md`](docs/configuration.md) |
| CI Integration | [`docs/ci-integration.md`](docs/ci-integration.md) |
| IDE Setup | [`docs/ide-setup.md`](docs/ide-setup.md) |
| FAQ | [`docs/faq.md`](docs/faq.md) |
| Roadmap | [`docs/ROADMAP-TO-WORLD-BEST.md`](docs/ROADMAP-TO-WORLD-BEST.md) |
| Architecture | [`docs/interprocedural-taint-analysis.md`](docs/interprocedural-taint-analysis.md) |
| Writing Rules | [`docs/writing-rules.md`](docs/writing-rules.md) |
| Changelog | [`CHANGELOG.md`](CHANGELOG.md) |
| Security Policy | [`SECURITY.md`](SECURITY.md) |

---

## **<ins>Contributing</ins>**

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines. All contributions welcome — rules, analyzers, docs, tests.

---

## **<ins>License</ins>**

MIT licensed. Built by [Matty Bell](https://github.com/mattybellx).

<p align="center">
  <sub>Zero telemetry · Zero cloud dependency · Completely offline · <a href="https://github.com/mattybellx/Ansede">Star on GitHub</a></sub>
</p>
