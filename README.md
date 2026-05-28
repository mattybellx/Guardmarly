<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <img alt="Ansede Static — Offline SAST Engine" src="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png" width="600">
  </picture>
</p>

<p align="center">
  <strong>The offline SAST engine that finds what others miss.</strong><br>
  <strong>Rust-accelerated fast path</strong> · <strong>0.02s per 100k LOC</strong> · <strong>Zero external dependencies</strong><br>
  <code>pip install ansede-static</code> &nbsp;·&nbsp; No telemetry &nbsp;·&nbsp; Fully offline
</p>

<p align="center">
  <a href="https://pypi.org/project/ansede-static"><img src="https://img.shields.io/pypi/v/ansede-static?label=PyPI&color=0078D4" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/mattybellx/Ansede/ci.yml?branch=master&label=CI&logo=github" alt="CI"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-98.8%25-success?logo=owasp" alt="CVE Recall 98.8%"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Precision-96.4%25-success" alt="96.4% precision"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Languages-7-blue" alt="7 languages"></a>
  <a href="https://github.com/mattybellx/Ansede/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
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
ansede-static --batch "src/ tests/"        # Batch API — multi-path scan
ansede-static src/ --fail-on high          # CI gate
ansede-static src/ --incremental           # git-diff mode
```

**Zero-dependency binary also available** — download the standalone executable from [Releases](https://github.com/mattybellx/Ansede/releases).

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
| Zero Dependencies | ✓ | ✗ | ✗ | **✓ Pure stdlib** |

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

### NVD CVE Recall (Synthetic Corpus)

| Language | Cases | Detected | Recall |
|---|---|---|---|
| Python | 55 | 55 | 100% |
| JavaScript | 31 | 31 | 100% |
| Go | 7 | 7 | 100% |
| Java | 12 | 12 | 100% |
| C# | 10 | 10 | 100% |
| **Total** | **115** | **115** | **100%** |

### Real-World Open-Source Validation (35 repos, 71 MB)

| Metric | Value |
|---|---|
| Repos scanned | **35/35 (0 failures)** |
| Files scanned | **12,372** |
| Lines scanned | **1,759,954** |
| CWE types detected | **35+** |
| Cluster-adjusted NQ | **1.28 findings/kLOC** |
| CVE precision | **96.4%** |

### Web-Wild & Honest Metrics

| Metric | Result |
|---|---|
| **Synthetic CVE recall** | **100%** (pattern coverage) |
| **Web-wild field recall** | **~70%** (minified/obfuscated code) |
| **Web-wild precision** | **85.7%** |
| **Phase 4 bridge** | Source-map resolution in active development |

> **Transparency commitment:** 100% synthetic CVE recall measures pattern coverage — not field performance. Web-wild recall on minified/obfuscated code is ~70%. The [Phase 4 roadmap](docs/ROADMAP.md) (source-map resolution, symbolic guards) bridges this gap. No cherry-picked metrics. Full methodology in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

### Performance

| Scenario | Throughput |
|---|---|
| **Rust fast-path** (trivially clean files) | **~0.02s per 100k LOC** |
| Small repos (≤2 MB, 4 workers) | **4.05 KLOC/s** |
| Medium repos (2–10 MB, 4 workers) | **2.03 KLOC/s** |
| Single-file scan | **~0.01–0.05s** |

---

## **<ins>Comparison</ins>**

| Feature | Ansede Static | Semgrep OSS | CodeQL |
|---|---|---|---|
| **NVD CVE Recall** | **98.8%** | ~70%* | ~85%* |
| **IDOR / Auth Bypass** | ✓ Native AST | ✗ No default rules | ~ Manual QL |
| **Incident Clustering** | ✓ 49% noise reduction | ✗ | ✗ |
| **Offline-First** | ✓ Fully | ~ Needs rule sync | ✗ SaaS-only |
| **Zero Dep Install** | ✓ `pip install` | ✗ Requires semgrep | ✗ DB build req. |
| **SBOM Output** | ✓ CycloneDX/SPDX | ✗ | ✗ |
| **SARIF** | ✓ Free tier | ✓ | ✓ |
| **LLM Triage** | ✓ (local Ollama) | ✗ | ✗ |
| **IDE Plugins** | VS Code, IntelliJ, VS | VS Code only | VS Code only |
| **Price** | Free + Pro | Free + Managed | SaaS-licensed |

*\*Estimated based on default rule coverage. Exact figures vary by deployment.*

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
- uses: mattybellx/Ansede@v2.3.2
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

---

## **<ins>Documentation</ins>**

| Resource | Link |
|---|---|
| Full Benchmarks | [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) |
| Roadmap | [`docs/ROADMAP.md`](docs/ROADMAP.md) |
| Architecture | [`docs/interprocedural-taint-analysis.md`](docs/interprocedural-taint-analysis.md) |
| IDE Plugin Architecture | [`docs/ide-plugin-architecture.md`](docs/ide-plugin-architecture.md) |
| Community Rule Guide | [`docs/community-rule-conversion-guide.md`](docs/community-rule-conversion-guide.md) |
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
