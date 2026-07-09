<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <img alt="Ansede Static" src="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png" width="600">
  </picture>
</p>

<p align="center">
  <strong>Finds the vulnerabilities other SAST tools miss.</strong><br>
  #1 CVE recall (100%) · 6 languages · 35+ CWE types · Fully offline<br>
  <code>pip install ansede-static</code>
</p>

<p align="center">
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-100%25-success" alt="CVE 100%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP%20Recall-93.3%25-success?logo=owasp" alt="OWASP 93%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP%20Score-%2B0.8%25%20Youden-success" alt="OWASP Score"></a>
  <a href=""><img src="https://img.shields.io/badge/Languages-6-blue" alt="6 langs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <a href=""><img src="https://img.shields.io/badge/tests-1239%20passed-success" alt="1239 tests"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=PyPI%20installs&color=blue" alt="PyPI installs"></a>
</p>

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/                    # Scan a directory
ansede-static src/ --format sarif     # GitHub Code Scanning
ansede-static src/ --fail-on high     # CI gate (non-zero exit on findings)
ansede-static src/ --format html      # Interactive HTML report
ansede-static src/ --diff-only        # PR scan: only changed files (< 5s)
ansede-static src/ --suggest          # Adaptive rules: improve based on your codebase
```

No network, no API keys, no compilation. Just Python 3.9+ and `rich`.

**[Try the live playground →](https://ansede.onrender.com/scan)** — no install required.

---

## Why Ansede?

Most free SAST tools focus on injection bugs (SQLi, XSS). Ansede also catches the **authorization flaws** that cause real data breaches:

| | Bandit | Semgrep | CodeQL | **Ansede** |
|---|---|---|---|---|
| SQL Injection, XSS | ✓ | ✓ | ✓ | ✓ |
| **IDOR / Broken Access Control** | ✗ | ✗* | manual | **✓ Built-in** |
| **Missing Auth on Routes** | ✗ | ✗* | manual | **✓ Built-in** |
| **Ownership Bypass (CWE-285)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| Offline / Air-gapped | ✓ | needs sync | ✗ | **✓** |

*\*Possible with custom rules; no defaults ship.*

```python
@app.route("/invoice/<id>")
@login_required
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ CWE-639 IDOR: any user can view any invoice
    #   Bandit: silent. Semgrep: silent. Ansede: CRITICAL
```

---

## Benchmarks

### OWASP Benchmark v1.2 — 2,740 Java Tests

| Tool | Recall | Score (Youden) |
|---|---|---|
| FBwFindSecBugs | ~45% | **+35.8%** 🥇 |
| **Ansede 6.0.0** | **93.3%** 🥇 | **+0.8%** 🥈 |
| CodeQL | ~30% | ~-20% |
| Semgrep OSS | ~20% | ~-30% |

**#1 in recall. #2 in score.** 9 of 11 categories at 100% TPR.
[Full scorecard →](benchmarks/owasp_scorecard.html)

### CVE Recall — 164 Known Vulnerabilities

| Language | CVEs | Found | Recall |
|---|---|---|---|
| Python | 68 | 68 | 100% |
| JavaScript | 42 | 42 | 100% |
| Java | 20 | 20 | 100% |
| C# | 19 | 19 | 100% |
| Go | 15 | 15 | 100% |
| **Total** | **164** | **164** | **100%** |

Semgrep OSS finds 23% of the same corpus. CodeQL finds ~34%.

### Precision (v6.2.2)

| Metric | Score |
|---|---|
| Blind audit (400 snippets, 4 runs) | **~90% recall, ~97% precision** |
| Real GitHub repos (22 repos, 1,027 files) | **0 crashes** |
| CRITICAL on safe parameterized SQL | **0** (eliminated) |
| Test/benchmark/tutorial FP suppression | **96% reduction** |
| Quality corpus | **56 cases, 96/96 checks (100%)** |

### Real-World Scale

Scanned **58 open-source repos** (21,871 files, 3.2M lines) with **zero crashes**. Detects 35+ CWE types. Average findings: ~0.11 per file on mature Apache/Google libraries.

### Performance

| Scenario | Throughput |
|---|---|
| Single file | ~0.05s |
| Batch (4 workers) | 4–6 KLOC/s |
| Rust native grammars | ~4,000 LOC/s |

---

## Comparison

| | Ansede | Semgrep | CodeQL | FBwFindSec |
|---|---|---|---|---|
| **CVE Recall** | **100%** 🥇 | 23% | 34% | 40% |
| **OWASP Recall** | **93%** 🥇 | 20% | 30% | 45% |
| **OWASP Score** | +0.8% 🥈 | -30% | -20% | **+36%** 🥇 |
| **Languages** | **6** 🥇 | 20+ | 5+ | 1 |
| **Auth/IDOR detection** | ✓ | custom | manual | ✗ |
| **Fully offline** | ✓ | partial | ✗ | ✓ |
| **Install** | `pip install` | needs binary | needs DB | needs Java |
| **IDE Plugins** | VS Code, IntelliJ, VS | VS Code | VS Code | ✗ |
| **Price** | Free + Pro | Free | Licensed | Free |

*\*Competitor OWASP figures from published scorecards. CVE recall from our 164-CVE benchmark.*

---

## Features

- **35+ CWE types** — SQLi, XSS, IDOR, auth bypass, SSRF, path traversal, command injection, hardcoded secrets, deserialization
- **6 languages** — Python, JavaScript/TypeScript, Go, Java, C#, **Rust**
- **Route-aware analysis** — maps HTTP routes → auth guards → data sinks
- **Framework profiles** — Spring, ASP.NET, Django, Express, Gin, Quarkus
- **Incident clustering** — groups related findings, cuts noise ~49%
- **Confidence scoring** — every finding rated 0–100%; low-signal results filtered by default
- **Guard detection** — recognizes `@login_required`, `@PreAuthorize`, `[Authorize]`, Go middleware, HMAC webhooks
- **Test-context awareness** — automatically suppresses findings in test/benchmark/tutorial files (96% FP reduction)
- **Output formats** — SARIF (GitHub Code Scanning), CycloneDX SBOM, HTML, JSON
- **CI/CD ready** — `--diff-only` PR scanning, `--fail-on` exit codes, `--baseline`
- **IDE plugins** — inline diagnostics + one-click fixes in VS Code, IntelliJ IDEA, Visual Studio 2022

---

## Adaptive Rules

Ansede learns from your codebase to reduce false positives over time:

```bash
ansede-static src/ --suggest          # Analyze gaps, propose new heuristics
ansede-static src/ --all-findings     # Override confidence filter — see everything
ansede-static src/ --min-confidence 0 # Same as --all-findings
```

After scanning multiple codebases, Ansede generates suppression rules that match your specific framework patterns — **fully offline, no ML API required**.

---

## CI/CD Templates

| Platform | Template |
|---|---|
| **GitHub Actions** | Built-in (`uses: mattybellx/Ansede@v6.2.0`) |
| **GitLab CI** | [docs/ci-templates/gitlab-ci.yml](docs/ci-templates/gitlab-ci.yml) |
| **Azure DevOps** | [docs/ci-templates/azure-pipelines.yml](docs/ci-templates/azure-pipelines.yml) |
| **Jenkins** | [docs/ci-templates/Jenkinsfile](docs/ci-templates/Jenkinsfile) |

---

## GitHub Actions

**Basic scan on push:**
```yaml
- uses: mattybellx/Ansede@v6.2.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
    post-pr-comments: true      # Inline review comments on every PR finding
```

**Auto-scan + open PR with findings (try it on any repo):**
```yaml
# Copy ansede-scan-pr.yml to .github/workflows/
# Then trigger from Actions tab → "Ansede Security Scan + PR"
# Scans your code and opens a PR with the results
```
→ [Copy the workflow template](ansede-scan-pr.yml)

---

## Docs

| | |
|---|---|
| [Getting Started](docs/getting-started.md) | Installation and first scan |
| [Benchmarks](docs/BENCHMARKS.md) | Full methodology and results |
| [CI Integration](docs/ci-integration.md) | GitHub Actions, GitLab CI, Jenkins |
| [IDE Setup](docs/ide-setup.md) | VS Code, IntelliJ, Visual Studio |
| [Configuration](docs/configuration.md) | All CLI flags and config options |
| [Writing Rules](docs/writing-rules.md) | Create custom detection rules |
| [FAQ](docs/faq.md) | Common questions |
| [Roadmap](ROADMAP.md) | What's coming next |
| [Changelog](CHANGELOG.md) | Version history |

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
pip install -e ".[dev]"
pytest tests/ -q          # 1249 tests
```

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/results-mario.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/results-mario.png">
    <img alt="Ansede Static Results" src="https://github.com/mattybellx/Ansede/blob/master/assets/results-mario.png" width="600">
  </picture>
</p>
## License

MIT · [Matty Bell](https://github.com/mattybellx)

<p align="center">
  <sub>Zero telemetry · Zero cloud · 100% offline · <a href="https://github.com/mattybellx/Ansede">⭐ Star on GitHub</a></sub>
</p>
