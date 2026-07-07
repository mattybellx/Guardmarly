<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png">
    <img alt="Ansede Static" src="https://github.com/mattybellx/Ansede/blob/master/assets/AS.png" width="600">
  </picture>
</p>

<p align="center">
  <strong>Finds the vulnerabilities other SAST tools miss.</strong><br>
  #1 CVE recall (100%) · #2 OWASP score · 5 languages · Fully offline<br>
  <code>pip install ansede-static</code>
</p>

<p align="center">
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-100%25-success" alt="CVE 100%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP%20Recall-93.3%25-success?logo=owasp" alt="OWASP 93%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/OWASP%20Score-%2B0.8%25%20Youden-success" alt="OWASP Score"></a>
  <a href=""><img src="https://img.shields.io/badge/Languages-5-blue" alt="5 langs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <a href=""><img src="https://img.shields.io/badge/tests-952%20passed-success" alt="952 tests"></a>
</p>

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/                    # Scan a directory
ansede-static src/ --format sarif     # GitHub Code Scanning
ansede-static src/ --fail-on high     # CI gate (non-zero exit on findings)
ansede-static src/ --format html      # Interactive HTML report
```

No network, no API keys, no compilation. Just Python 3.9+ and `rich`.

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
| **Ansede 5.6.0** | **93.3%** 🥇 | **+0.8%** 🥈 |
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
| **Languages** | 5 | 20+ | 5+ | 1 |
| **Auth/IDOR detection** | ✓ | custom | manual | ✗ |
| **Fully offline** | ✓ | partial | ✗ | ✓ |
| **Install** | `pip install` | needs binary | needs DB | needs Java |
| **IDE Plugins** | VS Code, IntelliJ, VS | VS Code | VS Code | ✗ |
| **Price** | Free + Pro | Free | Licensed | Free |

*\*Competitor OWASP figures from published scorecards. CVE recall from our 164-CVE benchmark.*

---

## Features

- **35+ CWE types** — SQLi, XSS, IDOR, auth bypass, SSRF, path traversal, command injection, hardcoded secrets, deserialization
- **5 languages** — Python, JavaScript/TypeScript, Go, Java, C#
- **Route-aware analysis** — maps HTTP routes → auth guards → data sinks
- **Framework profiles** — Spring, ASP.NET, Django, Express, Gin, Quarkus
- **Incident clustering** — groups related findings, cuts noise ~49%
- **Guard detection** — recognizes `@login_required`, `if user.is_authenticated`
- **Output formats** — SARIF (GitHub Code Scanning), CycloneDX SBOM, HTML, JSON
- **CI/CD ready** — `--incremental` git-diff, `--fail-on` exit codes, `--baseline`
- **IDE plugins** — inline diagnostics in VS Code, IntelliJ IDEA, Visual Studio 2022

---

## GitHub Action

```yaml
- uses: mattybellx/Ansede@v5.6.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

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
pytest tests/ -q          # 952 tests
```

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT · [Matty Bell](https://github.com/mattybellx)

<p align="center">
  <sub>Zero telemetry · Zero cloud · 100% offline · <a href="https://github.com/mattybellx/Ansede">⭐ Star on GitHub</a></sub>
</p>
