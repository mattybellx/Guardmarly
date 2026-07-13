# 🔍 Ansede Static · v6.3.0

<p align="center">
  <strong>World's first open-source SAST with CWE-639 IDOR detection.</strong><br>
  100% CVE recall · 91.4% vuln detection · 0.04 findings/kLOC on production code<br>
  <sub>Finds the authorization flaws Semgrep, CodeQL, and Bandit miss.</sub>
</p>

<p align="center">
  <a href="https://ansede.onrender.com/scan"><img src="https://img.shields.io/badge/🚀%20Try%20Online%20Scanner-ansede.onrender.com-6366F1?style=for-the-badge" alt="Try Online Scanner"></a>
</p>

```bash
pip install ansede-static && ansede-static src/
```

<p align="center">
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/CVE%20Recall-100%25-success" alt="CVE 100%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Vuln%20Detection-91.4%25-success" alt="91.4%"></a>
  <a href="docs/BENCHMARKS.md"><img src="https://img.shields.io/badge/Noise-0.04%2FkLOC-success" alt="0.04/kLOC"></a>
  <a href=""><img src="https://img.shields.io/badge/CWE--639%20IDOR-World%20First-blue" alt="IDOR"></a>
  <a href=""><img src="https://img.shields.io/badge/Languages-5-blue" alt="5 langs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
  <a href=""><img src="https://img.shields.io/badge/tests-1215%20passed-success" alt="1215 tests"></a>
  <a href="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Ansede/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pypi.org/project/ansede-static/"><img src="https://img.shields.io/pypi/dm/ansede-static?label=installs&color=blue" alt="PyPI"></a>
</p>

---

## 🚀 Try It Right Now — No Install

<p align="center">
  <a href="https://ansede.onrender.com/scan"><strong>→ ansede.onrender.com/scan ←</strong></a><br>
  <sub>Paste code, click Scan, see results in seconds. No signup. No install. Fully free.</sub>
</p>

---

## Why Ansede?

| Capability | Ansede | Semgrep | CodeQL |
|-----------|--------|---------|--------|
| **CVE Recall** | **100%** (164/164) | ~23% | ~34% |
| **CWE-639 IDOR** | ✅ World-first | ❌ No rules | ❌ No rules |
| **Production noise** | **0.04/kLOC** | Config-dependent | Config-dependent |
| **Languages** | 5 deep | 30+ shallow | 7 deep |
| **Offline** | ✅ No network | ❌ Needs registry | ❌ Needs build |

Most free SAST tools focus on injection bugs. Ansede also catches **authorization flaws** that cause real data breaches:

| | Bandit | Semgrep | CodeQL | **Ansede** |
|---|---|---|---|---|
| SQL Injection, XSS | ✓ | ✓ | ✓ | ✓ |
| **IDOR (CWE-639)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Missing Auth (CWE-862)** | ✗ | ✗ | ✗ | **✓ Built-in** |
| **Ownership Bypass** | ✗ | ✗ | ✗ | **✓ Built-in** |
| Fully offline | ✓ | ✗ | ✗ | **✓** |

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ CWE-639 IDOR: any user can view any invoice
    #   Bandit: silent. Semgrep: silent. Ansede: 🚨 CRITICAL
```

---

## Quick Start

```bash
pip install ansede-static
ansede-static src/                    # Scan a directory
ansede-static src/ --format sarif     # GitHub Code Scanning
ansede-static src/ --fail-on high     # CI gate
ansede-static src/ --format html      # Interactive HTML report
ansede-static src/ --diff-only        # PR scan (< 5s)
```

No network. No API keys. No compilation. Just Python 3.9+.

---

## Benchmarks

### CVE Recall — 164 Known Vulnerabilities

| Language | CVEs | Found | Recall |
|---|---|---|---|
| Python | 68 | 68 | 100% |
| JavaScript | 42 | 42 | 100% |
| Java | 20 | 20 | 100% |
| C# | 19 | 19 | 100% |
| Go | 15 | 15 | 100% |
| **Total** | **164** | **164** | **100%** |

Semgrep finds 23%. CodeQL finds ~34%.

### Production Noise — 16 Repos, 366K LOC

**0.04 findings per 1,000 lines.** The scanner correctly treats well-written production code as clean. Tested on go-redis, gin, echo, zap, cobra, viper, gorilla-websocket, zod, supabase, grafana, and more.

### OWASP Benchmark v1.2

| Tool | Recall | Score |
|---|---|---|
| **Ansede 6.0.0** | **93.3%** 🥇 | +0.8% 🥈 |
| FBwFindSecBugs | ~45% | +35.8% 🥇 |
| CodeQL | ~30% | ~-20% |
| Semgrep OSS | ~20% | ~-30% |

[Full benchmarks →](docs/BENCHMARKS.md)

---

## Features

- **35+ CWE types** — SQLi, XSS, IDOR, auth bypass, SSRF, path traversal, command injection, hardcoded secrets, deserialization
- **5 languages** — Python, JavaScript/TypeScript, Go, Java, C#
- **Route-aware** — maps HTTP routes → auth guards → data sinks
- **Framework profiles** — Django, Flask, Express, Spring, ASP.NET, Gin
- **Incident clustering** — groups related findings, ~49% noise reduction
- **Confidence scoring** — 0–100% per finding; low-signal filtered by default
- **Guard detection** — `@login_required`, `@PreAuthorize`, `[Authorize]`, Go middleware
- **Test-context awareness** — auto-suppresses findings in test/benchmark files (96% FP reduction)
- **Output formats** — SARIF (GitHub Code Scanning), CycloneDX SBOM, HTML, JSON
- **CI/CD ready** — `--diff-only`, `--fail-on`, `--baseline`
- **IDE plugins** — VS Code, IntelliJ IDEA, Visual Studio 2022

---

## GitHub Actions

```yaml
- uses: mattybellx/Ansede@v6.3.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

---

## Contributing

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede && pip install -e ".[dev]"
pytest tests/ -q
```

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT · [Matty Bell](https://github.com/mattybellx)

<p align="center">
  <sub>Zero telemetry · Zero cloud · 100% offline · <a href="https://github.com/mattybellx/Ansede">⭐ Star on GitHub</a></sub>
</p>
