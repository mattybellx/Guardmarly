# <img src="guard.png" width="36" style="vertical-align:middle"> Guardmarly — Find authorization bugs before attackers do

<p align="center">
  <strong>The only free SAST with built-in IDOR detection. 100% CVE recall. Fully offline.</strong>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mattybellx/Guardmarly/main/showcase.png" width="800" alt="Guardmarly in action — CWE-22 path traversal detection in VS Code">
</p>

<p align="center">
  <a href="https://guardmarly.onrender.com"><img src="https://img.shields.io/badge/Try%20Online%20Scanner-guardmarly.onrender.com-22c55e?style=for-the-badge" alt="Try Online Scanner"></a>
  <a href="https://pypi.org/project/guardmarly/"><img src="https://img.shields.io/pypi/v/guardmarly?color=22c55e" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Guardmarly/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Guardmarly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mattybellx/Guardmarly/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
</p>

```bash
pip install guardmarly && guardmarly src/
```

---

## The problem

Authorization bugs — **IDOR, missing access controls, privilege escalation** — caused some of the largest data breaches in history. Most SAST tools can't find these bugs because they require tracing data from HTTP routes through auth guards into database queries.

## What Guardmarly does differently

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)
    # ↑ CWE-639 IDOR: any user can view any invoice
    #   Bandit: silent. Semgrep OSS: silent. CodeQL: silent.
    #   Guardmarly: 🚨 CRITICAL — route flows to DB without auth check
```

Guardmarly maps every HTTP route, checks for auth guards, traces data flow to sinks, and flags the gap.

## Quick start

```bash
pip install guardmarly
guardmarly src/                          # text output
guardmarly src/ --format json -o r.json  # JSON report
guardmarly src/ --format sarif           # SARIF for GitHub
guardmarly --show-stats                  # lifetime + today counts
guardmarly --list-rules                  # full rule catalog
```

## Supported languages & CWEs

**5 languages:** Python, JavaScript/TypeScript, Go, Java, C#  
**35+ CWE types:** IDOR (CWE-639), Missing Auth (CWE-862/306), SQLi (CWE-89), Command Injection (CWE-78), XSS (CWE-79), Path Traversal (CWE-22), SSRF (CWE-918), Deserialization (CWE-502), Hardcoded Secrets (CWE-798), Open Redirect (CWE-601), CSRF (CWE-352), XXE (CWE-611), and 25+ more.

## Contributing

```bash
git clone https://github.com/mattybellx/Guardmarly.git
cd Guardmarly && pip install -e ".[dev]"
pytest tests/ -q                       # 1,183+ tests in ~12s
```

## License

MIT © Matty Bell
