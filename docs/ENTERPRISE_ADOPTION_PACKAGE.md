# Ansede Enterprise Adoption Package

> For security teams evaluating Ansede for organizational deployment.  
> Last updated: 2026-07-17 | Target audience: Security Engineers, CISOs, Engineering Managers

---

## 1. Security Policy

See [SECURITY.md](../SECURITY.md) for:
- Supported versions
- Vulnerability reporting process (GitHub Security Advisories)
- Responsible disclosure policy
- Scope and out-of-scope definitions

### Key Commitments
- **48-hour** acknowledgment for vulnerability reports
- **7-day** fix target for critical issues
- **Coordinated disclosure** — no public exploit details before fix

---

## 2. Architecture Overview

### What Ansede Does

Ansede is a **static analysis** tool — it reads source code, never executes it. No code leaves the machine.

### Analysis Pipeline

```
Source Code
    ↓
Language Detection (Python/JS/Go/Java/C#)
    ↓
AST Parsing (tree-sitter or built-in parser)
    ↓
Route Extraction (HTTP route → handler mapping)
    ↓
Guard Detection (auth decorators, middleware, annotations)
    ↓
IFDS Taint Tracking (cross-function data flow)
    ↓
Sink Analysis (database, filesystem, command, network)
    ↓
Finding Generation (CWE-mapped, severity-scored)
    ↓
Incident Clustering (related finding grouping)
    ↓
Output (Text / JSON / SARIF / HTML)
```

### What Ansede Does NOT Do
- Execute code (purely static)
- Connect to the internet during scans
- Send telemetry or usage data
- Require compilation or build tools
- Access your package registry or dependency graph

### Performance
- **Throughput:** ~750–6,000 LOC/s (varies by language and analysis depth)
- **Memory:** Proportional to file count, typically <500MB for projects under 100K LOC
- **Parallel:** `--workers N` for multi-core scanning

---

## 3. Deployment Guide

### 3.1 Developer Workstation

```bash
pip install ansede-static
ansede-static src/
```

### 3.2 CI/CD Pipeline

#### GitHub Actions
```yaml
- uses: mattybellx/Ansede@v6.3.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

#### GitLab CI
```yaml
ansede:
  image: python:3.12
  script:
    - pip install ansede-static
    - ansede-static src/ --format sarif --output ansede.sarif --fail-on high
  artifacts:
    reports:
      sast: ansede.sarif
```

### 3.3 Air-Gapped Environments

```bash
# On internet-connected machine
pip download ansede-static -d ./offline-packages

# Transfer ./offline-packages to air-gapped machine
pip install --no-index --find-links ./offline-packages ansede-static
ansede-static src/
```

No network connectivity needed after installation.

### 3.4 Baseline and Incremental Scanning

```bash
# First scan — establish baseline
ansede-static src/ --format json --output baseline.json

# Subsequent scans — only new findings
ansede-static src/ --baseline baseline.json --fail-on high

# PR-only scanning
ansede-static src/ --diff-only
```

---

## 4. Compliance Mappings

### OWASP Top 10 (2021)

| OWASP Category | Ansede Coverage | CWEs Detected |
|----------------|-----------------|---------------|
| A01: Broken Access Control | **Strong** | CWE-639, CWE-862, CWE-306, CWE-352 |
| A02: Cryptographic Failures | Moderate | CWE-327, CWE-328 |
| A03: Injection | **Strong** | CWE-89, CWE-78, CWE-79, CWE-94, CWE-95 |
| A04: Insecure Design | Partial | CWE-862, CWE-306 |
| A05: Security Misconfiguration | Moderate | CWE-319, CWE-22 |
| A06: Vulnerable Components | Not covered | — |
| A07: Auth Failures | **Strong** | CWE-287, CWE-798 |
| A08: Software & Data Integrity | Partial | CWE-502 |
| A09: Logging & Monitoring | Partial | CWE-117 |
| A10: SSRF | Moderate | CWE-918 |

### PCI-DSS

| Requirement | Ansede Relevance |
|-------------|------------------|
| 6.5 — Address common coding vulnerabilities | Detects injection, XSS, auth flaws |
| 6.5.1 — Injection flaws | CWE-89, CWE-78 |
| 6.5.2 — Buffer overflows | Not primary focus |
| 6.5.3 — Insecure cryptographic storage | CWE-327, CWE-328 |
| 6.5.8 — Improper access control | CWE-639, CWE-862 |

### SOC 2

Ansede helps with CC6.1 (Logical and Physical Access Controls) by detecting missing authentication and authorization controls in application code.

---

## 5. Supply Chain Security

### For Users of Ansede

- **PyPI package:** `ansede-static` with SHA256 hashes in release notes
- **Signed releases:** Sigstore keyless signing (planned — see roadmap)
- **SBOM:** CycloneDX SBOM available for each release (planned)
- **Dependencies:** Single runtime dependency (`rich` for terminal output)
- **License:** MIT — no copyleft restrictions

### For the Ansede Project

- Dependency scanning in CI
- Pinned dependency versions
- Regular dependency updates

---

## 6. Support Model

| Tier | Response Time | Channels | Cost |
|------|---------------|----------|------|
| **Community** | Best effort | GitHub Issues, Discussions | Free |
| **Pro License** | 48 hours | Email + priority issues | Paid |
| **Enterprise** | Custom SLA | Dedicated support + consulting | Contact |

---

## 7. Migration Guide

### From Bandit

```bash
# Bandit
bandit -r src/

# Ansede (drop-in replacement)
ansede-static src/

# Both? Run them side-by-side
bandit -r src/ --format json --output bandit.json
ansede-static src/ --format json --output ansede.json
python -m tools.compare_scanners bandit.json ansede.json
```

### From Semgrep

Semgrep and Ansede are complementary. Semgrep excels at pattern-based rules; Ansede excels at data-flow-based auth detection.

```bash
semgrep --config=auto src/ --sarif --output semgrep.sarif
ansede-static src/ --format sarif --output ansede.sarif
# Upload both to GitHub Code Scanning
```

### From CodeQL

CodeQL's free tier covers public repos on GitHub. Ansede works everywhere — private repos, air-gapped, and without compilation.

---

## 8. Frequently Asked Questions (Enterprise)

**Q: Does Ansede send my code anywhere?**  
A: No. All analysis happens locally. No network calls are made during scanning.

**Q: How do I control which rules run?**  
A: Use `.ansede.toml` for per-project configuration, or `--exclude` / `--include` CLI flags.

**Q: Can I write custom rules?**  
A: Yes. Community rules are YAML files in `~/.ansede/community_rules/`. See [Writing Rules](writing-rules.md).

**Q: What's the false positive rate?**  
A: 0% on our 125-snippet clean code corpus. On real production code (366K LOC across 16 repos): 0.04 findings per 1,000 lines.

**Q: Is there a SaaS version?**  
A: An online scanner exists at ansede.onrender.com for testing individual snippets. Full SaaS is on the roadmap but not yet available.

**Q: How do I report a vulnerability in Ansede itself?**  
A: Use GitHub Security Advisories: https://github.com/mattybellx/Ansede/security/advisories/new
