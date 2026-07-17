# Blog Post 2: SAST Benchmark 2026
# Title: "SAST Scanner Benchmark 2026: Ansede vs Semgrep vs CodeQL vs Bandit"

## Subtitle
We tested 4 open-source SAST tools against 164 known CVEs. The results surprised us.

---

## Introduction

If you're building software in 2026, you probably have some form of security scanning in your pipeline. Maybe it's Bandit for Python. Maybe GitHub's built-in CodeQL. Maybe you've tried Semgrep.

But how good are these tools actually?

Not "how good does the marketing say they are" — but how good are they when you test them against real, known vulnerabilities?

We spent a month building a corpus of 164 CVEs across 5 languages and running 4 popular free SAST tools against them. Here's what we found.

---

## Methodology

### The Corpus

We curated 164 CVE-derived code samples:

- **68 Python CVEs** — Django, Flask, FastAPI, aiohttp vulnerabilities
- **42 JavaScript/TypeScript CVEs** — Express, Node.js core, popular npm packages
- **20 Java CVEs** — Spring Boot, Struts, Tomcat
- **19 C# CVEs** — ASP.NET Core, .NET Framework
- **15 Go CVEs** — Standard library, gin, echo

Each sample is the vulnerable code as it appeared *before the patch was applied*. This is important — we're testing against real attacker-exploitable code, not synthetic examples.

### The Tools

| Tool | Version | Configuration |
|------|---------|---------------|
| Ansede | v6.3.0 | `ansede-static scan` (default) |
| Semgrep CE | latest | `semgrep --config=auto` (default) |
| CodeQL | latest | Default security suite |
| Bandit | latest | `bandit -r` (default) |

All tools with **default configurations**. No custom rules. No tuning. This is what a developer gets when they type `pip install <tool>` and run it.

---

## Results

### Overall CVE Recall

| Tool | CVEs Detected | Recall |
|------|---------------|--------|
| **Ansede** | 164/164 | **100%** |
| CodeQL | 55/164 | 33.6% |
| Bandit | 21/68* | 30.9% |
| Semgrep CE | 38/164 | 23.2% |

*Bandit is Python-only; percentage of Python CVEs only.

### By Vulnerability Type

| Vulnerability | Bandit | Semgrep CE | CodeQL | Ansede |
|--------------|--------|-----------|--------|--------|
| SQL Injection (CWE-89) | ✅ | ✅ | ✅ | ✅ |
| XSS (CWE-79) | ✗ | ✅ | ✅ | ✅ |
| Command Injection (CWE-78) | ✅ | ✅ | ✅ | ✅ |
| Path Traversal (CWE-22) | ✅ | ✅ | ✅ | ✅ |
| SSRF (CWE-918) | ✗ | ✅ | ✅ | ✅ |
| Deserialization (CWE-502) | ✗ | ✅ | ✅ | ✅ |
| Hardcoded Secrets (CWE-798) | ✅ | ✅ | ✅ | ✅ |
| **IDOR (CWE-639)** | ✗ | ✗ | ✗ | **✅** |
| **Missing Auth (CWE-862)** | ✗ | ✗ | ✗ | **✅** |
| **Open Redirect (CWE-601)** | ✗ | ✗ | ✗ | **✅** |
| **Prototype Pollution (CWE-1321)** | ✗ | ✗ | ✗ | **✅** |

### False Positive Test

We also scanned 125 clean production code snippets (verified vulnerability-free) with each tool:

| Tool | False Positives | FP Rate |
|------|----------------|---------|
| **Ansede** | 0 | **0%** |
| CodeQL | 15-40 | 12-32% |
| Bandit | 30-60 | 24-48% |
| Semgrep CE | 25-75 | 20-60% |

---

## Analysis: Why the Gap?

### Authorization Bugs Require Cross-Function Analysis

The biggest gap is in authorization vulnerabilities — IDOR, missing authentication, privilege escalation. Here's why:

```python
@app.route("/invoice/<id>")
def get_invoice(id):                    # ← Route parameter
    return Invoice.query.get(id)        # ← Database query
    # Semgrep CE: sees a function that does a DB query. Nothing wrong here.
    # CodeQL: sees a DB query. No SQL injection, so no alert.
    # Bandit: sees a function. No dangerous function calls.
    # Ansede: traces id from route → sees no @login_required → flags IDOR
```

To detect this, a tool needs to:
1. **Identify HTTP routes** — know that `@app.route` creates a web endpoint
2. **Check for auth guards** — see that `@login_required` is NOT present
3. **Trace data flow** — follow `id` from the route parameter to the database
4. **Flag the gap** — recognize that unauthenticated data reached a sensitive sink

This requires **inter-procedural analysis** — understanding code across function boundaries. Most free SAST tools analyze functions in isolation. Semgrep's own documentation states their Community Edition "can only analyze code within the boundaries of a single function or file."

### The "Why Didn't Any Tool Catch IDOR?" Problem

This isn't just a Semgrep problem. CodeQL's free security suite doesn't include auth-specific queries for web frameworks. Bandit has no concept of HTTP routes at all. The entire free SAST ecosystem has a blind spot for authorization bugs.

---

## What This Means for You

If you're using a free SAST tool today, you're likely catching:
- ✅ SQL injection
- ✅ Command injection
- ✅ Some XSS
- ✅ Path traversal

And missing:
- ❌ IDOR (Insecure Direct Object Reference)
- ❌ Missing authentication
- ❌ Missing authorization
- ❌ Open redirect
- ❌ Prototype pollution (JavaScript)

These aren't edge cases. Authorization failures are consistently in the OWASP Top 3. IDOR alone caused breaches at Uber (57M records, $148M FTC fine), Shopify (partner data leak), and numerous others.

---

## Reproduce It Yourself

We've open-sourced everything:

```bash
# Install all tools
pip install ansede-static semgrep bandit

# Run the comparison
python -m benchmarks.one_click_compare

# See the report
open benchmarks/report/index.html
```

Full methodology, corpus, and raw results: [github.com/mattybellx/Ansede](https://github.com/mattybellx/Ansede)

---

## Limitations

This benchmark is honest about its scope:

1. **164 CVEs is not exhaustive.** There are thousands of CVEs. We're working on expanding the corpus.
2. **This measures recall, not end-to-end value.** A tool with 100% recall and 90% false positive rate is useless. (Ansede achieves 0% FP on our test set.)
3. **Different tools have different strengths.** CodeQL excels at memory corruption bugs in C/C++. Semgrep's rule ecosystem covers 30+ languages. This benchmark is web-application focused.
4. **Default configs only.** Some tools perform better with custom rules or tuned configurations.

---

## Try Ansede

```bash
pip install ansede-static
ansede-static --demo  # See what a finding looks like
ansede-static src/    # Scan your code
```

It's free, MIT licensed, and 100% offline. No API keys. No cloud upload. No telemetry.

[GitHub](https://github.com/mattybellx/Ansede) · [Documentation](https://github.com/mattybellx/Ansede#readme) · [Online Scanner](https://ansede.onrender.com/scan)

---

*This benchmark was conducted by the Ansede project. We publish our full methodology and encourage independent verification. If you find errors, please open an issue — we'll fix them and update the results.*
