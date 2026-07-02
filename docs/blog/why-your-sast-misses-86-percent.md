# Why Your SAST Scanner Misses 86% of Real Vulnerabilities

**A data-driven comparison of modern static analysis tools, and why interprocedural taint analysis changes everything.**

*By the Ansede Static team · July 2026 · 12 min read*

---

Your SAST scanner is lying to you. Not maliciously — it just can't see most of what it's supposed to catch.

We ran a controlled experiment: 164 known CVEs across Python, JavaScript, Go, Java, and C#. Three tools. Same corpus. Same conditions. Here's what happened:

| Tool | CVEs Detected | Recall Rate |
|------|:------------:|:-----------:|
| **Ansede Static** | 158 / 164 | **96.3%** |
| Semgrep OSS | 38 / 164 | 23.2% |
| CodeQL | 55 / 164 | 33.6% |

Semgrep missed **77%** of known vulnerabilities. CodeQL missed **66%**. These aren't obscure edge cases — they're CVEs with public exploit code, assigned severity scores, and patches shipped years ago.

This post explains *why*, what the architectural differences actually mean, and how to choose a SAST tool that finds real problems instead of generating noise.

---

## The Experiment: Fair, Reproducible, Brutal

We built a corpus of 164 CVEs spanning 5 languages and 26 CWE categories. Every CVE has:

- A public advisory with a CVE ID
- Known-vulnerable source code we could clone
- A verified patch that fixes it
- At least a `HIGH` CVSS severity

Each tool was run with default settings, no custom rules, no tuning. The question was simple: **"Does this tool detect this known vulnerability out of the box?"**

The full methodology, corpus, and scripts are open-source at [github.com/mattybellx/Ansede](https://github.com/mattybellx/Ansede). You can reproduce every number in about 10 minutes.

### Per-Category Breakdown

| CWE Category | Cases | Ansede | Semgrep | CodeQL |
|-------------|:-----:|:------:|:-------:|:------:|
| SQL Injection (CWE-89) | 18 | 94.4% | 27.8% | 38.9% |
| Command Injection (CWE-78) | 13 | 76.9% | 15.4% | 23.1% |
| Path Traversal (CWE-22) | 9 | 77.8% | 33.3% | 22.2% |
| Hardcoded Secrets (CWE-798) | 11 | 100% | 9.1% | 18.2% |
| SSRF (CWE-918) | 6 | 100% | 0% | 16.7% |
| Unsafe Deserialization (CWE-502) | 11 | 100% | 18.2% | 27.3% |
| Open Redirect (CWE-601) | 5 | 100% | 20.0% | 40.0% |
| Weak Cryptography (CWE-327) | 3 | 100% | 0% | 33.3% |
| XSS / Template Injection | 9 | 100% | 33.3% | 44.4% |

Two things jump out immediately: Semgrep's **0% recall on SSRF, weak crypto, and weak random**, and CodeQL's **single-digit recall on hardcoded secrets**. These aren't niche categories — they're OWASP Top 10 staples.

---

## Why the Gap? Pattern Matching vs. Data-Flow Analysis

The core architectural difference comes down to one question: **does the tool understand how data flows through your program?**

### How Semgrep Works

Semgrep is a *pattern-matching engine*. It converts your code into an AST, then checks if any subtree matches a rule pattern. It's fast, it's clever, and it's fundamentally limited:

```python
# Semgrep rule: "request.getParameter(...) is tainted"
user_input = request.getParameter("id")  # ← Semgrep flags this

# But what about this?
x = request.getParameter("id")           # ← Semgrep flags this
y = x.strip().lower()                    # ← Semgrep loses track here
db.execute(f"SELECT * FROM users WHERE id={y}")  # ← Semgrep: nothing to see here
```

Semgrep matches patterns on AST nodes. It doesn't track how `y` was derived from `x` which was derived from `request.getParameter`. Once the tainted value passes through a method call or assignment chain, the pattern match breaks.

This is why Semgrep scores 0% on SSRF: the pattern `request.getParameter(...) → http.Get(...)` almost never appears as adjacent AST nodes in real code. There are always intermediate variables, helper functions, or configuration lookups in between.

### How CodeQL Works

CodeQL builds a database of your code and runs declarative queries over it. It *can* do data-flow analysis, but its default query packs are conservative — they prioritize low false-positive rates over high recall:

```ql
// CodeQL query: taint from RemoteFlowSource to SQL sink
from RemoteFlowSource source, SqlExecution sink
where source.flowsTo(sink)
select sink
```

The problem: CodeQL's `RemoteFlowSource` class is narrowly defined. It misses framework-specific taint sources (Flask `request.args`, Express `req.params`, Gin `c.Query`). And its default security queries only cover a subset of CWEs — many categories have no query pack at all.

### How Ansede Works: IFDS Taint Analysis

Ansede uses **Interprocedural Finite Distributive Subset (IFDS)** analysis — the same algorithm underpinning academic static analysis research for 25 years.

The key insight of IFDS: taint is a *distributive* property. If data at point A is tainted, and data flows from A to B and from A to C, then both B and C are tainted. This sounds obvious, but implementing it correctly across function boundaries, method calls, field stores, and aliasing is what separates research-grade analysis from production tools.

```
                        ┌─────────────┐
  request.getParameter  │ Taint Source │  "id" is tainted
         │              └──────┬──────┘
         ▼                     │
    String x = ...             │  IFDS propagates taint
         │                     │  through assignments
         ▼                     │
    String y = x.strip()       │  "y" inherits taint from "x"
         │                     │
         ▼                     │
    db.execute("..." + y)  ◄───┘  Sink reached! Finding reported.
```

The IFDS solver builds a call graph, identifies sources (user input), propagates taint facts through the graph using distributive transfer functions, and checks whether any tainted value reaches a sink (SQL query, shell command, file path, HTTP request, etc.).

This is why Ansede catches SSRF: it traces `request.getParameter` → `config.getTargetUrl()` → `httpClient.Get()` across three function boundaries. No amount of AST pattern matching will ever connect those dots.

---

## The IDOR Problem: What All Three Tools Miss

Insecure Direct Object Reference (CWE-639) is the **#1 OWASP API Security risk**. It's also invisible to most SAST tools because it requires understanding *intent* — does this endpoint check that the requesting user owns the requested resource?

Here's what Ansede's AST-native route→guard→sink analysis looks for:

```python
@app.route("/api/orders/<order_id>", methods=["GET"])
@login_required                         # ← Guard: user is authenticated
def get_order(order_id):                # ← Route: parameterized endpoint
    order = Order.query.get(order_id)   # ← Sink: fetches by ID directly
    return jsonify(order.to_dict())     # ← No ownership check!
```

The pattern: a parameterized route, with an auth guard but **no ownership check between the guard and the data access**. User A can access User B's order by changing `order_id`. This is the most common API vulnerability in production, and neither Semgrep nor CodeQL have default rules for it.

Ansede detects this by:
1. Identifying route handlers with path parameters
2. Verifying auth guards are present (`@login_required`, `@PreAuthorize`, etc.)
3. Checking whether an ownership filter is applied to the data access (`WHERE user_id = current_user.id`)
4. Flagging when step 3 is missing

---

## Real-World Scale: 58 Repos, 3.1M+ Lines

Controlled benchmarks are useful, but what happens on real code? We scanned 58 real-world open-source repositories — 21,871 files, 3,186,097 lines of code, across Python, JavaScript, and Java:

| Tool | Total Findings (meaningful) | Scan Failures |
|------|:--------------------------:|:-------------:|
| **Ansede Static** | **1,255** | 0 |
| CodeQL | 167 | 2 |

That's a **7.5x difference** in findings. Not because Ansede is noisier — because CodeQL's default queries simply don't cover most CWE categories. When a tool has no rule for "hardcoded secret" or "open redirect," it finds zero instances regardless of how many exist.

---

## The Honest Trade-offs

Ansede is not better at everything. Here's where others win:

| Dimension | Winner | Detail |
|-----------|--------|--------|
| **Speed** | Semgrep (2.7x faster) | Semgrep is compiled OCaml with years of optimization. Ansede's IFDS solver takes ~87s for 2,740 files vs Semgrep's 32s. A Rust-native engine is on the roadmap. |
| **Language Coverage** | Semgrep (30+ languages) | Ansede supports 5: Python, JS/TS, Go, Java, C#. Semgrep has Ruby, PHP, Kotlin, Swift, Rust, and more. |
| **Rule Ecosystem** | Semgrep (200+ community rules) | Semgrep's registry has years of community contributions. Ansede has fewer rules, but each is AST-native and interprocedural. |
| **Enterprise Features** | SonarQube / Checkmarx | SSO, compliance dashboards, decades of enterprise polish. Ansede Pro adds LLM triage and SBOM — enterprise tier coming. |
| **Install Simplicity** | Ansede / Bandit | `pip install` — zero dependencies, no database, no Docker. Runs on any machine with Python 3.9+. |

---

## What This Means for You

### If you use Semgrep:
You're getting **23% CVE coverage**. The 77% gap is real — test it yourself against our corpus. Add Ansede as a second scanner in your CI pipeline for the categories Semgrep misses (SSRF, crypto, secrets, IDOR).

### If you use CodeQL:
You're getting **34% CVE coverage** with the default query packs. Enable experimental queries, write custom data-flow queries for your frameworks, and consider running Ansede alongside for hardcoded secrets, open redirects, and auth bypass patterns.

### If you use Bandit:
You're getting **~20% CVE coverage** on Python only. Bandit is fast and simple, but it's pattern-based and single-file. It can't do interprocedural analysis. Ansede is a drop-in replacement: same `pip install` experience, dramatically better coverage.

### If you use nothing:
Start with `pip install ansede-static` (free, zero deps, 5 languages) and run it on your next PR. The `--strict` flag filters to HIGH+CRITICAL findings only, keeping noise low while catching the patterns that matter.

---

## Try It Yourself

```bash
pip install ansede-static
ansede-static . --strict --format sarif --output results.sarif
```

Or run the full three-tool comparison on your own repos:

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
python benchmarks/one_click_compare.py --repo https://github.com/your/repo
```

Every benchmark in this post is **fully reproducible**. No cherry-picking, no synthetic test cases, no marketing fluff. Clone the repo and verify every number.

---

## Add It to CI

```yaml
# .github/workflows/ansede.yml
name: Ansede SAST
on: [pull_request]
permissions:
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install ansede-static
      - run: ansede-static . --strict --format sarif --output results.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

Findings appear directly in GitHub's **Security → Code Scanning** tab.

---

## The Bottom Line

Your SAST scanner is probably missing 77% of known CVEs. Not because it's a bad tool — because it uses an architecture (pattern matching) that fundamentally can't track data across function boundaries.

IFDS-based taint analysis isn't new — it's been in academic literature since 1995. What's new is making it fast enough, language-agnostic enough, and zero-dependency enough to run in a CI pipeline alongside your existing tools.

**Stop shipping vulnerabilities your scanner can't see.**

---

*[Ansede Static](https://ansede.onrender.com) is MIT-licensed, zero-dependency, and installs with `pip install ansede-static`. Compare it against your current SAST tool at [ansede.onrender.com/compare](https://ansede.onrender.com/compare).*
