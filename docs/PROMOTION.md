# Promotion Launch Kit — May 18, 2026

Copy-paste these posts. One post per day. Don't spam them all at once.

---

## Reddit: r/Python (Post 1 — Show, don't tell)

**Title:** Bandit missed this CWE-639 IDOR. My open-source tool caught it across 35 real repos.

**Body:**

Most Python SAST tools are fine with `subprocess(shell=True)`. They completely miss the bugs that actually appear in CVE databases:

```python
@app.route("/invoice/<invoice_id>")
@login_required
def get_invoice(invoice_id):
    # Bandit: silent. ansede-static: CRITICAL
    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
    #     ^ no WHERE user_id = current_user.id → any user can see any invoice
```

I spent 6 months building ansede-static specifically to catch IDOR, auth bypass, and broken access control at the AST level — the stuff that Bandit and Semgrep OSS don't even look for.

**Verified May 2026:**
- 35 real open-source repos scanned, 0 failures (12,372 files, 1.76M lines)
- 33+ CWE types detected in production codebases including CWE-862 (missing auth), CWE-1333 (ReDoS), CWE-798 (hardcoded creds)
- 100% CVE snippet recall (115/115), 95.9% LLM auto-classification
- Zero dependencies, completely offline, single `pip install`
- 5 languages: Python, JavaScript, TypeScript, Go, Java, C#
- Incident clustering reduces findings by 49%

GitHub: https://github.com/mattybellx/Ansede
Live benchmarks: https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md

Free tier: 500 scans/day. Pro: £4.99 one-time or £49/year.

---

## Reddit: r/netsec (Post 2 — Data-heavy)

**Title:** I benchmarked 4 SAST tools against 82 real CVEs. Here are the results.

**Body:**

I built a deterministic CVE corpus (82 entries across Python, JavaScript, Go, Java, C#) and ran the same snippets through each tool with default configs:

| Tool | Real repos validated | CWE coverage | Interprocedural taint | Route analysis |
|------|---|---|---|---|
| ansede-static | **35** | **33+ per run** | **Full** | **11 checkers** |
| Bandit OSS | 1 (Python only) | ~10 | ❌ | ❌ |
| Semgrep OSS | Community | ~15-25 | ❌ (Pro only) | Basic |
| CodeQL CLI | Limited | ~25-40 | ✅ | Limited |

The full gap is in access control: IDOR (CWE-639), auth bypass (CWE-862), and missing ownership checks (CWE-285). Traditional SAST tools don't model routes, decorators, or ownership patterns.

Full methodology, raw data, and reproducibility protocol:
https://github.com/mattybellx/Ansede/blob/master/BENCHMARKS.md

I'm the author. Happy to answer questions about methodology.

---

## Hacker News: "Show HN"

**Title:** Show HN: ansede-static — offline SAST that caught 33 CWE types across 35 real repos

**Body:**

I built a zero-dependency static analysis tool that focuses on what existing SAST misses: broken access control.

It models framework routes, decorator-based auth guards, and ownership check patterns at the AST level — catching what regex-only tools miss.

Tech stack: pure Python, stdlib only. No network calls. No telemetry. Ships as a single .exe via Nuitka.

GitHub: https://github.com/mattybellx/Ansede
Docs: https://github.com/mattybellx/Ansede#readme

Install: `pip install ansede-static`

Happy to answer questions.

---

## Twitter/X (Post these across a week)

**Tweet 1:**
I ran ansede-static across 35 real open-source repos.
33 CWE types found. 0 failures. 1.76M lines analyzed.
The gap is access control. github.com/mattybellx/Ansede

**Tweet 2:**
Most SAST tools miss this:
@app.route("/admin/users")
def list_users():  # no @login_required
    return User.query.all()
Bandit: silent. ansede-static: HIGH.
github.com/mattybellx/Ansede

**Tweet 3:**
Zero-dependency offline SAST. Single pip install. 5 languages.
98.8% CVE recall. MIT licensed. 
github.com/mattybellx/Ansede

---

## GitHub: Issue/PR for awesome lists

Open issues on these repos asking for inclusion:

### awesome-python-security
https://github.com/guohaojin9/awesome-python-security/issues

Title: Add ansede-static — 98.8% CVE recall, zero-dependency SAST

Body:
ansede-static is a zero-dependency offline SAST tool for Python, JavaScript, Go, Java, and C#. It focuses on access control (IDOR, auth bypass, missing ownership checks) that traditional tools miss.

- GitHub: https://github.com/mattybellx/Ansede
- 81/82 CVE recall (98.8%), 3.6% FP rate
- MIT licensed
- 919 unit tests
- Actively maintained (latest: v2.2.0, May 2026)

### awesome-static-analysis
https://github.com/analysis-tools-dev/static-analysis

Open a PR adding to data/tools/ansede-static.yml

---

## Posting Schedule

| Day | Platform | Post |
|-----|----------|------|
| Mon | r/Python | Post 1 (Show, don't tell) |
| Tue | Hacker News | Show HN |
| Wed | r/netsec | Post 2 (Data-heavy) |
| Thu | Twitter | Tweet 1 |
| Fri | r/cybersecurity | Cross-post Post 2 |
| Sat | Twitter | Tweet 2 |
| Sun | GitHub | Awesome list PRs |

---

## Conversion Funnel

1. Reddit/HN post → GitHub stars → README "Pricing" section → Stripe checkout
2. Twitter → direct link → Stripe checkout
3. pip install → 500 free scans → upgrade prompt in terminal → Stripe checkout
4. VS Code extension → try SARIF format → "Pro required" → Stripe checkout
5. GitHub Action → need SARIF upload → license key → subscription
