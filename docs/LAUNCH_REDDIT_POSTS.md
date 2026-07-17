# Reddit Launch Posts — Ready-to-Use

## r/Python Post

**Title:** I benchmarked Bandit, Semgrep, and my own SAST tool against 164 CVEs. Bandit missed ~70%.

**Body:**

I've been working on a SAST tool called Ansede. To make sure it wasn't just finding things at random, I put together a corpus of 164 known CVEs across Python, JS, Go, Java, and C# and ran 4 tools against them. Default configs, no tuning.

Results for Python CVEs specifically:
- **Ansede:** 68/68 (100%)
- **Bandit:** 21/68 (~31%)
- **Semgrep CE:** ~26%
- **CodeQL (free):** ~35%

The gap is almost entirely authorization bugs. No free tool detected a single IDOR or missing-auth vulnerability in the Python corpus. They all catch SQL injection. None of them catch "this Flask route lets any user view any invoice."

Here's what the IDOR detection looks like in practice:

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)  
    # Bandit: silent. Semgrep CE: silent.
    # Ansede: 🚨 CWE-639 IDOR — route param flows to DB without auth check
```

The tool traces HTTP routes → checks for @login_required or similar guards → follows data to databases/queries. If a route parameter reaches a sensitive sink without going through an auth check, it flags it.

Other stuff it does:
- 35+ CWE types across Python, JS/TS, Go, Java, C#
- IFDS taint tracking (cross-function data flow)
- Framework-aware (Flask, Django, FastAPI, Express, Spring Boot, ASP.NET)
- 0 false positives on 125 clean code snippets
- 100% offline, no telemetry, no API keys
- MIT licensed

`pip install ansede-static && ansede-static src/`

GitHub: https://github.com/mattybellx/Ansede

I'm sharing because I want honest feedback. What am I missing? What would make you actually use this over Bandit? What's the biggest pain point with your current SAST setup?

---

## r/netsec Post

**Title:** SAST Scanner Benchmark: 4 tools, 164 CVEs, one got 100% — and it's the one that catches IDOR

**Body:**

I ran a controlled benchmark of 4 open-source SAST tools against a corpus of 164 known CVEs across 5 languages. All tools with default configurations.

**Key finding:** Only one tool detected any authorization vulnerabilities (IDOR, missing auth) — and it achieved 100% recall on the entire corpus.

| Tool | Overall Recall | IDOR/Missing Auth Detection |
|------|---------------|---------------------------|
| Ansede | 100% | Yes — detects CWE-639, CWE-862 |
| CodeQL (free) | 33.6% | No |
| Semgrep CE | 23.2% | No |
| Bandit | 30.9%* | No |

*Python only

**Why authorization bugs are different:**
Detecting IDOR requires inter-procedural analysis — tracing data from HTTP route parameters through authentication middleware into database queries. Single-function pattern matching (used by most free tools) literally cannot do this. Semgrep's own docs acknowledge their CE edition "will miss many true positives" because it "can only analyze code within the boundaries of a single function or file."

**Why 100% recall matters for security:**
A SAST tool with 23% recall means 77% of known vulnerabilities in your code will go undetected. If you're relying on SAST as part of your security program, you're operating with a 77% blind spot.

**Methodology:**
- 164 CVE-derived code samples across Python, JavaScript, Go, Java, C#
- Each CVE: real vulnerable code from before the patch
- All tools: default configs, no custom rules
- Full corpus and reproduction script: github.com/mattybellx/Ansede

**Caveats:**
- Ansede is a single-maintainer project (disclosure: I am that maintainer)
- 5 languages, not 30+
- This measures recall, not precision (though Ansede also achieves 0% FP on clean code)
- Different tools have different strengths (e.g., CodeQL excels at C/C++ memory bugs)

I'm interested in the community's thoughts on SAST benchmarks and methodology. What would constitute a definitive, fair comparison in your view?

---

## r/programming Post

**Title:** I found that most free SAST tools miss 77% of known vulnerabilities. So I built one that doesn't.

**Body:**

Last year I got curious: how good are free SAST tools actually?

I grabbed 164 known CVEs across Python, JavaScript, Go, Java, and C#, ran 4 tools against them, and... the results were worse than I expected.

The best free tool detected 33.6% of the CVEs. The most popular free tool detected 23%. The most popular Python security linter detected ~31%.

So I built Ansede — a SAST that focuses on the vulnerability classes other tools miss, especially authorization bugs like IDOR. It does inter-procedural taint tracking (cross-function data flow analysis) to trace HTTP route parameters through auth guards into database queries.

Results: 100% recall on the 164-CVE corpus. 0% false positives on 125 clean code snippets.

It's MIT licensed, one-command install, fully offline.

```bash
pip install ansede-static && ansede-static src/
```

GitHub: https://github.com/mattybellx/Ansede

I'd love feedback from folks who use SAST tools regularly. What frustrates you about your current setup?

---

## Timing Strategy

- **Stagger posts** — r/Python first (largest audience), r/programming 2-3 days later, r/netsec last
- **r/Python:** Tuesday 8am ET
- **r/programming:** Thursday 8am ET  
- **r/netsec:** Following Tuesday 8am ET
- **Check each subreddit's rules** before posting — some have self-promotion limits

## Pre-Post Checklist

- [ ] README is applied with IDOR-first framing
- [ ] Demo GIF is visible in README
- [ ] benchmark data is linked with methodology
- [ ] Be online for 2-4 hours after posting to respond to comments
- [ ] Have a link to the one-click reproduction script
- [ ] Be honest about being the creator — transparency > pretending to be a user
