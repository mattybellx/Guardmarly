# Newsletter Pitch Templates — Ready to Send

## Pitch 1: Python Weekly

**To:** editor@pythonweekly.com
**Subject:** New open-source SAST: 100% CVE recall vs 31% for Bandit

Hi,

I wanted to share ansede-static — a new open-source Python SAST scanner. It caught my attention because it detected 100% of 68 Python CVEs in a benchmark, vs ~31% for Bandit.

The key difference: it does cross-function taint tracking to detect authorization bugs (IDOR, missing auth) that pattern-based tools miss. It also supports JS/TS, Go, Java, and C#.

Quick facts:
- pip install ansede-static
- 100% offline, zero dependencies beyond Python 3.9+
- MIT licensed
- 0% false positives on 125 clean code samples (Bandit: ~24-48%)
- 1,268 tests in CI

GitHub: https://github.com/mattybellx/Ansede
Benchmark: https://github.com/mattybellx/Ansede/blob/main/docs/BENCHMARKS.md

Would this be relevant for Python Weekly readers?

Best,
[Name]

---

## Pitch 2: tldrsec.com (Security Newsletter)

**To:** clint@tldrsec.com (check current contact)
**Subject:** Open-source SAST finds IDOR/auth bugs — 100% CVE recall, free, offline

Hi Clint,

I wanted to flag ansede-static — it's a new open-source SAST that's notable because it's the first free tool with built-in IDOR detection. It does inter-procedural taint tracking from HTTP routes → auth guards → database sinks, which catches authorization bugs that single-function scanners miss.

Benchmark data: 100% recall on 164 CVEs across 5 languages. Next best free tool: 33%.

Why this matters: Uber's 2016 breach (57M records) was caused by an IDOR. Shopify's partner data leak was a missing auth check. Free SAST tools catch SQL injection but miss authorization bugs entirely.

- GitHub: https://github.com/mattybellx/Ansede
- pip install ansede-static
- MIT license, 100% offline, no telemetry
- 1,268 tests, 0% FP on clean code

Happy to provide more details or demo access.

Best,
[Name]

---

## Pitch 3: Console.dev (Developer Tools Newsletter)

**To:** hello@console.dev
**Subject:** ansede-static: Find authorization bugs your SAST misses (free, offline)

Hi,

ansede-static is a new CLI tool that scans your code for security bugs — specifically the authorization flaws (IDOR, missing auth) that most free SAST tools miss.

Why it's interesting for Console readers:
- It's genuinely novel — first free tool with inter-procedural IDOR detection
- One command: pip install ansede-static && ansede-static src/
- Built by a solo developer, MIT licensed
- Benchmarked against 164 CVEs with 100% recall
- Beautiful terminal output (using Rich)

Would love to see this in Console if you think it fits.

Best,
[Name]
GitHub: https://github.com/mattybellx/Ansede

---

## Pitch 4: DevOps Weekly

**To:** editor@devopsweekly.com
**Subject:** Add SAST to CI in 3 lines — ansede-static GitHub Action

Hi,

ansede-static is a new open-source SAST that integrates with GitHub Actions in 3 lines:

```yaml
- uses: mattybellx/Ansede@v6
  with:
    path: src/
    fail-on: high
```

It's notable because it catches authorization bugs (IDOR, missing auth) that most free SAST tools miss — and it's 100% offline (no cloud upload needed, works in air-gapped CI environments).

Quick comparison: 100% CVE recall vs 23% for Semgrep CE on the same corpus.

Was thinking this might be useful for DevOps Weekly readers who want to add security scanning without complexity or cost.

Best,
[Name]
GitHub: https://github.com/mattybellx/Ansede

---

## Pitch 5: Changelog Weekly

**To:** editors@changelog.com
**Subject:** Show HN follow-up: The SAST that catches what 77% of scanners miss

Hi Changelog team,

ansede-static hit the front page of Hacker News recently ([link]) and I thought it might make a good Changelog mention.

The TL;DR: it's an open-source SAST that does inter-procedural taint tracking to find authorization bugs (IDOR, missing auth) — the vulnerability class behind real breaches at Uber, Shopify, and Meta. Most free SAST tools literally can't detect these because they analyze functions in isolation.

- GitHub: https://github.com/mattybellx/Ansede
- pip install ansede-static
- MIT license, 100% offline

Best,
[Name]

---

## Sending Tips

1. **Personalize** — Mention something specific about their newsletter
2. **Keep it short** — Curators scan dozens of pitches. Lead with the most interesting fact.
3. **Include links** — Make it easy to check out the project
4. **No attachments** — Links only
5. **Follow up once** — If no reply after 2 weeks, one gentle follow-up
6. **Track results** — Note which newsletters drive installs (check PyPI stats 48h after)
