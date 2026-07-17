# 5 Newsletter Pitches — Ready to Send
# From: mattybellx@gmail.com
# Just copy each To/Subject/Body into Gmail and send.

---

## Email 1: Python Weekly

**To:** editor@pythonweekly.com
**Subject:** New open-source SAST: 100% CVE recall vs 31% for Bandit

Hi,

I wanted to share ansede-static — a new open-source Python SAST scanner. It detected 100% of 68 Python CVEs in a benchmark, vs ~31% for Bandit.

The key difference: it does cross-function taint tracking to detect authorization bugs (IDOR, missing auth) that pattern-based tools miss. Also supports JS/TS, Go, Java, and C#.

Quick facts:
- pip install ansede-static
- 100% offline, zero dependencies (Python 3.9+)
- MIT licensed
- 0% false positives on clean code

GitHub: github.com/mattybellx/Ansede
Benchmark: dev.to/mattybellx/i-benchmarked-4-sast-tools-against-164-cves-heres-what-found-100-of-them-3m66

Would this fit Python Weekly?

Best,
Matty Bell

---

## Email 2: tldrsec

**To:** clint@tldrsec.com
**Subject:** First free IDOR scanner — 100% CVE recall, found what Semgrep missed

Hi Clint,

ansede-static is a new open-source SAST that's notable because it's the first free tool with built-in IDOR detection. It does inter-procedural taint tracking from HTTP routes → auth guards → database sinks.

Benchmark: 100% recall on 164 CVEs across 5 languages. Next best free tool: 33%.

Why this matters: Uber's breach (57M records) was an IDOR. Shopify's partner leak was a missing auth check. Free tools catch SQL injection but miss these entirely.

- GitHub: github.com/mattybellx/Ansede
- pip install ansede-static
- MIT license, 100% offline
- 1,268 tests, 0% FP on clean code

Happy to provide more details.

Best,
Matty Bell

---

## Email 3: Console.dev

**To:** hello@console.dev
**Subject:** ansede-static: Find auth bugs your SAST misses (free, offline)

Hi,

ansede-static is a CLI tool that scans your code for security bugs — specifically authorization flaws (IDOR, missing auth) that most free SAST tools miss.

Why it's interesting for Console readers:
- First free tool with inter-procedural IDOR detection
- One command: pip install ansede-static && ansede-static src/
- MIT licensed, 100% offline, zero dependencies
- Benchmarked against 164 CVEs with 100% recall

GitHub: github.com/mattybellx/Ansede

Best,
Matty Bell

---

## Email 4: DevOps Weekly

**To:** editor@devopsweekly.com
**Subject:** Add SAST to CI in 3 lines — catches what CodeQL misses

Hi,

ansede-static integrates with GitHub Actions in 3 lines:

```yaml
- uses: mattybellx/Ansede@v6
  with:
    path: src/
    fail-on: high
```

Notable because it catches authorization bugs (IDOR, missing auth) that most SAST tools miss — and it's 100% offline (works in air-gapped CI).

100% CVE recall vs 23% for Semgrep CE on the same corpus. 0% false positives.

GitHub: github.com/mattybellx/Ansede

Best,
Matty Bell

---

## Email 5: Changelog

**To:** editors@changelog.com
**Subject:** Benchmark: 4 SAST tools vs 164 CVEs — one got 100%

Hi Changelog team,

I published a data-driven benchmark of 4 SAST tools against 164 CVEs on dev.to. It's getting traction and I thought it might make a good Changelog mention.

The TL;DR: Ansede (open-source SAST) found 100% of CVEs. Semgrep CE found 23%. The gap is entirely authorization bugs — IDOR, missing auth — which most free tools literally can't detect.

- Blog: dev.to/mattybellx/i-benchmarked-4-sast-tools-against-164-cves-heres-what-found-100-of-them-3m66
- GitHub: github.com/mattybellx/Ansede
- MIT license, 100% offline

Best,
Matty Bell
