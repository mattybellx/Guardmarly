# Ansede Marketing Copy Package

> Ready-to-use copy for all channels. Last updated: 2026-07-17

---

## Taglines (Pick Your Primary)

1. **"Find authorization bugs before attackers do."** ← RECOMMENDED PRIMARY
2. "The SAST that catches IDOR, not just injection."
3. "100% CVE recall. 0% false positives. 100% offline."
4. "What your SAST misses, Ansede finds."
5. "The only free SAST with built-in IDOR detection."

---

## One-Sentence Descriptions

1. Ansede is an open-source SAST that catches IDOR, missing authentication, and injection flaws with 100% CVE recall and zero false positives on clean code.
2. The only free security scanner that detects authorization vulnerabilities like IDOR and privilege escalation across 5 languages.
3. `pip install ansede-static` — one command to find SQL injection, XSS, IDOR, and 30+ CWE types in your code.
4. An offline-first SAST that finds the authorization bugs LinkedIn, Uber, and Shopify missed — before they become breaches.
5. Security scanning that developers actually enjoy: zero setup, zero noise, zero telemetry.

---

## Website Hero Sections

### Option A: Problem-Focused
> **Find authorization bugs before attackers do.**
> Most SAST tools catch SQL injection. Almost none catch IDOR — the vulnerability behind the Uber, Shopify, and Meta breaches. Ansede does.
> ```bash
> pip install ansede-static && ansede-static src/
> ```

### Option B: Capability-Focused
> **100% CVE recall. 0% false positives. 5 languages.**
> The most accurate free SAST scanner available. Catches what Semgrep CE, CodeQL, and Bandit miss — especially authorization flaws.
> [Try Online] [GitHub] [Docs]

### Option C: Developer-Focused
> **Security scanning that doesn't slow you down.**
> One command. Zero config. Works offline. Finds real bugs your pipeline misses — IDOR, missing auth, privilege escalation. Free and open source.
> ```bash
> pip install ansede-static
> ```

---

## Social Media Posts

### X/Twitter (280 characters)

*Option A — Benchmark:*
"I benchmarked 4 SAST tools against 164 real CVEs. Ansede: 100%. Semgrep CE: 23%. CodeQL: 33%. The gap? Authorization bugs. Most tools can't detect IDOR. Ansede can. GitHub: github.com/mattybellx/Ansede"

*Option B — Quick pitch:*
"Your SAST catches SQL injection. Does it catch IDOR? The bug behind Uber's 57M-record breach? Probably not. Ansede does — and it's free. pip install ansede-static"

*Option C — Developer angle:*
"Tired of SAST tools that scream at you for clean code? Ansede: 0 false positives on 125 clean snippets. 100% CVE recall on 164 real vulns. 5 languages. Free. Offline. github.com/mattybellx/Ansede"

### LinkedIn

"I built Ansede after getting frustrated that free security scanners miss entire categories of bugs — especially authorization flaws like IDOR.

Here's what most SAST tools catch: SQL injection, XSS, command injection.
Here's what they miss: IDOR, missing auth guards, privilege escalation.

These aren't edge cases. They caused the Uber breach (57M records), the Shopify partner data leak, and the Facebook access token flaw.

Ansede traces every HTTP route → through auth guards → into database queries. When a route parameter reaches a database without an auth check, it flags it. No other free tool does this.

Results so far:
• 100% CVE recall (164/164 across 5 languages)
• 0% false positives on 125 clean code samples
• 1,268 tests in CI
• World's first free open-source IDOR scanner

Try it: pip install ansede-static
GitHub: github.com/mattybellx/Ansede"

### Reddit (r/Python)

**Title:** I benchmarked Bandit, Semgrep, and my own SAST against 164 CVEs. Here are the results.

**Body:**
I've been working on a SAST tool called Ansede. To validate it, I put together a corpus of 164 known CVEs across Python, JS, Go, Java, and C# and ran 4 tools against them.

Results:
- Ansede: 100% (164/164)
- Bandit: ~30% (Python only)
- Semgrep CE: ~23%
- CodeQL: ~33%

The gap is almost entirely authorization bugs. No free tool detected a single IDOR or missing-auth vulnerability in the corpus. Ansede detected all of them.

I'm sharing because I want honest feedback — what am I missing? What would make you actually use this? Repo and full methodology at github.com/mattybellx/Ansede

### Hacker News (Show HN)

**Title:** Show HN: Ansede — Free SAST with 100% CVE recall (vs 23% for Semgrep CE)

**Body:**
I built a SAST tool that focuses on authorization bugs (IDOR, missing auth, privilege escalation) in addition to standard injection flaws. The key technical difference: it does inter-procedural taint tracking from HTTP routes → auth guards → database sinks, which catches bugs that single-function pattern matchers miss.

Benchmarked against 164 known CVEs across 5 languages:
- Ansede: 164/164 (100%)
- Semgrep CE: 38/164 (23%)
- CodeQL (free): 55/164 (33%)
- Bandit (Python only): 21/68 (30%)

False positive test on 125 clean code snippets: Ansede 0 FPs.

Honest about limitations: 5 languages (not 30+), single maintainer, no SaaS platform (yet). MIT licensed. All benchmark data and reproduction scripts in the repo.

Would love feedback — especially from security engineers who use SAST tools daily. What would make you switch?

---

## Product Hunt Launch Copy

**Tagline:** Find IDOR and auth bugs your SAST misses — 100% offline, 0% false positives

**Description:**
Ansede is a free, open-source SAST scanner that catches what other tools miss: IDOR, missing authentication, and privilege escalation bugs. It detects 35+ CWE types across Python, JavaScript, Go, Java, and C#.

**Why it's different:**
- World's first free IDOR scanner — traces route params → auth guards → DB queries
- 100% CVE recall (vs 23% for Semgrep Community Edition)
- 0% false positives on clean code (most SAST tools: 20-60%)
- Fully offline — no network calls, no telemetry, no API keys
- One command: `pip install ansede-static && ansede-static src/`

**Maker Comment:**
"Hi Product Hunt! I built Ansede because most free SAST tools skip an entire category of bugs: authorization flaws. They catch SQL injection, but not 'any logged-in user can access any invoice.' The latter caused the Uber breach (57M records), the Shopify data leak, and numerous others. Ansede traces data from HTTP routes through auth guards to database queries — catching what pattern-matchers can't. Happy to answer any questions about the tech, benchmarks, or roadmap!"

---

## Elevator Pitches

### 15-second (Networking Event)
"Ansede is an open-source security scanner that finds authorization bugs — IDOR, missing auth — that tools like Semgrep and Bandit miss. pip install ansede-static and you're running."

### 30-second (Meeting)
"Most SAST tools are great at finding SQL injection and XSS. But they miss authorization bugs — like IDOR, where any user can access anyone's data. The Uber breach? IDOR. Shopify's data leak? Missing auth. Ansede traces HTTP routes through auth guards into databases and flags the gaps. 100% CVE recall. Free. Open source."

### 60-second (Conference Introduction)
"Hi, I'm [name], creator of Ansede — an open-source SAST that focuses on authorization bugs. Here's the problem: every free SAST tool catches SQL injection. Almost none catch IDOR. That's a problem because authorization flaws caused the biggest breaches — Uber, Shopify, Meta. Ansede solves this by doing something different. Instead of pattern-matching, it builds a map of your application: every HTTP route, every auth guard, every database query. When a route parameter reaches a database without authentication, it flags it. We've validated against 164 CVEs — 100% recall. Next best free tool? 23%. It's `pip install ansede-static` and it's MIT licensed. I'd love to talk more about the architecture or benchmarks afterward."

---

## Bio Lines

**GitHub Profile:**
"Building Ansede — open-source SAST that catches authorization bugs other tools miss. 100% CVE recall. 0% FPs."

**Twitter/X:**
"Building ansede-static — free SAST with IDOR detection. Previously: shipping code with auth bugs. Now: finding them first."

**LinkedIn:**
"Creator of Ansede, an open-source SAST scanner focused on authorization vulnerability detection (IDOR, missing auth, privilege escalation). 100% CVE recall across 5 languages."

**Conference Speaker Bio:**
"[Name] is the creator of Ansede, an open-source static analysis tool that achieved 100% CVE recall on 164 known vulnerabilities — 4× better than the next-best free tool. They previously worked as [background] and are passionate about making security tools that developers actually want to use."
