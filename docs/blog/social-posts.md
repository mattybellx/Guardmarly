# Where to Post — and How Not to Get Removed

## 1. Hacker News — "Show HN" ⭐ BEST PLACE

**Where:** https://news.ycombinator.com/submit
**Rules:** Must be something you built that people can actually try. No marketing speak. No "revolutionary" claims. Be genuine — HN sniffs out hype instantly.
**How not to get removed:** Don't say "7.5x better than CodeQL" in the title. Just describe what it is plainly. Let the numbers speak for themselves in the body.

---

**Title:** Show HN: Ansede — an offline SAST scanner I built to catch IDOR and auth bypass

**URL:** https://github.com/mattybellx/Ansede

**Text:**

I've been working on this on and off for about a year. It started because I was reviewing a Flask app and Bandit gave it a clean bill of health — but it had an IDOR vulnerability where any logged-in user could access anyone else's invoices. Bandit saw the @login_required decorator and moved on. Semgrep OSS did the same thing.

So I started writing checks for the stuff they miss — not just "is there an auth decorator" but "does this route verify that the current user owns the resource they're accessing." That turned into a whole scanner.

What it does:
- Finds IDOR (CWE-639), missing auth (CWE-862), ownership bypass (CWE-285) — the access control stuff
- Also the standard injection/XSS/path traversal stuff
- Works on Python, JavaScript/TypeScript, Go, Java, C#, Ruby, PHP
- Fully offline, no dependencies beyond Python itself, no telemetry

Numbers (take with salt, I ran these myself):
- 100% recall on a corpus of 164 CVEs I put together (Semgrep OSS got ~23%, CodeQL ~34% on the same set)
- Scanned 33 real GitHub repos — found 1,255 things vs CodeQL's 167 (but I'm the first to admit some of those are probably noise)

Where I think it's weak and would love help:
- The corpus I benchmarked against is only 164 CVEs. I need more real-world test cases
- Java support is structural but doesn't have the deep Spring Security modeling yet
- I'm sure there are false positives I haven't caught — I've been staring at this code too long to see them
- The Go and Ruby analyzers are pretty basic

If anyone wants to try it on their own code and tell me what it gets wrong, I'd genuinely appreciate it. Or if you want to look at the benchmarking methodology and point out flaws, even better.

pip install ansede-static

Repo has the full methodology for the CVE recall test and the 3-tool comparison. The comparison scripts are in benchmarks/ if you want to reproduce or critique them.

---

## 2. Reddit r/Python

**Where:** https://www.reddit.com/r/Python/submit
**Rules:** Must be Python-related. Self-promo is okay if you're upfront about it and engage in comments. Don't just drop a link and leave.
**How not to get removed:** Use the "Discussion" or "Showcase" flair. Write a real post, not just a link. Python community appreciates "I built a tool, here's what I learned."

---

**Title:** I built a Python SAST scanner and would love feedback — especially on what it gets wrong

**Flair:** Discussion

**Text:**

Been working on a static analysis tool for about a year. It's written in Python (with a Rust core for the JS/TS parser), and I'm looking for people to try it on their code and tell me where it falls down.

The short version: it's like Bandit or Semgrep but focused on access control vulnerabilities — IDOR, missing authorization, ownership bypass. The kind of stuff where just checking for a decorator isn't enough.

You can install it with pip:

    pip install ansede-static

Then just point it at your code:

    ansede-static your_project/ --verbose

It supports Python, JS/TS, Go, Java, C#, Ruby, and PHP, but Python and JS are the most mature.

What I'm looking for:
- False positives on your real code. I've tested it on 33 repos but that's nothing
- Languages or frameworks where it's useless — be honest, I need to know where not to spend time
- The benchmarking methodology: does it hold up? The comparison scripts are all in the repo

If you try it and it's terrible on your codebase, please tell me. That's more useful than "nice project" comments.

GitHub: https://github.com/mattybellx/Ansede

---

## 3. Reddit r/netsec

**Where:** https://www.reddit.com/r/netsec/submit
**Rules:** Technical security content only. No vendor marketing. Self-posts are preferred over direct links. They're picky — low-effort posts get removed.
**How not to get removed:** Write a technical self-post explaining the methodology. The comparison data is interesting to this crowd. Don't just link the repo.

---

**Title:** I benchmarked 3 free SAST tools against 164 CVEs — would appreciate a sanity check on my methodology

**Text:**

I've been building a SAST scanner and wanted to know if it actually works, so I put together a corpus of 164 CVEs across Python, JavaScript, Go, Java, and C# and ran my tool against Semgrep OSS and CodeQL on the same set.

Results (my tool / Semgrep OSS / CodeQL):
- Python: 100% / 18.8% / 31.3%
- JavaScript: 100% / 25.0% / 37.5%
- Go: 100% / 22.2% / 33.3%
- Java: 100% / 20.0% / 30.0%
- C#: 100% / 30.0% / 35.0%

Before anyone asks: yes, I built the tool being tested. Yes, that's a conflict of interest. The corpus, the comparison scripts, and the full methodology are all in the repo — I'm posting this specifically because I want someone who isn't me to look at the methodology and tell me if it's fair.

Things I'm worried about:
- Corpus selection bias: I may have unconsciously picked CVEs my tool handles well
- The CodeQL setup might not be optimal — I used the default query packs
- Sample size: 164 CVEs isn't huge

If anyone wants to audit the methodology or run the comparison themselves, everything is in benchmarks/. The CVE corpus is in benchmarks/fixtures/. I'd genuinely appreciate criticism.

The tool itself is at https://github.com/mattybellx/Ansede if you want context, but the benchmarking methodology is what I'm hoping for feedback on.

---

## 4. Dev.to — ⭐ SAFEST BET (no ban risk)

**Where:** https://dev.to/new
**Why here:** Dev.to explicitly allows and encourages project posts under the `#showdev` tag. They have a "this is my project" flair. No ban risk as long as you actually write a post, not just a link. The audience is 100% developers.
**Tags to use:** #security #python #showdev #javascript #todayilearned

---

**Title:** I Built an Offline SAST Scanner — Try It on Your Code and Tell Me Where It Fails

**Cover image hint:** A terminal screenshot of ansede finding a vulnerability in under a second (use the demo script output)

**Text:**

I've been working on a side project for about a year and just published v5.2.0. It's a static analysis security scanner called Ansede, and I'm looking for people to break it.

**What problem it solves**

Most free SAST tools (Bandit, Semgrep OSS) work by pattern-matching. They look for `cursor.execute("SELECT * FROM users WHERE id = " + user_input)` and flag it. That catches SQL injection, yes. But it completely misses access control:

```python
@app.route("/invoice/<invoice_id>")
@login_required          # ← Bandit sees this and says "safe"
def get_invoice(invoice_id):
    return db.execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    )
    # Any user can see anyone's invoice. This is IDOR (CWE-639).
    # Bandit: silent. Semgrep OSS: silent. Ansede: CRITICAL.
```

That gap — the decorator is there, but there's no ownership check — is what got me started building this.

**What it catches**

- IDOR / broken access control (CWE-639, CWE-862, CWE-285)
- SQL injection, XSS, command injection, path traversal (the usual stuff)
- Hardcoded credentials, dangerous deserialization, ReDoS
- 35+ CWE types across 7 languages

**What I actually want from you**

I'm not here to pitch a product. This is a free open-source tool and it'll stay that way. What I want is for people to run it on their own code and tell me:
- Where it gives false positives (it definitely will on some codebases)
- Which frameworks it's useless on
- What blind spots I haven't thought of

Install:

```bash
pip install ansede-static
ansede-static your_project/ --verbose
```

**The numbers (take with salt)**

I put together a corpus of 164 CVEs and ran my tool, Semgrep OSS, and CodeQL against the same set. 100% vs ~23% vs ~34% recall respectively. But I built the tool and I built the corpus, so there's absolutely selection bias. The corpus and comparison scripts are in the repo — I'd love someone to audit them.

Repo: https://github.com/mattybellx/Ansede

---

## 5. Lobsters

**Where:** https://lobste.rs/ (invite needed — ask in the HN thread or DM someone on Twitter who's active there)
**Why here:** Like a smaller, friendlier HN. Very technical. They love security and programming language tools. No ban risk if you're genuine.
**Tags:** security, python, rust

---

**Title:** Ansede: an offline SAST scanner focused on access-control vulnerabilities

**URL:** https://github.com/mattybellx/Ansede

**Text:**

Built a SAST scanner that targets the vulnerability classes Bandit/Semgrep OSS don't ship rules for — specifically IDOR, missing authorization, and ownership bypass. The idea is that pattern-matching (is there an auth decorator? yes → safe) doesn't work for access control, which requires understanding the relationship between routes, auth guards, and database queries.

pip install ansede-static. Zero deps, fully offline. Works on Python, JS/TS, Go, Java, C#, Ruby, PHP.

I'd appreciate people trying it on their own code and reporting false positives. The CVE benchmark corpus and comparison scripts are in the repo for anyone who wants to audit the methodology.

---

## 6. Twitter/X — Thread Format

**Why here:** Quickest reach. Tag a few security people with genuine questions and they'll often try it.

---

Draft a thread (5 tweets):

1/ I built a SAST scanner focused on access-control bugs — IDOR, missing auth, ownership bypass. The stuff that every free tool ignores because checking for a decorator isn't enough. pip install ansede-static. Looking for people to try it and tell me what it gets wrong.

2/ Bandit sees @login_required and says "safe." But that decorator doesn't check if the current user OWNS invoice_id. That's the gap. My tool traces route parameters into DB queries to verify ownership scoping.

3/ I benchmarked against 164 CVEs across 5 languages. My tool: 100% recall. Semgrep OSS: 23%. CodeQL: 34%. But I built both the tool and the corpus — selection bias is real. The comparison scripts are in the repo. Please audit them.

4/ It's fully offline — no API keys, no cloud, no telemetry. Just pip install and run. Python, JS/TS, Go, Java, C#, Ruby, PHP. The Python and JS analyzers are mature. The others are... a work in progress.

5/ If you try it on your code and it's terrible, tell me. That's more useful than "nice project." github.com/mattybellx/Ansede

---

## 7. LinkedIn

**Why here:** Professional audience, less likely to ban. Posts with a personal story get good reach.
**Format:** Write as a personal update, not a product announcement.

---

**Text:**

Side project update: after about a year of evenings and weekends, I just published v5.2.0 of my offline SAST scanner.

It started because I found an IDOR vulnerability in a code review that three different security tools had missed. They all saw the @login_required decorator and stopped checking.

If anyone in my network does AppSec or code review — I'd love for you to try it on a real codebase and tell me honestly where it fails. That's more useful than praise.

pip install ansede-static
github.com/mattybellx/Ansede

