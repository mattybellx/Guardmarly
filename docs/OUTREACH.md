# Outreach Templates — Anonymous Posting Guide

## Hacker News — Show HN

Title:
```
Show HN: Ansede — SAST scanner finds 96% of CVEs (Semgrep OSS: 23%, CodeQL: 34%)
```

Body:
```
I ran a reproducible 3-tool comparison against 164 known CVEs across
5 languages (Python, JS, Go, Java, C#). 

Results:
- Ansede: 96.3% recall
- CodeQL: 33.6% 
- Semgrep OSS: 23.2%

Also ran the OWASP Benchmark v1.2 (2,740 Java test cases, industry standard):
- Ansede: 62.0% recall
- Semgrep OSS: 59.4%

All benchmarks reproducible:
  python -m benchmarks.owasp_head_to_head
  python -m benchmarks.cve_recall_runner

The tool is MIT-licensed, fully offline, pip install. Comparison page with
all numbers: https://ansede.onrender.com/compare

Honest about weaknesses: Semgrep is faster (32s vs 87s) and has 30+
languages vs 5. But on the metric that matters — finding actual
vulnerabilities — the numbers speak for themselves.

Not selling anything. Free tier exists. Just wanted feedback from the HN
community on whether these results hold up to scrutiny.
```

Posting rules:
- Title under 80 chars ✅
- URL: https://ansede.onrender.com/compare
- HN allows Show HN for things you've made
- Anonymous account is fine — just create a throwaway
- Don't ask for upvotes, don't use voting rings
- Reply to every comment honestly — that's how Show HNs succeed

---

## r/netsec on Reddit

Title:
```
I benchmarked Semgrep, CodeQL, and an indie SAST tool against 164 CVEs
```

Body:
```
Methodology: 164 CVE snippets across Python, JavaScript, Go, Java, C#.
Each tool ran with default/OSS config. Same corpus for all three.

CVE recall:
- Ansede Static: 158/164 (96.3%)
- CodeQL CLI: 37/110 (33.6%) — Py+JS only
- Semgrep OSS: 38/164 (23.2%)

OWASP Benchmark v1.2 (2,740 Java cases):
- Ansede: 62.0% recall (877 true positives)
- Semgrep: 59.4% recall (840 true positives)

Three categories where Semgrep gets 0% and Ansede gets 74-100%:
weak random, insecure cookies, weak cryptography.

All benchmarks reproducible from the repo:
https://github.com/mattybellx/Ansede

Honest limitations: speed (87s vs Semgrep 32s), language breadth
(5 vs 30+), precision (47% vs Semgrep 62% on OWASP — though
real-world FP rate is 0.4% on 58 repos).

Curious what r/netsec thinks — does this methodology hold water?
```

Posting rules:
- r/netsec requires technical content, not marketing
- Don't mention pricing or "free trial"
- Use a throwaway account
- Reply to comments with data, not defensiveness
- The post should be about the METHODOLOGY, not the tool

---

## dev.to

Title:
```
I built a SAST scanner. It finds 96% of CVEs. Semgrep finds 23%. Here's how.
```

Body:
```
[Same as HN post but longer, more technical]

Include:
- What IFDS is and why it matters (simple explanation)
- How the CVE corpus works
- Per-language breakdown
- Architecture diagram (optional)
- Honest limitations section

Tags: #security #python #sast #devops #cybersecurity
```

---

## What NOT to Do (ban prevention)

| Don't | Why |
|---|---|
| Post to multiple subreddits same day | Cross-posting = ban |
| Include pricing/purchase links in posts | r/netsec bans commercial content |
| Use "guerilla marketing" tone | "Check out my tool!" = instant downvote |
| Astroturf (fake accounts upvoting) | Permanent ban everywhere |
| Reply "thanks, check out my tool!" to unrelated threads | Spam |
| Post the same content on HN + Reddit same hour | Looks coordinated |

## What TO Do

- **Lead with data, not product.** The benchmark IS the post
- **Be honest about weaknesses.** People trust you more
- **Reply to every comment.** Engagement drives visibility
- **Wait 24h between platforms.** HN first, then Reddit next day
- **Use a throwaway account with no history.** Fresh accounts get less scrutiny for Show HN than accounts with sketchy history
