# HN Launch Post — "Show HN: Ansede — Free SAST with 100% CVE recall (vs 23% for Semgrep CE)"

## Post Title (choose one)

1. **"Show HN: Ansede — Open-source SAST with 100% CVE recall (Semgrep CE got 23%)"**
2. **"Show HN: We benchmarked 4 SAST tools against 164 CVEs. One got 100%."**
3. **"Show HN: Ansede — The SAST that catches IDOR and auth bugs (free, offline, MIT)"**

## Post Body

I built a SAST tool that focuses on authorization bugs (IDOR, missing auth, privilege escalation) — the vulnerability class behind the Uber, Shopify, and Facebook breaches.

The key technical difference: it does inter-procedural taint tracking from HTTP routes → auth guards → database sinks. Most free SAST tools analyze functions in isolation, so they literally cannot detect "this route parameter reaches a database query without an auth check."

**Benchmarked against 164 known CVEs across 5 languages:**

| Tool | Recall |
|------|--------|
| Ansede | **100%** (164/164) |
| Semgrep CE | 23.2% |
| CodeQL (free) | 33.6% |
| Bandit (Python only) | 30.9% |

**False positive test:** 125 clean production code snippets. Ansede: 0 false positives. Semgrep CE: 20-60%.

**Honest about limitations:**
- 5 languages (Python, JS/TS, Go, Java, C#) — not 30+
- Single maintainer — this is an indie project
- No SaaS platform (fully offline by design)
- Performance: ~750-6,000 LOC/s (not the fastest)

**Why I built this:**
I got frustrated that every free SAST catches SQL injection but literally none of them catch IDOR. "Any authenticated user can view any invoice" is a one-line bug that caused a $148M FTC settlement for Uber. And no free tool could find it. So I built one.

MIT licensed. One-command install. Fully offline — no telemetry, no API keys, no cloud upload.

```bash
pip install ansede-static && ansede-static src/
```

**Reproduce the benchmark yourself:**
```bash
python -m benchmarks.one_click_compare
```

GitHub: https://github.com/mattybellx/Ansede

Happy to answer questions about the architecture, benchmarks, or roadmap. Would especially love feedback from security engineers who use SAST daily — what would make you switch?

---

## Timing

- **Best day:** Tuesday or Wednesday
- **Best time:** 8:00-10:00 AM ET (when both US and EU readers are active)
- **Avoid:** Friday afternoon, weekends, major holidays, days with huge competing launches

## Success Criteria

- 200+ points on HN
- Top 10 for 12+ hours
- 300-500+ new GitHub stars within 48 hours
- 2,000+ new PyPI installs within 1 week

## Pre-Launch Checklist

- [ ] README is in final form (PROPOSED version applied)
- [ ] Demo GIF is embedded in README
- [ ] Social preview image is set on GitHub
- [ ] GitHub topics are updated
- [ ] PyPI description is improved
- [ ] `python -m benchmarks.one_click_compare` works end-to-end
- [ ] Website (ansede.onrender.com) is up and responsive
- [ ] Have bandwidth to respond to comments for 4-6 hours post-launch

## Comment Response Templates

### "How does this compare to Semgrep Pro?"
Semgrep Pro does cross-function analysis and can detect some auth patterns. But it requires login, has usage-based pricing, and their free tier (CE) is single-function only. Ansede is MIT licensed, 100% offline, and free forever. Different tools for different needs — we're complementary.

### "100% recall sounds too good to be true."
The 164-CVE corpus is a specific dataset we've curated. It's not every CVE ever. Some bug classes (memory corruption, crypto implementation flaws) are out of scope. We publish the full corpus and a one-click reproduction script so anyone can verify. If you find a case we miss, open an issue and we'll add it.

### "Single maintainer is risky for a security tool."
Agreed — this is a valid concern. We're actively building a contributor community (see GOOD_FIRST_ISSUES.md). The tool is MIT licensed, so even if I disappear, the code is open. We're also working on SBOM + signed releases + third-party review for enterprise confidence.

### "How does this handle false positives?"
We've tested against 125 clean production code snippets and 16 real production repos (366K LOC). Average: 0.04 findings per 1,000 lines. For comparison, most SAST tools flag 20-60% of clean code. We achieve this through framework-aware analysis, execution context inference, and guard detection rather than generic pattern matching.
