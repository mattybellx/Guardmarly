# ansede-static Growth Roadmap
May 18, 2026

## What's Done
- World-class SAST engine (98.8% CVE recall, 3.6% FP rate)
- Automated payment → license flow (Stripe → Render → key displayed)
- VS Code extension published on Marketplace
- GitHub Action for CI integration
- Promo posts on Reddit (r/Python, r/SideProject, r/opensource, r/hacking) + HN
- CI/CD all green (919 tests, all benchmarks passing)

## Immediate Revenue Blockers — Fix These Today

### 1. Stripe Redirect Setup (CRITICAL)
Right now someone pays but isn't redirected to get their key. Fix:

Go to https://dashboard.stripe.com/payment-links
For each link (One-time £4.99 and Pro £49/yr):
  1. Click the link → Edit
  2. After payment → "Don't show confirmation page"
  3. Redirect to: https://ansede.onrender.com/success?session_id={CHECKOUT_SESSION_ID}
  4. Save

### 2. Stripe Webhook Secret
Go to Render dashboard → ansede-license → Environment:
  - Add `STRIPE_WEBHOOK_SECRET` = (from Stripe webhooks page)
  - Add `STRIPE_SECRET` = (from Stripe API keys)

Without this, webhook verification runs in permissive mode.

---

## Next 7 Days — Traffic Engine

### Day 1: Cross-post the winning post
Find which Reddit post got the most upvotes. Cross-post it to:
- r/programming (different framing: "I benchmarked 4 SAST tools")
- r/cybersecurity (framed as research)
- r/devops (framed as CI/CD security tool)
- Lobste.rs (invite-only HN alternative — ask a friend for an invite)

### Day 2: ProductHunt Launch
1. Go to https://www.producthunt.com
2. Create product: "ansede-static"
3. Tagline: "Zero-dependency SAST — catches IDOR and auth bypass at 98.8% recall"
4. Schedule for Tuesday or Wednesday (best days)
5. Post in PH community the night before
6. Share launch link on your posts for upvotes

### Day 3: Write one comparison blog post
Title: "Benchmarked: ansede-static vs Bandit vs Semgrep vs CodeQL on 82 CVEs"
Post on:
- dev.to
- Medium
- Your own blog/GitHub Pages
- Link from README

This ranks for "best SAST tool" and "Bandit alternative" searches.

### Day 4: Submit to curated lists
- https://github.com/analysis-tools-dev/static-analysis (PR template ready)
- https://github.com/guohaojin9/awesome-python-security
- https://github.com/fabacab/awesome-cybersecurity-blueteam
- https://github.com/sbilly/awesome-security

### Day 5: Make a 2-minute demo video
Record: `pip install ansede-static` → scan a file → show findings → show Pro gate → show license activate → show SARIF working. Upload to YouTube. Embed in README.

### Day 6: Email security newsletter writers
Pitch to:
- tldrsec.com
- securityweekly.com
- pythonweekly.com
One-line pitch: "Open-source SAST tool hits 98.8% CVE recall — 33% better than Bandit"

### Day 7: Set up analytics
Add a simple download/scan counter so you know if traffic is converting:
- GitHub stars (free tracking)
- PyPI download stats (pypistats.org)
- Stripe dashboard (revenue)

---

## Week 2-4 — Conversion Optimization

### Make the free tier sting earlier
Right now the upgrade prompt fires at 450/500 scans. This is too late for casual users — they might never hit it. Add:
- "First scan" message: "You're on the Free tier. 500 scans/day. Upgrade for SARIF & SBOM."
- Show upgrade prompt on every 10th scan starting from scan 1 (subtle reminder)
- When SARIF is blocked, suggest `ansede-static license upgrade`

### Add a "Pro trial" mechanic
- First 3 SARIF scans are free with a "Try Pro" watermark
- After 3 scans, "You've used your 3 free SARIF scans. Upgrade to continue."

### Email capture
- On the pricing page, add "Get notified about updates" email field
- Optional: collect emails in exchange for a "SAST Buyer's Guide" PDF

---

## Month 2-3 — Sustainable Growth

### SEO
- Comparison page: "ansede-static vs Bandit" (high search volume)
- "Python SAST tools compared" (ranks for developer search)
- Each page links to GitHub + Stripe

### GitHub Stars
- Every Reddit/HN post links to GitHub
- Stars → more visibility in GitHub search → more installs
- Add "⭐ us on GitHub" in CLI output

### Paid Channels (when you have revenue)
- Google Ads on "Bandit alternative" / "Python SAST" keywords
- Sponsor Python/security newsletters
- Sponsor security podcasts

---

## Conversion Math

| Traffic Source | Est. Visitors | Conv. Rate | Pro Sales |
|---|---|---|---|
| Reddit posts (6 live) | 500-2000 | 0.5% | 2-10 |
| Hacker News | 200-1000 | 0.3% | 1-3 |
| ProductHunt | 1000-5000 | 0.2% | 2-10 |
| SEO (month 3+) | 200-500/mo | 1% | 2-5/mo |
| GitHub organic | 100-300/mo | 0.5% | 1-2/mo |

Conservative estimate: **5-15 Pro sales in month 1**, growing to 10-30/month by month 3.

---

## Success Checklist
- [ ] Stripe payment links redirect to success page
- [ ] Webhook secret set on Render
- [ ] ProductHunt launched
- [ ] Blog post published (dev.to + Medium)
- [ ] 4 awesome list PRs submitted
- [ ] Demo video on YouTube
- [ ] Email newsletter pitches sent
- [ ] Analytics tracking set up
