# Ansede Demo Package

## 30-Second Demo (Terminal GIF)

### Script

```
[Terminal: clean prompt]

$ pip install ansede-static
  Installing... done ✓

$ cat app.py
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)

$ ansede-static app.py

╔══════════════════════════════════════════════╗
║  🚨 CRITICAL  CWE-639  IDOR Detected        ║
╠══════════════════════════════════════════════╣
║  File: app.py, Line 3                        ║
║  Route parameter 'id' flows to DB query       ║
║  without authentication check.                ║
║  Any authenticated user can access any        ║
║  invoice by changing the URL parameter.       ║
╠══════════════════════════════════════════════╣
║  Fix: Add @login_required + filter by user    ║
╚══════════════════════════════════════════════╝

  1 finding: 1 critical, 0 high, 0 medium, 0 low
```

### What This Shows

- Installation is one command
- The scanner reads route handlers
- It traces parameters to database queries
- It identifies missing auth guards
- The fix is clearly suggested
- Total time: ~25 seconds

---

## 60-Second Demo (Video Script)

### Scene 1: The Problem (0:00-0:15)
**Visual:** Code editor showing a Flask app.
**Voiceover:** "This looks like normal code. A route handler that fetches an invoice. But there's a problem — any logged-in user can view anyone's invoice. This is an IDOR vulnerability, and it's how Uber lost data on 57 million users."

### Scene 2: SAST Blind Spot (0:15-0:25)
**Visual:** Split screen — Bandit terminal showing "No issues found," Semgrep showing "No findings," CodeQL showing "No alerts."
**Voiceover:** "Most security scanners won't catch this. They look for injection flaws, not authorization gaps."

### Scene 3: Ansede Scan (0:25-0:40)
**Visual:** Terminal: `pip install ansede-static` → `ansede-static app.py` → Red CRITICAL finding appears.
**Voiceover:** "Ansede traces every HTTP route. It checks for auth guards. It follows data to database queries. And it flags the gap."

### Scene 4: The Fix (0:40-0:50)
**Visual:** Adding `@login_required` and `user=current_user.id` to the query. Re-scanning shows "No findings."
**Voiceover:** "Add the guard, filter by current user, and the vulnerability is gone. Scan again — clean."

### Scene 5: CI Integration (0:50-0:60)
**Visual:** GitHub Actions YAML snippet. PR comment showing "Ansede: No new findings ✅"
**Voiceover:** "Add this to CI and it runs on every PR. No API keys. No cloud upload. Your code stays private. github.com/mattybellx/Ansede"

---

## 5-Minute Technical Demo (Conference/Meetup)

### Part 1: Architecture Overview (1 min)
- How Ansede's analysis pipeline works
- Route extraction → Auth guard detection → Taint tracking → Sink analysis
- Difference from regex-based tools

### Part 2: IDOR Deep Dive (1.5 min)
- Walk through a real IDOR example in detail
- Show the IFDS graph visualization
- Compare with what Semgrep/Bandit do (and don't do)

### Part 3: Live Scan (1 min)
- Scan a deliberately vulnerable application
- Walk through each finding
- Show triage and fix workflow

### Part 4: CI/CD Integration (0.5 min)
- GitHub Actions setup
- SARIF output in GitHub Security tab
- PR comments

### Part 5: Q&A Hook (1 min)
- "What we're working on next"
- "How to contribute"
- "Try it yourself: pip install ansede-static"

---

## Demo Assets Checklist

- [ ] Terminal recording (asciinema or terminalizer)
- [ ] Animated GIF for README (under 2MB)
- [ ] YouTube video (2-3 min, polished)
- [ ] Conference slide deck (10-15 slides)
- [ ] One-pager handout (printable)
- [ ] Live demo environment (Docker container)
