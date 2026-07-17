# External Actions Checklist

> Everything left to do. Auto-completed items are checked. The rest need you (or a logged-in browser session).

---

## ✅ Done (Auto-Executed)

- [x] **Push v6.5.0 tag** — CI pipelines now running (SBOM, Sigstore, release, PyPI publish)
- [x] **Social preview PNG** — saved at `assets/social-preview.png` (1200×630)
- [x] **--demo mode** — `ansede-static --demo` works, exits clean
- [x] **"No findings" message** — now suggests `ansede-static --demo`
- [x] **Roadmap consolidated** — `ROADMAP.md` is now the single hub
- [x] **README rewritten** — IDOR-first positioning, demo link, who-is-this-for

---

## 🔴 Needs You — 5 Minutes Each

These need your GitHub login (I couldn't auth from this session):

- [ ] **Set GitHub repo description:** go to https://github.com/mattybellx/Ansede → click the gear icon next to "About" → paste:
  ```
  Find authorization bugs before attackers do. Free SAST — IDOR detection, 100% CVE recall, 0% false positives.
  ```
- [ ] **Set GitHub topics:** same panel, add: `sast` `static-analysis` `security-scanner` `idor` `authorization` `access-control` `cwe` `owasp` `devsecops` `python-security` `javascript-security` `offline-first` `code-review`
- [ ] **Star your own repo**

## 🔴 Needs You — 15 Minutes Each

- [ ] **Submit to awesome-static-analysis:** fork https://github.com/analysis-tools-dev/static-analysis, add Ansede entry (use template in `docs/awesome-list-entry.yml`), open PR
- [ ] **Submit to awesome-security:** https://github.com/sbilly/awesome-security
- [ ] **Submit to awesome-python-security:** https://github.com/guohaojin9/awesome-python-security

## 🔴 Needs You — 1 Hour Each

- [ ] **Tag 10 GitHub issues as `good first issue`** — ideas in `GOOD_FIRST_ISSUES.md`
- [ ] **HN Launch** — copy-paste from `docs/LAUNCH_HN_POST.md`, Tuesday 8am ET
- [ ] **Reddit Launch** — copy-paste from `docs/LAUNCH_REDDIT_POSTS.md`, stagger across 3 subs
- [ ] **Send 5 newsletter pitches** — templates in `docs/NEWSLETTER_PITCHES.md`

## 🔴 Needs You — Week-Level

- [ ] **Create Discord server** — channel plan in `DISCORD.md`, add link to README
- [ ] **Publish benchmark blog post** — draft at `docs/blog/BENCHMARK_2026.md`, post to dev.to + Medium
- [ ] **Record 60-second terminal demo** — script in `docs/DEMO_PACKAGE.md`, upload to YouTube
- [ ] **Add demo GIF/screenshot to README** after recording

## 🔴 Needs You — Month-Level

- [ ] **Submit to BSides CFP** — "Finding IDOR at Scale with Open-Source SAST"
- [ ] **Submit to PyCon US 2027 CFP** — "Building a SAST Engine in Python"
- [ ] **Verify CI ran** — check https://github.com/mattybellx/Ansede/actions for v6.5.0 tag workflows

---

*Everything has a template, script, or copy ready in the docs/ folder. Zero writing from scratch.*
