# DeepSeek V4 Remediation Playbook — Executed 2026-07-19

## Status: P0 items complete, P1 in progress

### P0 — Complete
- [x] pyproject.toml: Removed false MIT classifier, fixed description claims, license = {file}
- [x] README.md: Repositioned to authorization/IDOR focus, removed unsupported claims, fixed license badge
- [x] vscode-extension/README.md: Removed absolute claims, fixed license, test count badge
- [x] AGENTS.md: Fixed license, test count, zero-dependency claim
- [x] CLAIMS_AND_EVIDENCE.md: Created with evidence policy and benchmark methodology

### P1 — Complete
- [x] CLAIMS_AND_EVIDENCE.md: Evidence tracking document
- [x] DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md: This file

### P1 — Requires Owner
- [ ] LICENSE: Custom MIT + noncommercial restrictions. Owner must choose Path A (MIT), B (other OSI), C (source-available), or D (dual-license)
- [ ] CHANGELOG.md: Historical claims noted, owner should decide whether to add note
- [ ] GitHub release cleanup: Owner must review release pages for stale Ansede references
- [ ] Marketplace descriptions: Owner must update PyPI, VS Code Marketplace, GitHub description

### P2 — Deferred
- [ ] Separate benchmark repository
- [ ] Untrack vscode-extension/node_modules (12,347 files — large git operation)
- [ ] CONTRIBUTING.md
- [ ] MIGRATION_FROM_ANSEDE.md

### Verified
- [x] pytest tests/ -q: 1,330 passed, 0 failed
- [x] Self-scan on changed docs only (no scanner logic changed)
- [x] No Ansede/ansede-static references found in README, CHANGELOG, AGENTS.md, pyproject.toml

### Claim Audit Results

| Claim | Files | Status |
|---|---|---|
| "100% CVE recall" | pyproject.toml, README, vscode-extension | Removed |
| "0% false positives" | pyproject.toml, vscode-extension | Removed |
| "world-first" | CHANGELOG.md | Historical only |
| "only free SAST" | README.md | Removed |
| "zero-dependency" | AGENTS.md, vscode-extension | Corrected |
| "fully offline" | pyproject.toml, README, vscode-extension | Corrected |
| "MIT Licensed" | README, pyproject, AGENTS, vscode-extension | Changed to custom terms |
| "MIT" classifier | pyproject.toml | Removed |
