# DeepSeek V4 remediation playbook for Guardmarly

This document is an execution-grade brief for fixing the repository's trust, consistency, licensing, and hygiene problems without guessing. It distinguishes what a coding agent can change safely in-source from what still requires owner, legal, marketplace, or third-party decisions.

---

## 1. Executive diagnosis

Guardmarly's adoption problem is primarily a **credibility problem**, not a missing-feature problem.

Why this blocks adoption more than feature work:

- Security buyers distrust unqualified absolutes. Claims such as `100% CVE recall`, `0% false positives`, `only free SAST`, `world-first`, and `fully offline` are extraordinary and currently not backed by a reproducible in-repo benchmark surface.
- The on-disk `/home/runner/work/Guardmarly/Guardmarly/LICENSE` text is **not standard MIT**, while multiple surfaces previously claimed MIT. That creates legal friction before evaluators even reach the scanner.
- Repository identity has drift: current source uses Guardmarly, while release history still contains Ansede / ansede-static references and older URLs.
- Current docs were inconsistent about supported languages, active directories, versions, and test counts.
- Tracked vendor/build output in `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/node_modules` and `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/out` weakens maintenance signals.

The fastest path to trust is: **reduce unsupported claims, make current surfaces internally consistent, document the license truthfully, and publish a reproducible evidence program.**

### Safe in-source actions

- Rewrite docs and metadata to match the current tree and code dispatch.
- Remove tracked vendor/build artifacts.
- Add evidence-policy and migration docs.

### Requires owner / legal / external action

- Choosing a final license model
- Editing repository description and marketplace listings outside source control
- Cleaning GitHub releases, release assets, and external URLs
- Publishing independently reviewable benchmark results

---

## 2. Target positioning

### Recommended repository description text

`Static analysis focused on authorization gaps, IDOR patterns, and related code-security findings across supported languages.`

### Recommended README headline

`Guardmarly — Static analysis for authorization gaps and risky code paths`

### Recommended README subheadline

`Guardmarly focuses on missing object-level authorization checks (IDOR / broken access control) and related security findings across supported languages.`

### Positioning rules

- Lead with authorization / IDOR / missing-authorization analysis.
- Treat other CWE coverage as secondary support, not the headline.
- Prefer `focused on`, `designed to detect`, `supports`, and `currently dispatches` over `only`, `best`, `#1`, or `world-first`.

---

## 3. Claim-audit policy

| Unsafe pattern | Why unsafe here | Compliant replacement |
|---|---|---|
| `100% CVE recall` | Universal and unscoped; historical notes already vary | `Detected X/Y cases in the published benchmark corpus on <date> using <command>.` |
| `0% false positives` / `zero false positives` | Needs a defined corpus and adjudication process | `Observed no confirmed false positives in <named corpus> under <method>.` |
| `only free SAST` | Broad market claim that requires market surveillance | Omit, or state the concrete capability instead |
| `world-first` / `#1` | Requires external validation and stable comparison rules | Omit until independently substantiated |
| `zero dependency` | False for the Python package as currently published because `/home/runner/work/Guardmarly/Guardmarly/pyproject.toml` declares `rich` | `CLI package with a small runtime dependency set` |
| `fully offline` / `100% offline` | Misleading repository-wide because this repo also contains `/home/runner/work/Guardmarly/Guardmarly/webapp` and hosted/demo references | `The CLI scans files on the machine or CI runner where it is executed.` |
| Unqualified competitor comparisons | Require pinned versions, configs, and corpus | `Comparison results belong in a reproducible benchmark repo with pinned tool versions.` |
| Stale language counts | The current CLI dispatches more file types than older README language counts | List supported languages or split full analyzers vs pattern-only coverage |
| Exact test counts in marketing copy | Counts drift as tests evolve | Prefer `Run pytest tests/ -q` over badge-style counts unless auto-generated |
| Implied release maturity (`production/stable`) without context | Can overstate readiness | Describe the surface factually; avoid maturity claims unless intentionally maintained |

### Required verification command set

```bash
cd /home/runner/work/Guardmarly/Guardmarly
rg -n "100% CVE recall|0% false positives|zero false positives|only free SAST|MIT|Ansede|ansede-static|zero-dependency|fully offline" README.md pyproject.toml action.yml vscode-extension .github AGENTS.md CHANGELOG.md
```

---

## 4. License correction decision tree

### Current mismatch

- `/home/runner/work/Guardmarly/Guardmarly/LICENSE` starts with MIT language but adds noncommercial / no-sale restrictions.
- That means the current file is **not the standard MIT license**.
- Any metadata claiming MIT is therefore inaccurate.

### Agent-safe changes now

- Use `license = { file = "LICENSE" }` in `/home/runner/work/Guardmarly/Guardmarly/pyproject.toml`.
- Remove `License :: OSI Approved :: MIT License` from classifiers.
- Replace README/license badge text with `custom terms` or equivalent factual wording.
- Add an owner decision record in docs; do **not** rewrite `/home/runner/work/Guardmarly/Guardmarly/LICENSE` unilaterally.

### Owner decision paths

#### Path A — Standard MIT

Owner must:
1. Replace `/home/runner/work/Guardmarly/Guardmarly/LICENSE` with the canonical MIT text.
2. Restore MIT wording consistently in:
   - `/home/runner/work/Guardmarly/Guardmarly/README.md`
   - `/home/runner/work/Guardmarly/Guardmarly/pyproject.toml`
   - `/home/runner/work/Guardmarly/Guardmarly/action.yml` or other marketplace metadata only if they mention license
   - `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/README.md`
3. Re-add the MIT classifier only after the file is corrected.

#### Path B — Another OSI-approved license

Owner must:
1. Select the license with legal review.
2. Replace `/home/runner/work/Guardmarly/Guardmarly/LICENSE` accordingly.
3. Update packaging classifiers and README/license references to match that exact SPDX identity.

#### Path C — Source-available / noncommercial

Owner must:
1. Stop using MIT language entirely.
2. Replace the mixed MIT text with a clearly named custom license.
3. Update PyPI, README, badges, action metadata, and marketplace pages to describe the license accurately.

#### Path D — Dual license

Owner must:
1. Choose the exact open-source + commercial terms.
2. Add explicit documents for each path.
3. Update package metadata, README, release docs, and purchase/commercial language consistently.

### Important constraint

Do not provide legal advice beyond: **the owner should obtain legal review before selecting or publishing a replacement license.**

---

## 5. Documentation rewrite plan

### Files to edit immediately when claims are unsupported

- `/home/runner/work/Guardmarly/Guardmarly/README.md`
  - Lead with authorization / IDOR positioning.
  - Remove unqualified recall / false-positive / `only` / `MIT` / `fully offline` language.
  - Add scope, limitations, evidence, and license truthfulness.
- `/home/runner/work/Guardmarly/Guardmarly/pyproject.toml`
  - Replace absolute description.
  - Use license-file metadata.
  - remove false MIT classifier.
- `/home/runner/work/Guardmarly/Guardmarly/action.yml`
  - Keep functionality, but make description and input text factual.
- `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/README.md`
  - Describe the extension as local CLI integration.
  - Remove `100% offline`, test-count badge marketing, and MIT text.
- `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/package.json`
  - Remove unsupported absolute/comparative claims and misleading keywords.
- `/home/runner/work/Guardmarly/Guardmarly/CHANGELOG.md`
  - Preserve history, but add a note that historical benchmark language is not the current evidence policy.
- `/home/runner/work/Guardmarly/Guardmarly/SECURITY.md`
  - Remove stale version/support statements and deleted-path references.
- `/home/runner/work/Guardmarly/Guardmarly/AGENTS.md`
  - Correct stale directory, license, version, and test-count assumptions.
- `/home/runner/work/Guardmarly/Guardmarly/.github/CI.md` and `/home/runner/work/Guardmarly/Guardmarly/.github/SETUP.md`
  - Remove brittle counts and false deployment assertions if they can be corrected from current files.

### New docs to add

- `/home/runner/work/Guardmarly/Guardmarly/CLAIMS_AND_EVIDENCE.md`
- `/home/runner/work/Guardmarly/Guardmarly/MIGRATION_FROM_ANSEDE.md`
- `/home/runner/work/Guardmarly/Guardmarly/CONTRIBUTING.md`

### Verification searches after editing

```bash
cd /home/runner/work/Guardmarly/Guardmarly
rg -n "100% CVE recall|0% false positives|zero false positives|only free SAST|MIT|fully offline|zero-dependency" README.md pyproject.toml action.yml vscode-extension AGENTS.md .github mkdocs.yml
rg -n "Ansede|ansede-static" README.md CHANGELOG.md MIGRATION_FROM_ANSEDE.md .github
```

---

## 6. Release/rename cleanup plan

### What an agent can document but not fully fix in-source

The repository cannot, through source edits alone:

- delete or edit already-published GitHub releases unless the owner performs those edits
- change the GitHub repository description
- change marketplace descriptions already published outside source control
- remove stale release assets already attached to release pages

### Owner-run release cleanup checklist

1. Review GitHub releases page for:
   - legacy Ansede / ansede-static naming
   - old onrender URLs
   - duplicate or accidental releases
   - release notes that do not match the tagged version
2. Decide the canonical version mapping policy:
   - one Git tag -> one GitHub release
   - one package version per release
   - extension release version documented separately if it diverges
3. Add or approve a migration note based on `/home/runner/work/Guardmarly/Guardmarly/MIGRATION_FROM_ANSEDE.md`.
4. Reconcile release asset provenance:
   - checksums
   - SBOM publication
   - signing policy
5. Publish an owner-approved release checklist.

### Canonical version policy

- `pyproject.toml` is the CLI/package version source.
- `vscode-extension/package.json` is the extension version source.
- Release notes must state clearly which artifact each version refers to.
- Historical releases may stay published, but they should not conflict with current naming.

### Suggested release checklist

- tests green
- claim-audit search clean on current docs
- package metadata matches license and version truth
- release notes scoped to actual changes
- artifact list, hashes, and signing published if available

---

## 7. Benchmark/evidence program

Create a separate benchmark repository rather than burying benchmark logic inside the main scanner repo.

### Recommended benchmark repo layout

```text
guardmarly-benchmarks/
├── corpora/
│   ├── cves/
│   ├── clean/
│   ├── authz-design-partners/
│   └── licenses.md
├── tools/
│   ├── versions.lock
│   └── configs/
├── scripts/
│   ├── reproduce.py
│   ├── adjudicate_false_positives.py
│   └── export_tables.py
├── results/
│   └── <date>/<tool>/<corpus>/...
├── schema/
│   └── benchmark_result.schema.json
├── Makefile
└── README.md
```

### Non-negotiable reproducibility requirements

- A single `make reproduce` or equivalent top-level command
- Pinned versions for Guardmarly and comparison tools
- Exact config files committed in-repo
- Corpus license/permission documented for every included sample
- Machine-readable outputs preserved
- Published limitations section

### Evaluation schema

Track at least:

- corpus name
- sample id
- language
- vulnerability family / CWE
- expected status
- detected status
- finding location
- confidence/severity
- adjudication notes
- tool/version/config hash

### False-positive adjudication procedure

1. Define the clean corpus before running tools.
2. Require two-pass review for disputed findings when publishing claims.
3. Record `confirmed TP`, `confirmed FP`, `needs review`, and `tooling/config issue` separately.
4. Never collapse `needs review` into `0% false positives`.

### Ethical corpus guidance

- Use openly licensed samples, intentionally vulnerable apps, owner-permissioned repos, or disclosed findings with permission.
- Do **not** mass-scan unsolicited third-party repositories and market the output as benchmark evidence.

---

## 8. Technical quality and repository hygiene

### Immediate hygiene actions

- Untrack `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/node_modules`
- Untrack `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/out`
- Untrack packaged extension artifacts such as `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/*.vsix`
- Keep `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/package.json` and `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/package-lock.json`

### Verification commands

```bash
cd /home/runner/work/Guardmarly/Guardmarly
git ls-files 'vscode-extension/node_modules/**'
git ls-files 'vscode-extension/out/**'
git ls-files 'vscode-extension/*.vsix'
```

### Ongoing hygiene policy

- Generated artifacts belong in CI artifacts or releases, not normal git history.
- SBOM/signing claims should be tied to actual workflow outputs and release notes.
- Add lightweight docs-freshness checks for top-level docs and extension metadata.
- Keep dependency policy factual: minimal runtime dependency claims should match `pyproject.toml`.

---

## 9. Adoption/community plan

### 30 days

- Stabilize messaging and license truthfulness
- publish contribution guidance
- open discussion prompts for supported frameworks and authorization use cases
- recruit a small number of opt-in design partners

### 60 days

- publish reproducible benchmark repo
- gather owner-permissioned case studies
- create clear good-first-issue and rule-contribution tasks
- define issue triage labels for false positives, false negatives, framework support, and docs

### 90 days

- publish benchmark updates with limitations
- document real-world findings that maintainers have confirmed or fixed
- refine onboarding for CI, SARIF, and extension usage based on user feedback

### Explicit outreach rules

- No spam
- No mass unsolicited scanning of third-party projects for promotion
- Use responsible disclosure for any real finding
- Prefer design-partner style collaboration over growth hacking

---

## 10. Prioritized implementation backlog

| Priority | Deliverable | Acceptance criteria | Owner | Risk | Rollback / verification |
|---|---|---|---|---|---|
| P0 | Claim cleanup in README, pyproject, action, extension docs | No current-surface MIT / recall / zero-FP / `only` / `fully offline` marketing remains | Coding agent | Low | `rg` claim search + manual diff review |
| P0 | License truthfulness fix | Packaging points to `LICENSE` file; false MIT classifier removed | Coding agent now; owner later for final license choice | Low now / medium later | `python -m build` optional, metadata diff review |
| P0 | Vendor/build artifact removal | `git ls-files` shows no tracked `node_modules`, `out`, or `.vsix` | Coding agent | Low | `git ls-files` verification |
| P0 | Remediation playbook | `/home/runner/work/Guardmarly/Guardmarly/DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md` exists with all required sections | Coding agent | Low | file review |
| P1 | Claims/evidence and migration docs | New docs added and linked from README | Coding agent | Low | link check + `rg` |
| P1 | Security / AGENTS / setup doc corrections | Obvious stale assertions corrected | Coding agent | Low | manual review |
| P1 | Release cleanup execution | Release pages, repo description, marketplace text aligned | Human owner | Medium | inspect GitHub surfaces |
| P2 | Standalone benchmark repo | Reproducible benchmark program published | Human + coding agent | Medium | `make reproduce` works |
| P2 | License finalization | Final legal license selected and propagated | Human owner + legal review | High | re-run claim/license audit |

---

## 11. Agent execution protocol

Follow this exact order.

1. **Inventory current truth**
   - Read `/home/runner/work/Guardmarly/Guardmarly/README.md`, `/home/runner/work/Guardmarly/Guardmarly/pyproject.toml`, `/home/runner/work/Guardmarly/Guardmarly/action.yml`, `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/README.md`, `/home/runner/work/Guardmarly/Guardmarly/vscode-extension/package.json`, `/home/runner/work/Guardmarly/Guardmarly/CHANGELOG.md`, `/home/runner/work/Guardmarly/Guardmarly/LICENSE`, `/home/runner/work/Guardmarly/Guardmarly/SECURITY.md`, `/home/runner/work/Guardmarly/Guardmarly/AGENTS.md`, and relevant `.github` docs.
   - Inspect actual language dispatch in `/home/runner/work/Guardmarly/Guardmarly/src/guardmarly/cli.py` and `/home/runner/work/Guardmarly/Guardmarly/src/guardmarly/__init__.py`.
2. **Make a claim matrix**
   - For each public statement, capture: file, exact claim, evidence source, status (`supported`, `unsupported`, `historical`, `owner decision needed`).
3. **Run baseline validation before editing**
   - `pip install -e ".[dev]"`
   - `pytest tests/ -q`
   - `ruff check src/ --ignore E501,E701,E702,E741,F821,F401,F811,F841,E402 --fix` or note existing lint limitations
4. **Apply low-risk content fixes first**
   - README
   - pyproject metadata
   - action metadata
   - extension README/package metadata
   - security/contribution/agent docs
5. **Apply repository hygiene fixes**
   - untrack `node_modules`, `out`, `.vsix`
   - keep manifests and lockfiles
6. **Add durable supporting docs**
   - claims/evidence
   - migration
   - playbook
7. **Re-run validation**
   - `pytest tests/ -q`
   - `python -m guardmarly.cli --list-rules`
   - extension validation if package metadata and tooling are present: `npm ci && npm run compile` inside `/home/runner/work/Guardmarly/Guardmarly/vscode-extension`
8. **Inspect diffs manually**
   - Ensure no unrelated scanner logic changed.
   - Ensure no generated/vendor files are staged.
9. **Stop at approval gates**
   - Ask owner for a decision before changing the actual license text.
   - Ask owner before publishing competitive/benchmark claims.
   - Ask owner before editing release pages or marketplace listings.
10. **Produce PR report**
   - List claims removed/qualified
   - list metadata corrected
   - list files untracked
   - list tests run and limitations
   - list owner-deferred decisions

### Explicit do-not rules

- Do **not** rewrite core scanner logic unless a factual doc fix requires a tiny code-path correction.
- Do **not** replace `/home/runner/work/Guardmarly/Guardmarly/LICENSE` with standard MIT text without owner approval.
- Do **not** invent benchmark numbers, user adoption evidence, or competitive results.
- Do **not** delete historical changelog entries just to hide old claims.
- Do **not** keep tracked `node_modules` or generated extension artifacts.

---

## 12. PR acceptance checklist

- [ ] `README.md`, `pyproject.toml`, `action.yml`, extension docs, and touched metadata are internally consistent
- [ ] No touched file describes the current license as MIT unless `/home/runner/work/Guardmarly/Guardmarly/LICENSE` has been replaced with actual MIT text
- [ ] No fabricated benchmark, recall, false-positive, adoption, or competitor claims were introduced
- [ ] Historical references retained in `CHANGELOG.md` are clearly treated as historical
- [ ] `pytest tests/ -q` result recorded
- [ ] `python -m guardmarly.cli --list-rules` result recorded
- [ ] Extension install/compile validation recorded if extension metadata changed
- [ ] `git ls-files` confirms no tracked `vscode-extension/node_modules`, `vscode-extension/out`, or `.vsix`
- [ ] Owner-only decisions are clearly separated from agent-safe edits
