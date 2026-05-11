# Contributing to ansede-static

Thanks for considering contributing! Whether you're fixing a bug, adding a detection rule,
or improving docs — this guide has everything you need.

**First time?** Look for issues tagged [`good first issue`](https://github.com/mattybellx/Ansede/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
or try writing a [community rule](#writing-community-rules) — no core engine knowledge required.

## Quick navigation

- [Where to ask for help](#where-to-ask-for-help)
- [Development setup](#development-setup)
- [Run validations](#run-validations)
- [Add or update a rule](#add-or-update-a-rule)
- [Writing community rules](#writing-community-rules)
- [Pull request expectations](#pull-request-expectations)
- [Code style](#code-style)
- [Security reports](#reporting-security-issues)

## Where to ask for help

- **[GitHub Discussions](https://github.com/mattybellx/Ansede/discussions)** — questions, ideas, show-and-tell
- **[Issues](https://github.com/mattybellx/Ansede/issues)** — bugs and feature requests
- Security vulnerabilities: see [SECURITY.md](SECURITY.md) for private reporting

## Development Setup

```bash
git clone https://github.com/mattybellx/Ansede.git
cd Ansede
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1

# source .venv/bin/activate  # macOS/Linux
python -m pip install -e ".[dev]"
```

## Run validations

```bash
pytest tests/ -q --tb=short
python -m benchmarks.nvd_benchmark --fail-under 90 --quiet
python -m benchmarks.quality_benchmark --fail-under 100
python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100
```

For larger repo-shaped corpus work, the external runner also understands cached git-backed
manifest entries via `--cache-dir`, `--refresh`, and `--offline`.

If you add or update entries in `benchmarks/real_world_manifest.json`, keep them tightly scoped
to stable files or subdirectories, pin a full commit SHA, and avoid whole-repo scans that pull in
vendored assets or framework internals unless that noise is the point of the test.

All checks should pass before submitting a PR. CI targets Python **3.9–3.13**.

## Add or update a rule

1. Add a `_rule_NN(ctx: _Ctx) -> list[Finding]` function in the appropriate analyzer
2. Register it in the `_detect()` dispatcher
3. Add at least two tests: one that **triggers** the rule and one that does **not**
4. Include the CWE ID in the finding title: `CWE-XXX: Description`
5. Add or update a rule contract in `src/ansede_static/rules.py`
6. Add a trust-oriented case to `benchmarks/quality_corpus.py` when the detector is user-facing

When practical, include one realistic corpus fixture (or external corpus case) so regressions are caught early.

## Writing community rules

You can contribute custom detections without touching the core engine. Community rules
are YAML files loaded from `~/.ansede/community_rules/` and run alongside built-in rules.

1. Copy the template from `community_rules/flask-missing-rate-limit-CWE-307.yaml`
2. Adjust the `id`, `title`, `severity`, and `pattern` fields
3. Test it: `ansede-static --community-rules path/to/your.yaml src/`
4. Submit via: `ansede-static registry --publish path/to/your.yaml`
5. Open a PR adding the YAML to `community_rules/` and updating `community_rules/index.json`

See [Writing Rules](docs/writing-rules.md) for the full YAML schema and pattern syntax.

## Pull request expectations

- Keep PRs focused and reviewable; avoid unrelated refactors.
- Include a short “why now” in the PR description.
- If behavior changes, include before/after sample output.
- Update docs when adding user-facing flags, rules, or workflow changes.

## Code Style

- Zero external dependencies — stdlib only
- Type hints on all public functions
- No `# type: ignore` without a comment explaining why

Prefer narrowly scoped fixes over broad rewrites unless the issue explicitly requires architecture changes.

## Pull Request Checklist

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Quality benchmark passes (`python -m benchmarks.quality_benchmark --fail-under 100`)
- [ ] External corpus manifest passes (`python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100`)
- [ ] New rules have ≥ 2 tests (positive + negative)
- [ ] User-facing rules have a contract in `src/ansede_static/rules.py`
- [ ] No new dependencies added
- [ ] CHANGELOG.md updated under `## [Unreleased]`

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
