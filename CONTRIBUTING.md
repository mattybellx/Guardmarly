# Contributing to Guardmarly

Guardmarly welcomes contributions, especially in these areas:

- **Framework specs** — YAML rule definitions for new web frameworks
- **Sanitizer patterns** — reducing false positives on production code
- **Bug fixes** — especially false positive/negative corrections with test cases
- **Documentation** — clarity, examples, benchmark methodology

## Getting Started

```bash
git clone https://github.com/mattybellx/Guardmarly.git
cd Guardmarly
pip install -e ".[dev]"
pytest tests/ -q
```

## Contribution Guidelines

### For New Rules or Specs

1. Add the rule in `rules/specs/<language>/` as a YAML file
2. Include at least 1 positive test (must fire) and 1 negative test (must not fire)
3. Run `pytest tests/ -q` — all tests must pass
4. Run `python scripts/perf_check.py` — throughput must not drop below 80% of baseline

### For False Positive Fixes

1. Add a regression test that reproduces the FP
2. Fix the sanitizer or rule
3. Verify the FP no longer fires AND existing detections still work
4. Run full test suite

### For Framework Specs

Follow the schema in `rules/specs/python/django.yaml` as a reference:
- `sources`: Where user input enters the application
- `sinks`: Where tainted data causes harm
- `sanitizers`: Patterns that neutralize taint
- `propagators`: Operations that move taint without neutralizing it
- `auth_checks`: Patterns indicating a route IS protected
- `ownership_checks`: Patterns scoping queries to the current user
- `route_extractors`: Patterns identifying route definitions

## Claim and Evidence Policy

When making claims about detection quality, follow [CLAIMS_AND_EVIDENCE.md](CLAIMS_AND_EVIDENCE.md):

- Always name the corpus, version, and sample size
- Never claim "100%" or "zero" without qualification
- Publish methodology alongside results
- Document limitations honestly

## License

Guardmarly is source-available software. See [LICENSE](LICENSE) for terms.
Contributions are welcome under the same terms.
