# <img src="guard.png" width="36" style="vertical-align:middle"> Guardmarly — Static analysis for authorization gaps and risky code paths

<p align="center">
  <strong>Guardmarly focuses on missing object-level authorization checks (IDOR / broken access control) and related security findings across supported languages.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/guardmarly/"><img src="https://img.shields.io/pypi/v/guardmarly?color=22c55e" alt="PyPI"></a>
  <a href="https://github.com/mattybellx/Guardmarly/actions/workflows/ci.yml"><img src="https://github.com/mattybellx/Guardmarly/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mattybellx/Guardmarly/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-custom%20terms-orange" alt="License"></a>
</p>

```bash
pip install guardmarly
guardmarly src/
```

## Why Guardmarly

Most static analyzers are strongest on direct sink patterns such as SQL injection or command execution. Guardmarly's main differentiator is its focus on **authorization-sensitive flows**: route parameters, object lookups, and missing ownership checks that can lead to **IDOR / broken access control** findings.

```python
@app.route("/invoice/<id>")
def get_invoice(id):
    return Invoice.query.get(id)
    # Example risk: route parameter reaches an object lookup with no visible ownership check.
```

Guardmarly also reports other supported code-security issues such as injection, path traversal, secrets, and unsafe configuration patterns.

## Quick start

```bash
pip install guardmarly
guardmarly src/                          # text output
guardmarly src/ --format json -o r.json  # JSON report
guardmarly src/ --format sarif -o guardmarly.sarif
guardmarly --list-rules
```

## Supported analysis surface

Guardmarly does not provide identical analysis depth for every file type.

| Analysis mode | Languages / file types |
|---|---|
| Full analyzers in the current CLI | Python, JavaScript/TypeScript, Go, Java, C#, Rust |
| Pattern-based rule coverage in the current CLI | Ruby, PHP, Kotlin, Swift, Dart, Lua, Elixir, Scala, Clojure, Haskell, Shell, Dockerfile, Terraform |

See `/home/runner/work/Guardmarly/Guardmarly/src/guardmarly/cli.py` and `/home/runner/work/Guardmarly/Guardmarly/src/guardmarly/__init__.py` for the live dispatch and extension lists.

## Scope and limitations

- Guardmarly is **static analysis**. It can highlight risky authorization and data-flow patterns, but it cannot prove that an application's full authorization policy is correct.
- Findings still require human review. Framework conventions, helper functions, and business rules can change whether a result is actionable.
- Coverage differs by language and analyzer mode. Pattern-based languages are not equivalent to the full analyzers listed above.
- The repository also contains a hosted/demo surface and editor integrations. Do not treat repository-wide claims about deployment or privacy as interchangeable with the local CLI.

## Local CLI, GitHub Action, and hosted surfaces

- The **CLI** scans files on the machine or CI runner where you execute it.
- The root `/home/runner/work/Guardmarly/Guardmarly/action.yml` GitHub Action runs the scanner inside GitHub Actions and can optionally upload SARIF results to GitHub Code Scanning.
- The repository also contains `/home/runner/work/Guardmarly/Guardmarly/webapp`, which should be evaluated separately if you deploy or use a hosted scanner surface.

## Evidence and benchmarks

Guardmarly should not make performance or accuracy claims unless they are reproducible, scoped, and linked to the underlying corpus, tool versions, and commands.

- Public claim policy: [`CLAIMS_AND_EVIDENCE.md`](CLAIMS_AND_EVIDENCE.md)
- Remediation and benchmark program: [`DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md`](DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md)
- Historical release notes remain in [`CHANGELOG.md`](CHANGELOG.md), but older benchmark language there is preserved as release history rather than current marketing.

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
python -m guardmarly.cli --list-rules
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution expectations and validation steps.

## License

This repository currently ships a **custom / non-standard license text** in [`LICENSE`](LICENSE). It is not described as MIT in the project metadata in this branch. The owner decision record and follow-up paths live in [`DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md`](DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md#4-license-correction-decision-tree).
