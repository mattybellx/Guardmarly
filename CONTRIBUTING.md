# Contributing to Guardmarly

Thanks for contributing.

## Setup

```bash
cd /home/runner/work/Guardmarly/Guardmarly
pip install -e ".[dev]"
```

## Validation

Run the existing repository checks before opening a PR:

```bash
pytest tests/ -q
python -m guardmarly.cli --list-rules
ruff check src/ --ignore E501,E701,E702,E741,F821,F401,F811,F841,E402 --fix
```

Repository-wide lint still has pre-existing issues outside `src/`; keep your changes focused and avoid expanding scope unless the task requires it.

## Contribution expectations

- Keep changes surgical and directly related to the task.
- Add or update tests when behavior changes.
- Do not add benchmark, recall, false-positive, competitor, or adoption claims unless they are reproducible and documented in `/home/runner/work/Guardmarly/Guardmarly/CLAIMS_AND_EVIDENCE.md`.
- When editing public docs or metadata, keep `README.md`, `pyproject.toml`, `action.yml`, extension docs, and related release-facing text consistent.

## Rules and findings

If you add or change detection logic:

- include focused tests in `/home/runner/work/Guardmarly/Guardmarly/tests`
- verify `python -m guardmarly.cli --list-rules`
- explain expected false-positive / false-negative trade-offs in the PR

## Security

Please use `/home/runner/work/Guardmarly/Guardmarly/SECURITY.md` for vulnerability reporting guidance.
