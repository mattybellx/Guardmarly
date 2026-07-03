# CI Integration

## GitHub Actions

### Basic scan

```yaml
- uses: mattybellx/Ansede@v5.5.0
  with:
    path: src/
    fail-on: high
    upload-sarif: true
```

### Full matrix (scan + test)

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install
        run: pip install ansede-static
      - name: Scan
        run: ansede-static src/ --format sarif --output ansede.sarif --fail-on high
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ansede.sarif
```

### Incremental PR checks (fast)

```yaml
- name: Incremental scan
  run: ansede-static . --incremental --fail-on high
```

### Baseline mode (zero-friction rollout)

```yaml
- name: Generate baseline
  run: ansede-static src/ --format json --output baseline.json --fail-on never

- name: Future scans
  run: ansede-static src/ --baseline baseline.json --fail-on high
```

## GitLab CI

```yaml
ansede-sast:
  image: python:3.11-slim
  before_script:
    - pip install ansede-static
  script:
    - ansede-static src/ --format sarif --output ansede.sarif --fail-on high
  artifacts:
    reports:
      sast: ansede.sarif
```

## Jenkins

```groovy
stage('SAST Scan') {
    agent any
    steps {
        sh 'pip install ansede-static'
        sh 'ansede-static src/ --format sarif --output ansede.sarif --fail-on high'
    }
    post {
        always {
            publishIssues(
                pattern: 'ansede.sarif',
                tool: sarif(),
            )
        }
    }
}
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/mattybellx/Ansede
    rev: v5.5.0
    hooks:
      - id: ansede-static
        args: [--incremental, --fail-on high]
```

## Rollout strategy

| Day | Action |
|-----|--------|
| 0 | Run in observe-only mode: `--fail-on never` |
| 1 | Generate baseline: `ansede-static src/ --format json --output baseline.json` |
| 3 | Enable baseline mode: `--baseline baseline.json --fail-on high` |
| 7 | Remove baseline, enforce `--fail-on high` directly |
| 14 | Add `--audit` for TP/FP classification in reports |
