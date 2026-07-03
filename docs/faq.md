# FAQ / Troubleshooting

## General

### What languages does ansede-static support?

Python (mature), JavaScript/TypeScript (mature), Go (structural), Java (structural), C# (structural), Ruby (experimental), PHP (experimental).

### Does it require internet access?

No. Ansede is fully offline. No telemetry, no rule sync, no cloud dependency. Install once and scan anywhere.

### How is this different from Bandit or Semgrep?

Ansede detects **access-control vulnerabilities** (IDOR, auth bypass, ownership flaws) that Bandit and Semgrep OSS silently ignore. It also provides incident clustering (49% noise reduction), cross-language taint tracking, and offline-first design.

See the [comparison table](../README.md#comparison) in the main README.

### What output formats are available?

text, JSON, SARIF 2.1.0, HTML (interactive dashboard), CISO executive summary, SBOM (CycloneDX/SPDX with Pro license).

## Performance

### Scanning is slow on my project

Try batch mode for large codebases:

```bash
ansede-static src/ --batch --workers 8
```

This shares the analysis graph across all files and parallelizes via thread pool.

### My CI scan times are too long

Use incremental mode:

```bash
ansede-static . --incremental --fail-on high
```

This scans only files changed in the current git diff. For even faster checks, add:

```bash
ansede-static . --incremental --incremental-sha256
```

This caches unchanged files by content hash.

## False Positives

### Too many findings on a legacy codebase

Use baseline mode for gradual rollout:

```bash
# Day 0: freeze existing findings
ansede-static src/ --format json --output baseline.json --fail-on never

# Day 1+: only new findings
ansede-static src/ --baseline baseline.json --fail-on high
```

### A specific rule is noisy for my project

Disable it in `ansede.json`:

```json
{
  "disable_rules": ["PY-013", "CWE-862"]
}
```

Or suppress inline:

```python
# ansede: ignore[PY-013]
vulnerable_code_here()
```

## Installation

### pip install fails

Ensure you have Python 3.9+ and pip 21+:

```bash
python --version
pip install --upgrade pip
pip install ansede-static
```

The package has one external dependency (rich, for terminal output) — no npm, no Node, no compilers needed.

### Binary download

Standalone executables are available on the [Releases page](https://github.com/mattybellx/Ansede/releases) for Linux, macOS, and Windows.

## Errors

### "No supported source files found"

The scanner didn't find any `.py`, `.js`, `.ts`, `.go`, `.java`, `.cs` files in the target path. Check that your path is correct and contains source files.

### "license required for SARIF output"

SARIF, HTML, CISO, and SBOM output require a Pro license key. Get one at [ansede.onrender.com](https://ansede.onrender.com). Plain text and JSON output are always free.

### The scanner crashes on a specific file

Try with a generous timeout:

```bash
ansede-static path/to/file.py --timeout-per-file 60
```

If it still crashes, please [file a bug report](https://github.com/mattybellx/Ansede/issues/new?template=bug_report.yml).
