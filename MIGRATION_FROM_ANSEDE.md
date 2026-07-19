# Migration from Ansede / ansede-static

Guardmarly was previously published under the name **Ansede** / **ansede-static**.
This document tracks the migration timeline and remaining cleanup items.

## Timeline

- **Pre-2026**: Project started as `ansede-static`
- **Early 2026**: Renamed to `guardmarly`, PyPI package republished
- **July 2026**: Repository cleanup — removed `benchmarks/`, `tools/`, `scripts/`, `docs/`, `site/`, `webapp/`, `campaign/`, editor extensions (pre-rewrite), and stale roadmap files
- **July 2026 (19th)**: Claims audit — removed unsupported absolute claims, fixed license metadata

## What Changed

| Before | After |
|---|---|
| `ansede-static` | `guardmarly` |
| `ansede_rust_core` | `guardmarly_rust_core` |
| MIT license badge | Custom terms badge |
| "100% CVE recall" | Scoped evidence in CLAIMS_AND_EVIDENCE.md |
| "Zero false positives" | Per-language FP rates in CLAIMS_AND_EVIDENCE.md |

## For Users Upgrading

```bash
# Uninstall old package
pip uninstall ansede-static

# Install new package
pip install guardmarly

# Update CI configs: replace ansede-static with guardmarly
# Update .github/workflows references
```

## Owner Remaining Tasks

- [ ] Review GitHub Releases page for stale Ansede references
- [ ] Update PyPI project description
- [ ] Update VS Code Marketplace listing
- [ ] Update any external URLs referencing ansede-static
- [ ] Decide final license model (see LICENSE section in DEEPSEEK_V4_REMEDIATION_PLAYBOOK.md)
