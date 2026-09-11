# CI/CD Pipeline Reference

## What happens when you...

### Push to `main`
| Trigger | What runs |
|---|---|
| `ci.yml` | Tests (Linux py3.9/3.12/3.13, Windows py3.13, macOS py3.12) + ruff lint + wheel build |
| `guardmarly-code-scanning.yml` | Self-scan → SARIF → GitHub code scanning |
| `publish-extension.yml` | Publishes VS Code extension (if `vscode-extension/**` changed) |
| `pages.yml` | `mkdocs build --strict` → GitHub Pages (if `docs/**` changed) |
| Render.com | Auto-deploys `guardmarly.onrender.com` |

### Tag a version (`git tag v6.6.0 && git push --tags`)
| Trigger | What runs |
|---|---|
| `release.yml` | Compiles PyInstaller binaries (Linux, macOS, Windows) + GitHub Release |
| `publish.yml` | Publishes to PyPI (Trusted Publishing OIDC, API token fallback) |
| `publish-extension.yml` | Publishes VS Code extension to Marketplace |
| `scanner-image.yml` | Docker image to GHCR |
| `sbom.yml` | CycloneDX SBOM |
| `sigstore-sign.yml` | Sigstore signing |

## Version bumps checklist

`src/guardmarly/_version.py` is the single source of truth — `pyproject.toml`
reads it via `[tool.hatch.version]` and reports read it at runtime. Update these
files when releasing:

| File | Value | Example |
|---|---|---|
| `src/guardmarly/_version.py` | `__version__ = "X.Y.Z"` | `6.6.0` |
| `vscode-extension/package.json` | `"version": "X.Y.Z"` | `1.6.0` |
| `webapp/templates/index.html` | Hero badge version | `v6.6.0` |
| `CHANGELOG.md` | Release entry | See existing format |

`tests/test_version.py` fails if the version file and the packaging metadata
ever disagree, so a missed bump is caught by CI rather than by a user.

Then:
```bash
git add -A
git commit -m "release: v6.6.0"
git tag v6.6.0
git push --tags
git push
```

## Secrets required

| Secret | Where | Purpose |
|---|---|---|
| `VSCE_PAT` | GitHub Actions | VS Code Marketplace publish |
| `PYPI_API_TOKEN` | GitHub Actions | PyPI fallback (primary: OIDC) |
| `GITHUB_TOKEN` | Auto-provided | GitHub Release, GHCR |

## Webapp (Render.com)

- Uses `Dockerfile` at repo root (not `render.yaml`)
- Auto-deploys on every push to `main`
- Counter persists across spin-downs, resets on deploys
- Live at: https://guardmarly.onrender.com
