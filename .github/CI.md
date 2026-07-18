# CI/CD Pipeline Reference

## What happens when you...

### Push to `main`
| Trigger | What runs |
|---|---|
| `ci.yml` | Tests + lint (1,183 tests) |
| `publish-extension.yml` | Publishes VS Code extension (if `vscode-extension/**` changed) |
| Render.com | Auto-deploys `guardmarly.onrender.com` |

### Tag a version (`git tag v6.5.0 && git push --tags`)
| Trigger | What runs |
|---|---|
| `release.yml` | Compiles PyInstaller binaries (Linux, macOS, Windows) + GitHub Release |
| `publish.yml` | Publishes to PyPI (Trusted Publishing OIDC, API token fallback) |
| `publish-extension.yml` | Publishes VS Code extension to Marketplace |
| `scanner-image.yml` | Docker image to GHCR |
| `sbom.yml` | CycloneDX SBOM |
| `sigstore-sign.yml` | Sigstore signing |

## Version bumps checklist

When releasing a new version, update these files:

| File | Value | Example |
|---|---|---|
| `pyproject.toml` | `version = "X.Y.Z"` | `6.5.0` |
| `vscode-extension/package.json` | `"version": "X.Y.Z"` | `1.1.0` |
| `webapp/templates/index.html` | Hero badge version | `v6.5.0` |
| `CHANGELOG.md` | Release entry | See existing format |

Then:
```bash
git add -A
git commit -m "release: v6.5.0"
git tag v6.5.0
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
