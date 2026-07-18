# CI/CD Secrets Setup

Guardmarly's CI pipeline auto-publishes to PyPI, VS Code Marketplace, and Docker Hub.  
You only need to set these secrets once in your GitHub repo.

## Required Secrets

Go to: **GitHub → Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Where to Get It | Used By |
|---|---|---|
| `VSCE_PAT` | [Azure DevOps](https://dev.azure.com) → User Settings → Personal Access Tokens → New Token → "Marketplace (Publish)" scope | `publish-extension.yml` |
| `PYPI_API_TOKEN` | [PyPI](https://pypi.org) → Account Settings → API Tokens → "guardmarly" scope | `publish.yml` (fallback) |

`GITHUB_TOKEN` is auto-provided — no setup needed.

## PyPI Trusted Publishing (Preferred)

Instead of `PYPI_API_TOKEN`, use OIDC Trusted Publishing:

1. **PyPI**: Go to [publishing settings](https://pypi.org/manage/project/guardmarly/settings/publishing/)
2. Add a **pending publisher**:
   - Owner: `mattybellx`
   - Repository: `Guardmarly`
   - Workflow: `publish.yml`
   - Environment: `pypi`
3. **GitHub**: Settings → Environments → `pypi` → add protection rules if desired

The CI will try Trusted Publishing first, then fall back to `PYPI_API_TOKEN`.

## Render.com Auto-Deploy

1. Go to [Render Dashboard](https://dashboard.render.com)
2. **New → Web Service** → Connect `mattybellx/Guardmarly`
3. Render auto-detects `render.yaml` — no manual config needed
4. **Auto-deploy** is on by default — every push to `main` triggers a deploy

## What Happens On...

| Action | Triggers |
|---|---|
| `git push` to main | Tests + lint + VS Code extension publish |
| `git tag v6.5.0 && git push --tags` | + PyPI publish + GitHub Release + binaries |
| Render deploys | Automatic on every push to main |
