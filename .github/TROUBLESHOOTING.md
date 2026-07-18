# Troubleshooting & Known Issues

## CI/CD

### Release workflow fails with "Not Found - delete a release asset"
- **Cause**: `softprops/action-gh-release@v2` API bug when tag was moved
- **Fix**: Downgraded to `@v1` in `.github/workflows/release.yml`
- **Workaround**: Create release manually at `https://github.com/mattybellx/Guardmarly/releases/new`

### VS Code Extension publish fails with "already exists"
- **Cause**: Version in `vscode-extension/package.json` already published
- **Fix**: Bump version before pushing
- **Workaround**: Manually trigger from Actions tab with `workflow_dispatch`

### Extension CI fails with "Cannot find name 'child_process'"
- **Cause**: Missing `"types": ["node"]` in `tsconfig.json`
- **Fix**: Added to `vscode-extension/tsconfig.json`

### Path filter prevents workflow trigger
- **Cause**: `publish-extension.yml` only triggers on `vscode-extension/**` changes
- **Fix**: Also included `.github/workflows/publish-extension.yml` in paths

## Local Development

### `con` file appears in repo root
- **Cause**: PowerShell `2>con` redirect creates this Windows device file
- **Fix**: Added to `.gitignore`; use `2>$null` instead of `2>con`

### Guardmarly CLI not found by extension
- **Cause**: `guardmarly` not on PATH (installed via `pip install --user`)
- **Fix**: Extension v1.1.0+ auto-detects via `python -m guardmarly.cli`
- **Manual**: Add `%APPDATA%\Python\Python3XX\Scripts` to PATH

### `jsonschema` config warning
- **Cause**: Optional dependency not installed
- **Fix**: `pip install jsonschema` (cosmetic only, doesn't affect scanning)

## Render.com

### Build fails with "InvalidVersion: Invalid version: 'dev'"
- **Cause**: `guardmarly>=6.4.0` in `webapp/requirements.txt` conflicted with Docker COPY of src/
- **Fix**: Removed guardmarly from requirements (Dockerfile copies src/ directly)

### Counter resets on deploy
- **Cause**: Free tier has ephemeral filesystem that resets on new Docker builds
- **Fix**: Counter survives spin-downs, only resets on code deploys
- **Permanent fix**: Upgrade to $7/month for persistent disk, or external JSON store

## Performance

### Scan hangs on large JS files
- **Cause**: JS structural AST analyzer can hang on deeply nested code
- **Fix**: `filename=""` workaround for JS; timeout fallback in engine
- **Status**: Being addressed in v0.3 JS engine

### Rust core panics with "stack overflow"
- **Cause**: Deeply nested code exceeding MAX_PARSE_DEPTH (500)
- **Fix**: `panic::catch_unwind` wrapper in `parse_with_language`

## Version Management

### Tag/version mismatch (PyPI fails to publish)
- **Cause**: `pyproject.toml` version doesn't match git tag
- **Fix**: Update all version references before tagging:
  - `pyproject.toml` → `version = "X.Y.Z"`
  - `webapp/templates/index.html` → hero badge
  - `vscode-extension/package.json` → `"version"`
  - `CHANGELOG.md` → release entry
