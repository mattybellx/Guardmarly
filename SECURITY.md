# Security Policy

Thanks for helping keep `guardmarly` safe and trustworthy.

## Supported versions

We currently prioritize security fixes for the latest release line and `main`. If you reproduce an issue on an older version, please re-test on the latest release before reporting it.

| Scope | Supported |
|---|---|
| Latest release line and `main` | ✅ |
| Older release lines | ⚠️ Best effort only |

## Reporting a vulnerability

If you discover a security vulnerability in Guardmarly, **please do not open a public issue**.

Instead, use **GitHub private vulnerability reporting**:

- https://github.com/mattybellx/Guardmarly/security/advisories/new

When reporting, please include:

1. Version: `guardmarly --version`
2. Steps to reproduce
3. Impact assessment (if known)

## In scope

- Scanner engine, CLI, reporters, analysis rules, and repository-maintained integrations
- Supply-chain issues in published packages or bundled release artifacts

## Out of scope

- Intentionally vulnerable examples under `samples/` and similar fixtures unless the issue affects real scanner behavior
- Issues requiring physical machine access
- Social engineering

We aim to acknowledge reports within 48 hours and coordinate a fix based on severity and reproduction quality.

## Responsible disclosure

We follow coordinated disclosure. If you report a vulnerability, we will:

1. Confirm receipt and begin investigation
2. Develop and test a fix
3. Release a patched version or mitigation guidance
4. Credit you in release notes if you want attribution

Please avoid posting exploit details publicly until a fix or mitigation is available.
