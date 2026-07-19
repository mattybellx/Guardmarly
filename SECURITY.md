# Security Policy

Thanks for helping keep `guardmarly` safe and trustworthy.

## Supported Versions

| Version | Supported |
|---|---|
| 6.x (latest) | ✅ Active |
| 5.x | ✅ Security fixes |
| < 5.0 | ❌ No longer supported |

## Reporting a Vulnerability

If you discover a security vulnerability in guardmarly, **please do not open a public issue**.

Instead, use **GitHub private vulnerability reporting**:

- https://github.com/mattybellx/Guardmarly/security/advisories/new

When reporting, please include:

1. Version: `guardmarly --version`
2. Steps to reproduce
3. Impact assessment (if known)

### Scope
- Scanner engine, CLI, analysis rules
- Supply chain issues in PyPI packages
- License server authentication bypass

### Out of scope
- Example/test code under `samples/` or `campaign/`
- Issues requiring physical machine access
- Social engineering

We aim to acknowledge reports within **48 hours** and provide a fix within **7 days** for critical issues.

## Advisories
https://github.com/mattybellx/Guardmarly/security/advisories

## Where to report

- **Private security vulnerabilities:** GitHub Security Advisories (link above)
- **Non-sensitive bugs / false positives / false negatives:** GitHub Issues
- **General questions:** GitHub Discussions

### Suggested report format

Include as much of the following as possible:

1. Affected version(s)
2. Reproduction steps / minimal sample
3. Security impact (confidentiality / integrity / availability)
4. Potential CWE mapping (if known)
5. Any proposed mitigation or patch direction

## Scope

guardmarly is a static analysis tool — it reads source code but never executes it. Security concerns include:

- **False negatives** — missing a real vulnerability in scanned code
- **ReDoS** — a crafted input causing the regex engine to hang
- **Path traversal** — if directory scanning follows symlinks outside the intended scope

## Responsible Disclosure

We follow coordinated disclosure. If you report a vulnerability, we will:

1. Confirm receipt and begin investigation
2. Develop and test a fix
3. Release a patched version
4. Credit you in the release notes (unless you prefer anonymity)

Please avoid posting exploit details publicly until a fix is available.
