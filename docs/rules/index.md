# Ansede Rule Database

Complete reference for every active rule shipped with ansede-static.

## Severity Classification

| Severity | Criteria |
|---|---|
| **CRITICAL** | Direct unauthenticated Remote Code Execution paths or unconditional global database overrides |
| **HIGH** | Horizontal/Vertical Broken Object Level Authorization (BOLA) and structural access bypass gaps |
| **MEDIUM** | Cryptographic vulnerabilities, missing explicit SSL tracking flags, and missing cross-site configurations |
| **LOW** | General information leaks or unseeded local diagnostic log structures |

## Rule Index

| Rule ID | CWE | Severity | Title |
|---|---|---|---|
| PY-001 | CWE-617 | MEDIUM | Silent exception swallowing |
| PY-002 | CWE-89 | CRITICAL | SQL injection via string formatting |
| PY-003 | CWE-78 | CRITICAL | OS command injection |
| PY-004 | CWE-95 | CRITICAL | Code injection via eval/exec |
| PY-005 | CWE-502 | CRITICAL | Unsafe deserialization |
| PY-006 | CWE-22 | HIGH | Path traversal |
| PY-007 | CWE-798 | CRITICAL | Hardcoded credentials |
| PY-008 | CWE-327 | HIGH | Weak cryptographic algorithm |
| PY-009 | CWE-338 | MEDIUM | Weak PRNG for security |
| PY-010 | CWE-918 | HIGH | SSRF via user-controlled URL |
| PY-011 | CWE-1188 | HIGH | Dangerous default configuration |
| PY-012 | CWE-502 | CRITICAL | Pickle deserialization |
| PY-013 | CWE-327 | HIGH | Legacy hash algorithm |
| PY-014 | CWE-117 | MEDIUM | Log injection |
| PY-015 | CWE-639 | HIGH | IDOR via unowned resource access |
| PY-016 | CWE-89 | CRITICAL | SQL injection in route handler |
| PY-017 | CWE-862 | HIGH | Missing authentication on route |
| PY-018 | CWE-285 | HIGH | Missing ownership verification |
| PY-019 | CWE-639 | HIGH | Resource mutation without ownership check |
| PY-020 | CWE-285 | HIGH | Broken access control |
| PY-021 | CWE-287 | HIGH | Auth bypass via presence-only check |
| PY-022 | CWE-918 | HIGH | SSRF heuristic |
| PY-023 | CWE-601 | HIGH | Open redirect |
| PY-024 | CWE-532 | MEDIUM | Sensitive data in logs |
| PY-025 | CWE-915 | HIGH | Mass assignment |
| PY-026 | CWE-345 | CRITICAL | Security decision without verification |

See [writing-rules.md](../writing-rules.md) for guidance on authoring custom rules.
