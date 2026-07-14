# Ansede Static — Detection Coverage Matrix

> Generated: 2026-07-14 | Version: v6.3.0

## Python Detection Coverage

| CWE | Category | Rule IDs | Confidence |
|---|---|---|---|
| CWE-22 | Path Traversal | PY-023F, PY-045 | High |
| CWE-78 | Command Injection | PY-005F, PY-008 | Critical |
| CWE-79 | Cross-Site Scripting | PY-009F | High |
| CWE-89 | SQL Injection | PY-004F, PY-001 | Critical |
| CWE-94 | Code Injection (exec) | PY-012 | Critical |
| CWE-95 | Code Injection (eval) | PY-012, PY-006F | Critical |
| CWE-117 | Log Injection | PY-062, PY-017 | Medium |
| CWE-200 | Information Exposure | PY-011 | Medium |
| CWE-295 | TLS Verification | PY-040 | High |
| CWE-326 | Weak TLS Protocol | PY-050F | High |
| CWE-327 | Weak Cryptography | PY-013 | High |
| CWE-330 | Weak Random (Crypto) | PY-018 | Medium |
| CWE-338 | Weak PRNG | PY-018 | Medium |
| CWE-345 | JWT Verification Disabled | PY-038 | High |
| CWE-362 | TOCTOU Race Condition | PY-065 | Medium |
| CWE-502 | Insecure Deserialization | PY-012, PY-006 | Critical |
| CWE-601 | Open Redirect | PY-009F | High |
| CWE-611 | XXE | PY-049 | Critical |
| CWE-639 | IDOR | PY-024F | High |
| CWE-798 | Hardcoded Secrets | PY-010 | Critical |
| CWE-862 | Missing Authorization | PY-002 | High |
| CWE-915 | Mass Assignment | PY-056 | High |
| CWE-918 | SSRF | PY-030F | High |
| CWE-942 | CORS Misconfiguration | PY-057 | High |
| CWE-1188 | Dangerous Defaults | PY-011 | High |
| CWE-1321 | Prototype Pollution | PY-060 | High |
| CWE-1333 | ReDoS | PY-051F | Medium |

## JavaScript Detection Coverage

| CWE | Category | Rule IDs | Confidence |
|---|---|---|---|
| CWE-22 | Path Traversal | JS-013, JS-038, JS-049 | High |
| CWE-78 | Command Injection | JS-007, JS-008 | Critical |
| CWE-79 | XSS | JS-001, JS-002, JS-003, JS-001F | Critical |
| CWE-89 | SQL Injection | JS-009, JS-010 | Critical |
| CWE-95 | Code Injection | JS-004, JS-005, JS-006 | Critical |
| CWE-117 | Log Injection | JS-072 | Medium |
| CWE-312 | Sensitive Data Exposure | JS-017 | Medium |
| CWE-330 | Weak Random | JS-079 | High |
| CWE-338 | Weak PRNG | JS-016 | Medium |
| CWE-345 | JWT Verification | JS-020 | High |
| CWE-601 | Open Redirect | JS-014, JS-039, JS-062 | High |
| CWE-798 | Hardcoded Secrets | JS-011, JS-012 | Critical |
| CWE-918 | SSRF | JS-015, JS-015F, JS-040 | High |
| CWE-943 | NoSQL Injection | JS-051F, JS-074, JS-088 | Critical |
| CWE-1004 | Cookie Security | JS-019 | Medium |
| CWE-1321 | Prototype Pollution | JS-018, JS-018F, JS-064 | High |

## Benchmark Results (2026-07-14)

| Test | Snippets | Precision | Recall | F1 |
|---|---|---|---|---|
| Gold-Standard Structured | 100 | 83.3% | 100% | 90.9% |
| Blind Evaluation v3 | 50 | 100% | 76.0% | 86.4% |
| Competitive vs Bandit | 50 | 100% | 72.0% | 83.7% |
| CVE Recall | 82 | 88.1% | 90.2% | 89.2% |

## Throughput

| Language | LOC/s |
|---|---|
| Python | ~1,900 |
| JavaScript | ~1,300 |
| Java | ~11,000 |
| C# | ~61,000 |
