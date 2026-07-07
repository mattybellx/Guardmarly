#!/usr/bin/env python
"""Debug: why safe-pattern suppression didn't help OWASP FPR."""
from ansede_static.java_analyzer import analyze_java
from pathlib import Path

# Test known FP cases from each category
test_cases = {
    "crypto": "BenchmarkTest00054",
    "hash": "BenchmarkTest00009",
    "weakrand": "BenchmarkTest00010",
    "sqli": "BenchmarkTest00052",
}

for cat, name in test_cases.items():
    fp = Path(f"benchmarks/owasp/src/main/java/org/owasp/benchmark/testcode/{name}.java")
    if not fp.exists():
        print(f"{cat}: {name} NOT FOUND")
        continue
    src = fp.read_text()
    r = analyze_java(src, filename=str(fp))
    cwes = {f.cwe for f in r.findings if f.cwe}
    bl = src.lower()
    
    # Check for safe patterns
    has_secure_random = "securerandom" in bl or "threadlocalrandom" in bl
    has_safe_crypto = any(x in bl for x in ("sha-256", "sha-384", "sha-512", "aes/gcm", "pbkdf2withhmac"))
    has_echo = '"echo "' in bl
    has_callable = "callablestatement" in bl or "preparedstatement" in bl
    has_canonical = "getcanonicalpath" in bl
    
    flags = []
    if has_secure_random: flags.append("SecureRandom")
    if has_safe_crypto: flags.append("SafeCrypto")
    if has_echo: flags.append("Echo")
    if has_callable: flags.append("CallableStmt")
    if has_canonical: flags.append("CanonicalPath")
    
    print(f"{cat} {name}: {len(r.findings)} findings, CWEs={cwes}, safe_flags={flags}")
