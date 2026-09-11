# Guardmarly

**Offline static analysis for authorization gaps and taint bugs.**

Guardmarly is a command-line SAST scanner. It runs entirely on your machine —
no account, no upload, no telemetry — and is built around the vulnerability
classes that general-purpose linters usually miss: missing object-level
authorization (IDOR / CWE-639), missing authentication, and taint flows from
HTTP input into dangerous sinks.

```bash
pip install guardmarly
guardmarly src/
```

---

## What it detects

| Class | Examples |
| --- | --- |
| **Authorization** | IDOR (CWE-639), missing authentication (CWE-862/306), missing ownership filters, privilege escalation (CWE-285) |
| **Injection** | SQL (CWE-89), command (CWE-78), code/eval (CWE-94/95), template (CWE-1336), LDAP (CWE-90), XPath (CWE-643) |
| **Data handling** | Path traversal (CWE-22), unsafe deserialization (CWE-502), XXE (CWE-611), SSRF (CWE-918), open redirect (CWE-601) |
| **Secrets & crypto** | Hardcoded credentials (CWE-798), weak hashing (CWE-327/328), weak randomness (CWE-338), insecure TLS (CWE-295) |
| **Web hardening** | Missing CSRF (CWE-352), insecure cookies (CWE-614), permissive CORS (CWE-942), missing security headers (CWE-693) |

35+ CWE types in total. Run `guardmarly --list-rules` for the rule catalogue on
your installed version, or `guardmarly --explain-cwe CWE-639` for the reasoning
behind an individual finding.

## Language support

| Depth | Languages |
| --- | --- |
| **Full AST / taint analysis** | Python, JavaScript/TypeScript, Go, Java, C#, PHP, Ruby |
| **Structural parsers** | Kotlin, Swift, Scala, Rust, Dart, Lua, Elixir |
| **Pattern-aware (30+)** | C/C++, Shell, Dockerfile, Terraform, YAML, Solidity, Perl, Groovy, Haskell, OCaml, Clojure, R, Julia, Zig, Nix, Erlang, F#, VBA, PL/SQL, ABAP, COBOL, Crystal, Nim, Vala, Objective-C, ReasonML, and more |

Pattern-aware languages detect fewer classes of bug than full-AST languages —
see [Benchmarks](benchmarks.md) for what is measured and what is not.

## Why authorization bugs

Most vulnerabilities that make headlines are not clever memory bugs; they are
missing checks. A route takes an identifier from the URL, passes it to the
database, and never verifies that the caller owns the record:

```python
@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    return Invoice.query.get(invoice_id)
    # CWE-639: any authenticated user can read any invoice
```

Finding this requires three things at once: knowing where routes are declared,
knowing which database calls are lookups, and knowing whether the code between
them constrains the query by owner. Guardmarly models all three per framework
and reports the path it followed.

## Framework awareness

Route/auth/ownership semantics ship as declarative specs for Django, DRF,
Flask, FastAPI, Express, NestJS, Next.js, Spring, ASP.NET Core, Gin, Echo,
Laravel, and Rails. The Python distributions are in
[`rules/specs/`](https://github.com/mattybellx/Guardmarly/tree/main/rules/specs);
the unified accessor is `guardmarly.frameworks.get_framework_spec()`.

## Where to go next

- [Getting started](getting-started.md) — install, first scan, CI wiring
- [Configuration](configuration.md) — `guardmarly.json`, suppressions, baselines
- [CI integration](ci-integration.md) — GitHub Action, SARIF, PR gating
- [Writing rules](writing-rules.md) — add your own detectors
- [Architecture](architecture.md) — how the analysis pipeline fits together
- [FAQ](faq.md) — Windows console, false positives, licensing

## Claims and evidence

Guardmarly does not publish universal claims ("100% detection", "zero false
positives"). Every number quoted in these docs names the corpus it came from
and is reproducible with the scripts in [`scripts/`](https://github.com/mattybellx/Guardmarly/tree/main/scripts).
The policy is written down in
[CLAIMS_AND_EVIDENCE.md](https://github.com/mattybellx/Guardmarly/blob/main/CLAIMS_AND_EVIDENCE.md).

## License

Source-available, custom terms — see
[LICENSE](https://github.com/mattybellx/Guardmarly/blob/main/LICENSE).
