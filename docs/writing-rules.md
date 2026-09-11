# Writing rules

Guardmarly ships with a rule registry plus support for your own pattern rules.
Custom rules are YAML, use a deliberately constrained subset of the language,
and are validated before they can fire.

## Where rules live

| Location | Scope | Loaded when |
| --- | --- | --- |
| `~/.guardmarly/community_rules/*.yaml` | Your machine, every project | Always |
| `rules/` in this repository | Project | Project `custom_rules_file` or registry packs |
| `community_rules/auto_generated/` | Project | With `--apply-auto-rules` |
| Any file named by `custom_rules_file` in `guardmarly.json` | Project | On every scan |

`--list-rules` shows the catalogue the current process would use, including
community and custom rules, so you can confirm a new rule was picked up.

## Rule format

```yaml
# community/django-debug-enabled-CWE-489.yaml
id: community/django-debug-enabled-CWE-489
title: "Django DEBUG mode enabled (information disclosure)"
cwe: CWE-489
severity: high
language: python
frameworks: [django]
description: |
  DEBUG=True leaks stack traces, settings and environment variables to
  end users.
pattern: |
  DEBUG\s*=\s*True
fix: |
  Set `DEBUG = False` in production and configure proper error handling.
tags:
  - owasp:A05
  - information-disclosure
```

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Stable identifier; `community/<slug>` for shared rules |
| `title` | yes | One line, shown in reports |
| `cwe` | yes | `CWE-<number>` |
| `severity` | yes | `critical`, `high`, `medium`, `low`, `info` |
| `language` | no | Restricts the rule to one language |
| `frameworks` | no | Only run when a framework marker is present |
| `pattern` | yes | Regular expression matched against source text |
| `description` / `fix` | no | Rendered in `--verbose` output |
| `tags` | no | Free-form labels (OWASP, category) |

Regular expressions are run through a ReDoS circuit breaker: pathological
patterns are blacklisted for the rest of the run instead of hanging the scan.
Prefer anchored, linear-time patterns and avoid nested quantifiers.

## The one rule for rule authors

**Every rule needs both sides.** A rule that fires is not finished until it also
demonstrably *does not* fire on safe code:

```text
community_rules/
  my-rule-CWE-XXX.yaml
<golden-corpus>/CWE-XXX/
  vulnerable.py.test     # must be detected
  secure.py.test         # must stay clean
```

The corpus defaults to `.guardmarly/golden_corpus` in the working directory;
this repository keeps its own at `.ansede/golden_corpus` and passes it
explicitly:

```bash
guardmarly --dse-validate --golden-corpus .ansede/golden_corpus
```

`--dse-validate` runs both sides of every rule before a release is tagged.
Rules without a negative case are how a scanner becomes something people turn
off.

## Rule quality checklist

1. Does it fire on the vulnerable fixture and stay silent on the secure one?
2. Is the CWE correct — not merely adjacent?
3. Will it fire on minified or generated files? (If so, exclude them.)
4. Is the pattern anchored tightly enough to avoid matching documentation and
   test fixtures?
5. Does the `fix` text describe a real remediation, not a restatement of the
   problem?

## Sinks, sources and sanitizers

Pattern rules are the shallow end. To teach the taint engine about your own
code, extend `guardmarly.json` instead — see
[Configuration](configuration.md#supported-keys):

```json
{
  "sinks": [
    { "rule_id": "CUSTOM-001", "cwe": "CWE-89", "title": "Raw SQL via query builder",
      "function": "query_builder.raw", "severity": "high", "tainted_args": [0] }
  ],
  "sources": [{ "function": "my_request_wrapper", "category": "user_input" }],
  "custom_sanitizers": { "sanitize_sql": ["CWE-89"] }
}
```

Prefer `custom_sanitizers` over tightening regexes: a sanitizer records *why*
code is safe, while a pattern exception just hides the symptom.

## Sharing a rule

1. Add the YAML to `community_rules/` with the `community/` id prefix.
2. Include vulnerable and secure fixtures.
3. Run `pytest tests/test_community_rules.py -q` and `guardmarly --dse-validate`.
4. Open a PR describing the pattern, its CWE and the false-positive risk.
