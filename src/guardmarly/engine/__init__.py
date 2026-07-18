"""Shared engine helpers for guardmarly.

Public API:
  - shadow_scan: parallel pattern-only scan for failure attribution
  - dump_failures: per-FN/FP diagnostics with taint-flow breakpoint tracing
  - symbolic_guards: path-sensitive guard detection and finding adjustment
  - triage: context-aware confidence scoring and suppression
  - explain: zero-dependency CWE educational explanations
"""

from guardmarly.engine.shadow_scan import (  # noqa: F401
    ShadowMatch,
    ShadowScanReport,
    DiffEntry,
    run_shadow_scan,
    diff_scans,
    generate_shadow_report,
    shadow_report_to_dict,
)

from guardmarly.engine.dump_failures import (  # noqa: F401
    FailureAttribution,
    FailureDiagnosticReport,
    attribute_false_negative,
    attribute_false_positive,
    run_failure_diagnostics,
    diagnostic_report_to_dict,
    dump_failures_json,
)