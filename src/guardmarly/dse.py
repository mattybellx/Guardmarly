"""
guardmarly.dse
─────────────────
Deterministic Sandbox Engine (DSE) — guards against catastrophic regex
backtracking (ReDoS) and performance degradation from community-contributed
rules.

Architecture (per Section 3.2 of the blueprint):

1. **ReDoS Circuit Breaker**: Every custom regex pattern is executed inside a
   thread-isolated wrapper with a hard timeout. Patterns exceeding the budget
   are blacklisted and skipped.

2. **Golden Corpus Pipeline**: Each rule can declare paired test files
   (vulnerable.test + secure.test). On every commit, the engine verifies:
   - Rule MUST trigger on vulnerable.test (prevent False Negative regression)
   - Rule MUST NOT trigger on secure.test (prevent False Positive regression)

3. **Performance Regression Guard**: Tracks per-rule evaluation time and raises
   a warning if any rule exceeds the performance budget.

Zero external dependencies — pure stdlib.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

_log = logging.getLogger(__name__)

# ── Configuration ────────────────────────────────────────────────────────────

DEFAULT_REGEX_TIMEOUT_SECONDS: float = 0.01   # 10 ms per pattern
DEFAULT_RULE_TIMEOUT_SECONDS: float = 5.0      # 5 s per rule total
MAX_BLACKLISTED_PATTERNS: int = 500
GOLDEN_CORPUS_DIR: str = ".guardmarly/golden_corpus"


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class RegexEvalResult:
    """Result of a single regex evaluation with circuit breaker."""
    pattern: str
    matched: bool
    elapsed_ms: float
    timed_out: bool = False
    error: str = ""


@dataclass
class GoldenCorpusResult:
    """Result of running a rule against its golden corpus pair."""
    rule_id: str
    vulnerable_file: str
    secure_file: str
    vulnerable_triggered: bool        # MUST be True
    secure_clean: bool                # MUST be True (no findings on secure file)
    passed: bool
    fp_regression: bool = False       # True = rule fired on secure file (bad)
    fn_regression: bool = False       # True = rule missed vulnerable file (bad)
    details: str = ""


@dataclass
class DSEValidationReport:
    """Full validation report from a DSE run."""
    total_patterns: int = 0
    passed_patterns: int = 0
    timed_out_patterns: int = 0
    blacklisted_patterns: int = 0
    golden_corpus_results: list[GoldenCorpusResult] = field(default_factory=list)
    golden_passed: int = 0
    golden_failed: int = 0
    total_elapsed_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return (self.timed_out_patterns == 0
                and self.blacklisted_patterns == 0
                and self.golden_failed == 0
                and len(self.errors) == 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total_patterns": self.total_patterns,
            "passed_patterns": self.passed_patterns,
            "timed_out_patterns": self.timed_out_patterns,
            "blacklisted_patterns": self.blacklisted_patterns,
            "golden_corpus_passed": self.golden_passed,
            "golden_corpus_failed": self.golden_failed,
            "total_elapsed_ms": round(self.total_elapsed_ms, 3),
            "all_passed": self.all_passed,
            "errors": self.errors,
        }


# ── ReDoS Circuit Breaker ────────────────────────────────────────────────────


class ReDoSCircuitBreaker:
    """Thread-isolated regex evaluator with hard timeout.

    Prevents catastrophic backtracking from malicious or poorly-optimized
    community-contributed regex patterns.

    Usage::

        breaker = ReDoSCircuitBreaker(timeout_seconds=0.01)
        result = breaker.evaluate(r"(a+)+b", "aaaaaaaaaaaaaaaaaaaaaaaac")
        if result.timed_out:
            print("Pattern blacklisted — potential ReDoS")
    """

    def __init__(self, timeout_seconds: float = DEFAULT_REGEX_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout_seconds
        self._blacklist: set[str] = set()

    @property
    def blacklist(self) -> frozenset[str]:
        return frozenset(self._blacklist)

    def is_blacklisted(self, pattern: str) -> bool:
        return pattern in self._blacklist

    def blacklist_pattern(self, pattern: str) -> None:
        if len(self._blacklist) < MAX_BLACKLISTED_PATTERNS:
            self._blacklist.add(pattern)
            # Allowed: len() returns int — no CRLF injection possible
            _log.log(logging.WARNING, "Blacklisted ReDoS pattern (len=%d)", len(pattern))

    def evaluate(self, pattern: str, text: str) -> RegexEvalResult:
        """Evaluate a regex pattern against text with timeout protection.

        If the pattern is blacklisted, returns immediately with matched=False.
        If the evaluation exceeds the timeout, the pattern is blacklisted.
        """
        if pattern in self._blacklist:
            return RegexEvalResult(
                pattern=pattern, matched=False, elapsed_ms=0.0,
                timed_out=False, error="blacklisted",
            )

        result_container: list[RegexEvalResult] = []

        def _worker() -> None:
            try:
                start = time.perf_counter()
                compiled = re.compile(pattern)
                matched = bool(compiled.search(text))
                elapsed = (time.perf_counter() - start) * 1000.0
                result_container.append(RegexEvalResult(
                    pattern=pattern, matched=matched, elapsed_ms=elapsed,
                ))
            except re.error as exc:
                result_container.append(RegexEvalResult(
                    pattern=pattern, matched=False, elapsed_ms=0.0,
                    error=str(exc),
                ))
            except Exception:
                _log.debug("Unexpected error evaluating pattern", exc_info=True)
                result_container.append(RegexEvalResult(
                    pattern=pattern, matched=False, elapsed_ms=0.0,
                    error="Unexpected evaluation error (see debug log)",
                ))

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout)

        if thread.is_alive():
            # Pattern is malicious or catastrophically slow — blacklist it
            self.blacklist_pattern(pattern)
            return RegexEvalResult(
                pattern=pattern, matched=False, elapsed_ms=self._timeout * 1000,
                timed_out=True, error="timeout — pattern blacklisted (potential ReDoS)",
            )

        if result_container:
            return result_container[0]

        return RegexEvalResult(
            pattern=pattern, matched=False, elapsed_ms=0.0,
            error="no result produced",
        )


# ── Golden Corpus Pipeline ───────────────────────────────────────────────────


class GoldenCorpusValidator:
    """Validates rules against paired vulnerable/secure test files.

    Directory layout::

        .guardmarly/golden_corpus/
        └── <rule-id>/
            ├── vulnerable.<ext>.test    # MUST trigger the rule
            └── secure.<ext>.test        # MUST NOT trigger the rule

    On every validation run:
      - If a rule triggers on secure.test → FP Regression → REJECT
      - If a rule fails on vulnerable.test → FN Regression → REJECT
    """

    def __init__(self, corpus_root: str | Path | None = None) -> None:
        self._corpus_root = Path(corpus_root or GOLDEN_CORPUS_DIR)

    @property
    def corpus_root(self) -> Path:
        return self._corpus_root

    def list_rule_dirs(self) -> list[Path]:
        """Return all rule directories in the golden corpus."""
        if not self._corpus_root.exists():
            return []
        return sorted(
            p for p in self._corpus_root.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )

    def get_rule_files(self, rule_id: str) -> tuple[Path | None, Path | None]:
        """Return (vulnerable_file, secure_file) for a rule, or (None, None)."""
        rule_dir = self._corpus_root / rule_id
        if not rule_dir.is_dir():
            return None, None

        vulnerable: Path | None = None
        secure: Path | None = None
        for f in rule_dir.iterdir():
            if f.is_file():
                if "vulnerable" in f.name.lower():
                    vulnerable = f
                elif "secure" in f.name.lower():
                    secure = f
        return vulnerable, secure

    def validate_rule(
        self,
        rule_id: str,
        evaluate_fn: Callable[[str], list[Any]],
    ) -> GoldenCorpusResult:
        """Validate a single rule against its golden corpus.

        Args:
            rule_id: The rule identifier.
            evaluate_fn: Callable that takes source text and returns findings.
                         An empty list means no findings (clean).

        Returns:
            GoldenCorpusResult with pass/fail and regression details.
        """
        vulnerable_file, secure_file = self.get_rule_files(rule_id)

        if vulnerable_file is None or secure_file is None:
            return GoldenCorpusResult(
                rule_id=rule_id,
                vulnerable_file=str(vulnerable_file or "MISSING"),
                secure_file=str(secure_file or "MISSING"),
                vulnerable_triggered=False,
                secure_clean=False,
                passed=False,
                details="Golden corpus files missing — add vulnerable.*.test and secure.*.test",
            )

        try:
            vuln_content = vulnerable_file.read_text(encoding="utf-8", errors="replace")
            secure_content = secure_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return GoldenCorpusResult(
                rule_id=rule_id,
                vulnerable_file=str(vulnerable_file),
                secure_file=str(secure_file),
                vulnerable_triggered=False,
                secure_clean=False,
                passed=False,
                details=f"File read error: {exc}",
            )

        vuln_findings = evaluate_fn(vuln_content)
        secure_findings = evaluate_fn(secure_content)

        vulnerable_triggered = len(vuln_findings) > 0
        secure_clean = len(secure_findings) == 0
        fp_regression = not secure_clean
        fn_regression = not vulnerable_triggered

        passed = vulnerable_triggered and secure_clean

        details_parts: list[str] = []
        if not vulnerable_triggered:
            details_parts.append("FN REGRESSION: rule did NOT trigger on vulnerable file")
        if not secure_clean:
            details_parts.append(f"FP REGRESSION: rule triggered {len(secure_findings)} finding(s) on secure file")

        return GoldenCorpusResult(
            rule_id=rule_id,
            vulnerable_file=str(vulnerable_file),
            secure_file=str(secure_file),
            vulnerable_triggered=vulnerable_triggered,
            secure_clean=secure_clean,
            passed=passed,
            fp_regression=fp_regression,
            fn_regression=fn_regression,
            details="; ".join(details_parts) if details_parts else "OK",
        )

    def validate_all(
        self,
        rule_evaluators: dict[str, Callable[[str], list[Any]]],
    ) -> DSEValidationReport:
        """Run golden corpus validation for all registered rules.

        Args:
            rule_evaluators: Dict mapping rule_id → evaluate_fn(source) → findings.

        Returns:
            DSEValidationReport with aggregated results.
        """
        report = DSEValidationReport()
        total_start = time.perf_counter()

        for rule_id, evaluate_fn in rule_evaluators.items():
            result = self.validate_rule(rule_id, evaluate_fn)
            report.golden_corpus_results.append(result)
            if result.passed:
                report.golden_passed += 1
            else:
                report.golden_failed += 1
                report.errors.append(f"{rule_id}: {result.details}")

        report.total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0
        return report


# ── Performance Regression Guard ─────────────────────────────────────────────


@dataclass
class RulePerfRecord:
    """Tracks evaluation time for a single rule over multiple runs."""
    rule_id: str
    total_calls: int = 0
    total_elapsed_ms: float = 0.0
    max_elapsed_ms: float = 0.0
    budget_exceeded_count: int = 0

    @property
    def avg_elapsed_ms(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_elapsed_ms / self.total_calls

    def record(self, elapsed_ms: float, budget_ms: float = 100.0) -> None:
        self.total_calls += 1
        self.total_elapsed_ms += elapsed_ms
        if elapsed_ms > self.max_elapsed_ms:
            self.max_elapsed_ms = elapsed_ms
        if elapsed_ms > budget_ms:
            self.budget_exceeded_count += 1


class PerfRegressionGuard:
    """Tracks per-rule evaluation time and flags performance regressions."""

    def __init__(self, warning_budget_ms: float = 100.0) -> None:
        self._records: dict[str, RulePerfRecord] = {}
        self._warning_budget_ms = warning_budget_ms

    def record(self, rule_id: str, elapsed_ms: float) -> None:
        if rule_id not in self._records:
            self._records[rule_id] = RulePerfRecord(rule_id=rule_id)
        self._records[rule_id].record(elapsed_ms, self._warning_budget_ms)

    def get_slow_rules(self, threshold_ms: float = 50.0) -> list[RulePerfRecord]:
        """Return rules whose average evaluation time exceeds threshold."""
        return sorted(
            (r for r in self._records.values()
             if r.avg_elapsed_ms > threshold_ms),
            key=lambda r: r.avg_elapsed_ms,
            reverse=True,
        )

    def get_budget_violations(self) -> list[RulePerfRecord]:
        """Return rules that have exceeded the per-call budget at least once."""
        return sorted(
            (r for r in self._records.values() if r.budget_exceeded_count > 0),
            key=lambda r: r.budget_exceeded_count,
            reverse=True,
        )

    def report(self) -> dict[str, Any]:
        return {
            "total_rules_tracked": len(self._records),
            "slow_rules": [
                {"rule_id": r.rule_id, "avg_ms": round(r.avg_elapsed_ms, 3),
                 "max_ms": round(r.max_elapsed_ms, 3), "calls": r.total_calls}
                for r in self.get_slow_rules()
            ],
            "budget_violations": [
                {"rule_id": r.rule_id, "violations": r.budget_exceeded_count,
                 "max_ms": round(r.max_elapsed_ms, 3)}
                for r in self.get_budget_violations()
            ],
        }


# ── Convenience: full DSE pipeline ───────────────────────────────────────────


def run_dse_pipeline(
    patterns: list[str],
    test_text: str,
    rule_evaluators: dict[str, Callable[[str], list[Any]]] | None = None,
    corpus_root: str | Path | None = None,
    regex_timeout: float = DEFAULT_REGEX_TIMEOUT_SECONDS,
) -> DSEValidationReport:
    """Run the full DSE pipeline: circuit breaker + golden corpus.

    Args:
        patterns: List of regex pattern strings to validate.
        test_text: Sample text to test patterns against (for timeout detection).
        rule_evaluators: Optional dict of rule_id → evaluate_fn for golden corpus.
        corpus_root: Path to golden corpus directory.
        regex_timeout: Per-pattern timeout in seconds.

    Returns:
        DSEValidationReport with aggregated results.
    """
    breaker = ReDoSCircuitBreaker(timeout_seconds=regex_timeout)
    report = DSEValidationReport()
    total_start = time.perf_counter()

    # Phase 1: Circuit breaker on all patterns
    for pattern in patterns:
        report.total_patterns += 1
        result = breaker.evaluate(pattern, test_text)
        if result.timed_out:
            report.timed_out_patterns += 1
            report.errors.append(f"Timeout: {pattern[:100]}")
        elif result.error:
            report.errors.append(f"Error ({pattern[:80]}): {result.error}")
        else:
            report.passed_patterns += 1

    report.blacklisted_patterns = len(breaker.blacklist)

    # Phase 2: Golden corpus validation
    if rule_evaluators:
        validator = GoldenCorpusValidator(corpus_root)
        golden_report = validator.validate_all(rule_evaluators)
        report.golden_corpus_results = golden_report.golden_corpus_results
        report.golden_passed = golden_report.golden_passed
        report.golden_failed = golden_report.golden_failed
        report.errors.extend(golden_report.errors)

    report.total_elapsed_ms = (time.perf_counter() - total_start) * 1000.0
    return report
