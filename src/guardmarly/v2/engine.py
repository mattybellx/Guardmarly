"""
guardmarly.v2.engine
────────────────────────
Single-pass rule engine (Phase 2 §2.4).

One pass over every node in the SemanticModel.  No rule touches
the AST outside of dispatch().  The SemanticModel is the only shared
state passed to rules.

Structured logging emits DEBUG events for every file parsed, every
finding emitted, and every suppression applied (§Observability).
"""
from __future__ import annotations

import gc
import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator

from guardmarly.v2.model import SemanticModel
from guardmarly.v2.rule_protocol import Finding, REGISTRY, RuleRegistry

# Import all rule packages to trigger @REGISTRY.register decorators.
# Each package's __init__.py imports the individual rule modules.
import guardmarly.v2.rules.python  # noqa: F401, E402
import guardmarly.v2.rules.javascript  # noqa: F401, E402
import guardmarly.v2.rules.shared  # noqa: F401, E402
from guardmarly.v2.normalizer import normalize_file, normalize_source

_log = logging.getLogger(__name__)

# Hard-coded exclusion list — not user-overridable downward (Phase 6 §6.3).
# Users may extend via guardmarly.json exclude_paths; they cannot remove from this set.
ALWAYS_EXCLUDE: frozenset[str] = frozenset({
    "node_modules", ".venv", "venv", "env",
    "dist", "build", "__pycache__", ".git",
    ".tox", "site-packages", "vendor",
    ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "eggs", ".eggs", "*.egg-info",
})


def _should_exclude(path: Path, extra_excludes: frozenset[str] = frozenset()) -> bool:
    """Return True when *path* should be skipped (spec §6.3)."""
    all_excludes = ALWAYS_EXCLUDE | extra_excludes
    return any(part in all_excludes for part in path.parts)


def _parse_single_file(file_path: str) -> SemanticModel:
    """Worker function used by ProcessPoolExecutor — must be picklable."""
    model = normalize_file(file_path)
    _log.debug("parsed file=%s language=%s nodes=%d",
               file_path, model.language, sum(len(v) for v in model.nodes_by_type.values()))
    return model


class Engine:
    """
    v2 Engine — orchestrates Parse → Normalize → Evaluate.

    Usage::

        engine = Engine()
        findings = engine.scan_file("app.py")
        all_findings = engine.scan_directory("src/")
    """

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        max_workers: int | None = None,
        extra_excludes: frozenset[str] = frozenset(),
    ) -> None:
        self.registry = registry or REGISTRY
        # Default: min(4, cpu_count) per spec §5.2 for CI-runner safety
        self.max_workers = max_workers or min(4, os.cpu_count() or 1)
        self.extra_excludes = extra_excludes

    # ── Single-file scan ───────────────────────────────────────────────────────

    def scan_source(
        self,
        source: str,
        file_path: str,
        language: str,
    ) -> list[Finding]:
        """Scan a source string directly (useful for stdin and test fixtures)."""
        model = normalize_source(source, file_path, language)
        return self._evaluate(model)

    def scan_file(self, file_path: str) -> list[Finding]:
        """Parse and evaluate a single file.  Returns findings, empty on error."""
        model = normalize_file(file_path)
        if model.parse_error:
            _log.warning("parse_error file=%s error=%s", file_path, model.parse_error)
        return self._evaluate(model)

    def scan_model(self, model: SemanticModel) -> list[Finding]:
        """Run the rule engine over a pre-built SemanticModel."""
        return self._evaluate(model)

    # ── Multi-file scan ────────────────────────────────────────────────────────

    def scan_files(self, file_paths: list[str]) -> dict[str, list[Finding]]:
        """
        Scan multiple files in parallel using ProcessPoolExecutor (spec §5.2).

        Parsing is embarrassingly parallel (each file independent).
        Rule evaluation happens in the main process after parsing completes.
        """
        if not file_paths:
            return {}

        # For small repos, process-pool overhead > parse time; fall through
        # to sequential for <= 8 files.
        if len(file_paths) <= 8:
            return {fp: self.scan_file(fp) for fp in file_paths}

        models = self._parse_parallel(file_paths)
        results: dict[str, list[Finding]] = {}
        for model in models:
            results[model.file_path] = self._evaluate(model)
        return results

    def scan_directory(
        self,
        directory: str | Path,
        extra_excludes: frozenset[str] | None = None,
    ) -> dict[str, list[Finding]]:
        """
        Recursively scan all supported files under *directory*.

        Returns ``{file_path: [Finding, ...]}`` for every file processed.
        """
        excludes = self.extra_excludes | (extra_excludes or frozenset())
        base = Path(directory)
        exts = frozenset({".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
        file_paths = [
            str(p)
            for p in sorted(base.rglob("*"))
            if p.is_file()
            and p.suffix.lower() in exts
            and not _should_exclude(p, excludes)
        ]
        _log.debug("scan_directory dir=%s files=%d", directory, len(file_paths))
        return self.scan_files(file_paths)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _evaluate(self, model: SemanticModel) -> list[Finding]:
        """
        Single-pass evaluation — the core of the v2 engine.

        For every node type in the model, every subscribed rule is called
        exactly once per node.  No rule touches the AST outside of dispatch.
        """
        if model.parse_error and not model.nodes_by_type:
            return []

        findings: list[Finding] = []

        for node_type, nodes in model.nodes_by_type.items():
            for node in nodes:
                # Skip lines marked with inline suppressions
                if node.location.line and model.is_line_suppressed(
                    node.location.line, ""
                ):
                    _log.debug(
                        "suppressed file=%s line=%d node_type=%s",
                        model.file_path, node.location.line, node_type,
                    )
                    continue

                for finding in self.registry.dispatch(node, model):
                    # Check rule-specific suppression
                    if model.is_line_suppressed(node.location.line or 0, finding.rule_id):
                        _log.debug(
                            "suppressed rule=%s file=%s line=%d",
                            finding.rule_id, model.file_path, node.location.line,
                        )
                        finding = Finding(
                            **{**finding.__dict__, "suppressed": True}
                        )

                    if not finding.suppressed:
                        _log.debug(
                            "finding rule=%s file=%s line=%d confidence=%s",
                            finding.rule_id, model.file_path,
                            finding.location.line, finding.confidence,
                        )
                        findings.append(finding)

        return findings

    def _parse_parallel(self, file_paths: list[str]) -> list[SemanticModel]:
        """Parse files in parallel worker processes (spec §5.2)."""
        models: list[SemanticModel] = []
        with ProcessPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(_parse_single_file, fp): fp for fp in file_paths}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    model = future.result()
                    models.append(model)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("parse_failed file=%s error=%s", path, exc)
                    # One bad file must not abort the scan (spec §5.2)

        # Explicitly yield control to GC — keeps peak memory proportional to
        # the largest single file, not the entire codebase (spec §5.1)
        gc.collect()
        return models

    # ── Streaming helper ───────────────────────────────────────────────────────

    def scan_files_streaming(
        self,
        file_paths: list[str],
    ) -> Iterator[tuple[str, list[Finding]]]:
        """
        Generator that yields (file_path, findings) one file at a time.

        Uses explicit GC after each parse to keep peak memory O(largest_file)
        rather than O(codebase) (spec §5.1).
        """
        for path in file_paths:
            model = normalize_file(path)
            findings = self._evaluate(model)
            del model
            gc.collect()
            yield path, findings
