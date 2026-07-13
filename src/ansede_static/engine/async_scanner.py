"""
Asynchronous Parallel Execution Engine
───────────────────────────────────────
Refactors scan execution to use asyncio for parallel I/O and multi-processing
for AST parsing. Maintains <10s per 100k LOC even with 10x rule expansion.

Architecture:
  - Worker pool for file parsing (CPU-bound)
  - Async I/O for disk reads (I/O-bound)
  - Bounded semaphore to control concurrency
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import multiprocessing
from pathlib import Path
from typing import Callable

from ansede_static._types import AnalysisResult, Finding

_log = logging.getLogger(__name__)

# Default concurrency: use all cores but leave 1 free
_DEFAULT_MAX_WORKERS = max(1, (multiprocessing.cpu_count() or 4) - 1)
_DEFAULT_IO_SEMAPHORE = _DEFAULT_MAX_WORKERS * 2


async def _scan_file_async(
    file_path: Path,
    scan_fn: Callable[[Path], AnalysisResult],
    executor: concurrent.futures.ProcessPoolExecutor,
) -> tuple[Path, AnalysisResult | None, str | None]:
    """Scan a single file in a process pool worker."""
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(executor, scan_fn, file_path)
        return file_path, result, None
    except Exception as exc:
        return file_path, None, str(exc)


async def scan_directory_parallel(
    root: Path,
    *,
    scan_fn: Callable[[Path], AnalysisResult],
    file_filter: Callable[[Path], bool] | None = None,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    io_semaphore: int | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[Path, AnalysisResult]:
    """
    Scan all matching files in a directory tree in parallel.

    Args:
        root: Root directory to scan
        scan_fn: Function that takes a Path and returns AnalysisResult
        file_filter: Optional predicate to filter files
        max_workers: Number of process pool workers
        io_semaphore: Max concurrent I/O operations
        progress_callback: Called with (completed, total) on each file

    Returns:
        Dict mapping file paths to their AnalysisResults
    """
    sem = asyncio.Semaphore(io_semaphore or _DEFAULT_IO_SEMAPHORE)

    # Collect files
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and (file_filter is None or file_filter(path)):
            files.append(path)

    if not files:
        return {}

    total = len(files)
    completed = 0
    results: dict[Path, AnalysisResult] = {}
    errors: list[str] = []

    async def scan_with_semaphore(fp: Path, executor: concurrent.futures.ProcessPoolExecutor) -> None:
        nonlocal completed
        async with sem:
            _, result, error = await _scan_file_async(fp, scan_fn, executor)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            if result is not None:
                results[fp] = result
            elif error:
                errors.append(f"{fp}: {error}")

    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
        tasks = [scan_with_semaphore(f, executor) for f in files]
        await asyncio.gather(*tasks, return_exceptions=True)

    if errors:
        _log.warning("Parallel scan: %d/%d files failed", len(errors), total)
        for err in errors[:10]:
            _log.debug("  %s", err)

    return results


def scan_directory_sync(
    root: Path,
    *,
    scan_fn: Callable[[Path], AnalysisResult],
    file_filter: Callable[[Path], bool] | None = None,
    max_workers: int = _DEFAULT_MAX_WORKERS,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[Path, AnalysisResult]:
    """Synchronous wrapper around scan_directory_parallel."""
    return asyncio.run(scan_directory_parallel(
        root,
        scan_fn=scan_fn,
        file_filter=file_filter,
        max_workers=max_workers,
        progress_callback=progress_callback,
    ))


async def scan_files_parallel(
    files: list[Path],
    *,
    scan_fn: Callable[[Path], AnalysisResult],
    max_workers: int = _DEFAULT_MAX_WORKERS,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[Path, AnalysisResult]:
    """Scan an explicit file list in parallel using asyncio + threads.

    Unlike process-pool variants, this accepts non-picklable callables/closures,
    which makes it safe for CLI orchestration that carries runtime state.
    """
    if not files:
        return {}

    sem = asyncio.Semaphore(max(1, max_workers))
    total = len(files)
    completed = 0
    results: dict[Path, AnalysisResult] = {}
    errors: list[str] = []

    async def scan_one(fp: Path) -> None:
        nonlocal completed
        async with sem:
            try:
                result = await asyncio.to_thread(scan_fn, fp)
            except Exception as exc:  # noqa: BLE001
                result = None
                errors.append(f"{fp}: {exc}")

            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            if result is not None:
                results[fp] = result

    await asyncio.gather(*(scan_one(path) for path in files), return_exceptions=True)

    if errors:
        _log.warning("Parallel file scan: %d/%d files failed", len(errors), total)
        for err in errors[:10]:
            _log.debug("  %s", err)

    return results


def scan_files_sync(
    files: list[Path],
    *,
    scan_fn: Callable[[Path], AnalysisResult],
    max_workers: int = _DEFAULT_MAX_WORKERS,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[Path, AnalysisResult]:
    """Synchronous wrapper around scan_files_parallel."""
    return asyncio.run(
        scan_files_parallel(
            files,
            scan_fn=scan_fn,
            max_workers=max_workers,
            progress_callback=progress_callback,
        )
    )


def aggregate_findings(
    results: dict[Path, AnalysisResult],
    *,
    severity_min: str = "low",
) -> list[Finding]:
    """Flatten all findings from parallel scan results, optionally filtered."""
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    threshold = sev_order.get(severity_min.lower(), 1)

    all_findings: list[Finding] = []
    for path, result in results.items():
        for f in result.findings:
            sev_val = sev_order.get(str(f.severity).lower() if hasattr(f.severity, 'value') else str(f.severity).lower(), 1)
            if sev_val >= threshold:
                all_findings.append(f)

    return sorted(all_findings, key=lambda f: (
        sev_order.get(str(f.severity).lower() if hasattr(f.severity, 'value') else str(f.severity).lower(), 1),
        f.line or 0,
    ), reverse=True)
