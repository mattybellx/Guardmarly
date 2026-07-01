"""Interprocedural fixpoint computation over GlobalGraph FunctionSummary.

After all files are scanned, propagates taint summaries across call edges
until a fixed point is reached. This enables cross-file taint detection.

Algorithm:
  1. Collect all FunctionSummary entries from GlobalGraph
  2. Build caller→callee dependency graph
  3. Iterate: if callee's arg N reaches a sink, and caller passes tainted
     data as arg N, then caller's corresponding param reaches a sink too
  4. Update caller summaries, repeat until stable
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

_log = logging.getLogger(__name__)


def run_interprocedural_fixpoint(global_graph: object) -> dict[str, Any]:
    """Run IFDS-style fixpoint over GlobalGraph summaries.

    Args:
        global_graph: GlobalGraph instance with recorded FunctionSummary entries

    Returns:
        Stats dict: {iterations, edges_processed, summaries_updated}
    """
    stats: dict[str, Any] = {
        "iterations": 0,
        "edges_processed": 0,
        "summaries_updated": 0,
    }

    # Collect all known summaries
    summaries_by_key: dict[tuple[str, str], Any] = {}
    for (file_path, func_name), summary in getattr(global_graph, "function_summaries", {}).items():
        summaries_by_key[(file_path, func_name)] = summary

    # Build reverse index: callee_name → list of (caller_file, caller_name)
    callee_to_callers: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for (caller_file, caller_name), summary in summaries_by_key.items():
        for callee_name in getattr(summary, "depends_on", ()):
            callee_to_callers[callee_name].append((caller_file, caller_name))

    _log.debug("Fixpoint: %d summaries, %d callee-to-caller edges",
               len(summaries_by_key), sum(len(v) for v in callee_to_callers.values()))

    changed = True
    max_iter = 20
    while changed and max_iter > 0:
        max_iter -= 1
        changed = False
        stats["iterations"] += 1

        for callee_name, callers in callee_to_callers.items():
            callee_simple = callee_name.split("::")[-1].split(".")[-1]
            callee_keys = [(f, n) for (f, n) in summaries_by_key if n == callee_simple or n == callee_name or n.endswith("." + callee_simple)]
            if not callee_keys:
                continue
            callee_file, callee_name_full = callee_keys[0]
            callee_summary = summaries_by_key.get((callee_file, callee_name_full))
            if callee_summary is None:
                continue
            if not callee_summary.args_to_sink and not callee_summary.return_from_source:
                continue

            for caller_file, caller_name in callers:
                stats["edges_processed"] += 1
                caller_summary = summaries_by_key.get((caller_file, caller_name))
                if caller_summary is None:
                    continue

                new_sink_args = set(caller_summary.args_to_sink)
                new_return_args = set(caller_summary.args_to_return)

                for sink_idx in callee_summary.args_to_sink:
                    new_sink_args.add(sink_idx)
                    new_return_args.add(sink_idx)

                if callee_summary.return_from_source:
                    new_return_args.update(callee_summary.args_to_return)

                if new_sink_args != set(caller_summary.args_to_sink) or \
                   new_return_args != set(caller_summary.args_to_return):
                    from ansede_static.ir.global_graph import FunctionSummary
                    updated = FunctionSummary(
                        file_path=caller_file,
                        function_name=caller_name,
                        args_to_sink=tuple(sorted(new_sink_args)),
                        args_to_return=tuple(sorted(new_return_args)),
                        return_from_source=caller_summary.return_from_source or callee_summary.return_from_source,
                        side_effect_symbols=caller_summary.side_effect_symbols,
                        depends_on=caller_summary.depends_on,
                    )
                    global_graph.record_function_summary(updated)
                    summaries_by_key[(caller_file, caller_name)] = updated
                    stats["summaries_updated"] += 1
                    changed = True

    global_graph.save_summaries()
    _log.debug("Fixpoint complete: %s", stats)
    return stats
