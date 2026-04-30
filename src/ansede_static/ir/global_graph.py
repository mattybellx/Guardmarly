from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ansede_static._types import TraceFrame
from ansede_static.cache.sqlite_store import SQLiteStore, stable_hash


@dataclass(frozen=True)
class NodeID:
    """A unique identifier for a symbol or AST node across the workspace."""

    file_path: str
    symbol_name: str


@dataclass
class TaintNode:
    """A node in the inter-procedural taint graph."""

    id: NodeID
    ast_type: str
    line_start: int
    is_source: bool = False
    is_sink: bool = False
    taint_source: Optional[str] = None
    taint_trace: Tuple[TraceFrame, ...] = field(default_factory=tuple)


@dataclass
class Edge:
    """A directional relationship between two nodes."""

    source: NodeID
    target: NodeID
    edge_type: str  # IMPORTS, CALLS, RETURNS, DATA_FLOW
    weight: int = 1
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FunctionSummary:
    """IFDS-compatible summary for a function.

    The summary captures distributive flow facts:
    - argument positions that can reach sinks
    - argument positions that can taint the return value
    - whether return can be tainted directly from an intrinsic source
    - side effects (symbol names) visible outside callee scope
    """

    file_path: str
    function_name: str
    args_to_sink: Tuple[int, ...] = ()
    args_to_return: Tuple[int, ...] = ()
    return_from_source: bool = False
    side_effect_symbols: Tuple[str, ...] = ()
    depends_on: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "function_name": self.function_name,
            "args_to_sink": list(self.args_to_sink),
            "args_to_return": list(self.args_to_return),
            "return_from_source": self.return_from_source,
            "side_effect_symbols": list(self.side_effect_symbols),
            "depends_on": list(self.depends_on),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FunctionSummary":
        return cls(
            file_path=str(data.get("file_path", "")),
            function_name=str(data.get("function_name", "")),
            args_to_sink=tuple(sorted(int(v) for v in data.get("args_to_sink", ()) if isinstance(v, int))),
            args_to_return=tuple(sorted(int(v) for v in data.get("args_to_return", ()) if isinstance(v, int))),
            return_from_source=bool(data.get("return_from_source", False)),
            side_effect_symbols=tuple(sorted(str(v) for v in data.get("side_effect_symbols", ()) if isinstance(v, str))),
            depends_on=tuple(sorted(str(v) for v in data.get("depends_on", ()) if isinstance(v, str))),
        )


@dataclass(frozen=True)
class IFDSTaintFact:
    """Context-sensitive IFDS taint fact.

    `call_string` stores the bounded call context (k-limited) and is used to
    keep return-flow propagation sound for nested helper chains.
    """

    function_file: str
    function_name: str
    value_label: str
    call_string: Tuple[str, ...] = ()

    def trim(self, k: int) -> "IFDSTaintFact":
        if k <= 0:
            return IFDSTaintFact(
                function_file=self.function_file,
                function_name=self.function_name,
                value_label=self.value_label,
                call_string=(),
            )
        if len(self.call_string) <= k:
            return self
        return IFDSTaintFact(
            function_file=self.function_file,
            function_name=self.function_name,
            value_label=self.value_label,
            call_string=self.call_string[-k:],
        )


class IDETaintLevel(IntEnum):
    """Finite-height taint lattice levels for IDE-style dataflow facts."""

    BOTTOM = 0
    CLEAN = 1
    TAINTED = 2
    TOP = 3


@dataclass(frozen=True)
class IDETaintFact:
    """IDE lattice fact tracked per (file, function, value, call-string)."""

    level: IDETaintLevel = IDETaintLevel.BOTTOM
    sources: Tuple[str, ...] = ()
    sanitizers: Tuple[str, ...] = ()
    call_string: Tuple[str, ...] = ()

    def trim(self, k: int) -> "IDETaintFact":
        if k <= 0:
            return IDETaintFact(
                level=self.level,
                sources=self.sources,
                sanitizers=self.sanitizers,
                call_string=(),
            )
        if len(self.call_string) <= k:
            return self
        return IDETaintFact(
            level=self.level,
            sources=self.sources,
            sanitizers=self.sanitizers,
            call_string=self.call_string[-k:],
        )

    def join(self, other: "IDETaintFact") -> "IDETaintFact":
        if self.level == IDETaintLevel.BOTTOM:
            return other
        if other.level == IDETaintLevel.BOTTOM:
            return self
        level = IDETaintLevel(max(int(self.level), int(other.level)))
        sources = tuple(sorted(set(self.sources) | set(other.sources)))
        sanitizers = tuple(sorted(set(self.sanitizers) | set(other.sanitizers)))
        call_string = self.call_string if len(self.call_string) >= len(other.call_string) else other.call_string
        return IDETaintFact(level=level, sources=sources, sanitizers=sanitizers, call_string=call_string)

    def meet(self, other: "IDETaintFact") -> "IDETaintFact":
        if self.level == IDETaintLevel.TOP:
            return other
        if other.level == IDETaintLevel.TOP:
            return self
        level = IDETaintLevel(min(int(self.level), int(other.level)))
        source_intersection = set(self.sources) & set(other.sources)
        sanitizer_intersection = set(self.sanitizers) & set(other.sanitizers)
        if not source_intersection and level > IDETaintLevel.CLEAN:
            level = IDETaintLevel.CLEAN
        return IDETaintFact(
            level=level,
            sources=tuple(sorted(source_intersection)),
            sanitizers=tuple(sorted(sanitizer_intersection)),
            call_string=self.call_string if self.call_string == other.call_string else (),
        )


class GlobalGraph:
    """Workspace-global graph plus IFDS summary state.

    Compatibility: keeps legacy APIs (`add_node`, `add_edge`,
    `resolve_cross_file_taint`, `find_all_paths`) while adding formal summary
    persistence and propagation helpers for mathematically-sound incremental
    scanning.
    """

    _SUMMARY_BUCKET = "ifds_function_summaries_v1"
    _DEPENDENCY_BUCKET = "ifds_function_dependencies_v1"
    DEFAULT_CALL_STRING_K = 2

    def __init__(self, cache_path: str | Path | None = None):
        self.nodes: Dict[NodeID, TaintNode] = {}
        self.adjacency: Dict[NodeID, List[Edge]] = {}
        self.reverse_adjacency: Dict[NodeID, List[Edge]] = {}

        # (normalized file, symbol) -> [(normalized file, symbol)]
        self.imports: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
        # (normalized file, symbol) -> (source label, trace)
        self.module_taint: Dict[Tuple[str, str], Tuple[str, Tuple[TraceFrame, ...]]] = {}

        # (normalized file, function name) -> FunctionSummary
        self.function_summaries: Dict[Tuple[str, str], FunctionSummary] = {}
        # (callee file, callee function) -> set((caller file, caller function))
        self.reverse_summary_dependencies: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        # (normalized file, function, value_label, call_string) -> IDETaintFact
        self.ide_facts: Dict[Tuple[str, str, str, Tuple[str, ...]], IDETaintFact] = {}

        self._cache_path = Path(cache_path) if cache_path else Path(".ansede") / "cache.db"

    @staticmethod
    def _normalize_path(path: str) -> str:
        try:
            normalized = Path(path).resolve(strict=False).as_posix()
        except OSError:
            normalized = path.replace("\\", "/")
        return normalized.casefold()

    @classmethod
    def _paths_match(cls, left: str, right: str) -> bool:
        left_norm = cls._normalize_path(left)
        right_norm = cls._normalize_path(right)
        if left_norm == right_norm:
            return True
        if left_norm.endswith("/" + right_norm) or right_norm.endswith("/" + left_norm):
            return True
        return Path(left_norm).name == Path(right_norm).name

    def _summary_key(self, file_path: str, function_name: str) -> str:
        normalized = self._normalize_path(file_path)
        return stable_hash(f"{normalized}::{function_name}")

    def _summary_tuple_key(self, file_path: str, function_name: str) -> Tuple[str, str]:
        return (self._normalize_path(file_path), function_name)

    def _summary_label(self, file_path: str, function_name: str) -> str:
        normalized = self._normalize_path(file_path)
        return f"{normalized}::{function_name}"

    def _ide_fact_key(
        self,
        *,
        file_path: str,
        function_name: str,
        value_label: str,
        call_string: Tuple[str, ...],
    ) -> Tuple[str, str, str, Tuple[str, ...]]:
        return (self._normalize_path(file_path), function_name, value_label, call_string)

    def join_ide_facts(self, left: IDETaintFact, right: IDETaintFact) -> IDETaintFact:
        return left.join(right)

    def meet_ide_facts(self, left: IDETaintFact, right: IDETaintFact) -> IDETaintFact:
        return left.meet(right)

    def set_ide_fact(
        self,
        *,
        file_path: str,
        function_name: str,
        value_label: str,
        fact: IDETaintFact,
        join: bool = True,
        call_string_k: int = DEFAULT_CALL_STRING_K,
    ) -> IDETaintFact:
        trimmed = fact.trim(call_string_k)
        key = self._ide_fact_key(
            file_path=file_path,
            function_name=function_name,
            value_label=value_label,
            call_string=trimmed.call_string,
        )
        if join and key in self.ide_facts:
            merged = self.ide_facts[key].join(trimmed)
            self.ide_facts[key] = merged
            return merged
        self.ide_facts[key] = trimmed
        return trimmed

    def get_ide_fact(
        self,
        *,
        file_path: str,
        function_name: str,
        value_label: str,
        call_string: Tuple[str, ...] = (),
        call_string_k: int = DEFAULT_CALL_STRING_K,
    ) -> IDETaintFact:
        bounded = call_string[-call_string_k:] if call_string_k > 0 else ()
        key = self._ide_fact_key(
            file_path=file_path,
            function_name=function_name,
            value_label=value_label,
            call_string=bounded,
        )
        return self.ide_facts.get(key, IDETaintFact())

    def add_node(self, node: TaintNode) -> None:
        self.nodes[node.id] = node
        self.adjacency.setdefault(node.id, [])
        self.reverse_adjacency.setdefault(node.id, [])

        if node.taint_source:
            key = (self._normalize_path(node.id.file_path), node.id.symbol_name)
            self.module_taint[key] = (node.taint_source, node.taint_trace)

    def add_edge(self, edge: Edge) -> None:
        if edge.edge_type == "IMPORTS":
            src_key = (self._normalize_path(edge.source.file_path), edge.source.symbol_name)
            tgt_key = (self._normalize_path(edge.target.file_path), edge.target.symbol_name)
            self.imports.setdefault(src_key, []).append(tgt_key)

        if edge.source in self.nodes and edge.target in self.nodes:
            self.adjacency.setdefault(edge.source, []).append(edge)
            self.reverse_adjacency.setdefault(edge.target, []).append(edge)

    def record_function_summary(self, summary: FunctionSummary) -> None:
        key = self._summary_tuple_key(summary.file_path, summary.function_name)
        normalized_dependencies = tuple(
            sorted(
                dep
                for dep in summary.depends_on
                if isinstance(dep, str) and "::" in dep
            )
        )
        normalized_summary = FunctionSummary(
            file_path=self._normalize_path(summary.file_path),
            function_name=summary.function_name,
            args_to_sink=summary.args_to_sink,
            args_to_return=summary.args_to_return,
            return_from_source=summary.return_from_source,
            side_effect_symbols=summary.side_effect_symbols,
            depends_on=normalized_dependencies,
        )
        self.function_summaries[key] = normalized_summary
        self._rebuild_reverse_dependencies_for(key, normalized_summary)

    def record_call_dependency(
        self,
        *,
        caller_file: str,
        caller_name: str,
        callee_file: str,
        callee_name: str,
    ) -> None:
        caller_key = self._summary_tuple_key(caller_file, caller_name)
        callee_label = self._summary_label(callee_file, callee_name)
        existing = self.function_summaries.get(caller_key)
        if existing is None:
            existing = FunctionSummary(file_path=caller_key[0], function_name=caller_name)
        deps = set(existing.depends_on)
        if callee_label in deps:
            return
        deps.add(callee_label)
        updated = FunctionSummary(
            file_path=existing.file_path,
            function_name=existing.function_name,
            args_to_sink=existing.args_to_sink,
            args_to_return=existing.args_to_return,
            return_from_source=existing.return_from_source,
            side_effect_symbols=existing.side_effect_symbols,
            depends_on=tuple(sorted(deps)),
        )
        self.function_summaries[caller_key] = updated
        self._rebuild_reverse_dependencies_for(caller_key, updated)

    def _rebuild_reverse_dependencies_for(
        self,
        caller_key: Tuple[str, str],
        summary: FunctionSummary,
    ) -> None:
        for callee_key, callers in list(self.reverse_summary_dependencies.items()):
            if caller_key in callers:
                callers.discard(caller_key)
                if not callers:
                    self.reverse_summary_dependencies.pop(callee_key, None)

        for dependency in summary.depends_on:
            if "::" not in dependency:
                continue
            dep_file, dep_fn = dependency.rsplit("::", 1)
            dep_key = (dep_file, dep_fn)
            self.reverse_summary_dependencies.setdefault(dep_key, set()).add(caller_key)

    def get_function_summary(self, file_path: str, function_name: str) -> Optional[FunctionSummary]:
        key = (self._normalize_path(file_path), function_name)
        summary = self.function_summaries.get(key)
        if summary is not None:
            return summary

        # Fuzzy fallback for relative/absolute path mismatches
        normalized = self._normalize_path(file_path)
        for (fp, fn), candidate in self.function_summaries.items():
            if fn == function_name and self._paths_match(fp, normalized):
                return candidate
        return None

    def save_summaries(self) -> None:
        if not self.function_summaries and not self.reverse_summary_dependencies:
            return
        with SQLiteStore(self._cache_path) as store:
            for summary in self.function_summaries.values():
                cache_key = self._summary_key(summary.file_path, summary.function_name)
                store.set_json(self._SUMMARY_BUCKET, cache_key, summary.as_dict())
            for (dep_file, dep_fn), callers in self.reverse_summary_dependencies.items():
                dep_key = self._summary_key(dep_file, dep_fn)
                payload = {
                    "dependency": f"{dep_file}::{dep_fn}",
                    "callers": [f"{caller_file}::{caller_fn}" for caller_file, caller_fn in sorted(callers)],
                }
                store.set_json(self._DEPENDENCY_BUCKET, dep_key, payload)

    def load_summary(self, file_path: str, function_name: str) -> Optional[FunctionSummary]:
        cache_key = self._summary_key(file_path, function_name)
        with SQLiteStore(self._cache_path) as store:
            payload = store.get_json(self._SUMMARY_BUCKET, cache_key)
            dep_payload = store.get_json(self._DEPENDENCY_BUCKET, cache_key)
        if not isinstance(payload, dict):
            return None
        summary = FunctionSummary.from_dict(payload)
        self.record_function_summary(summary)
        if isinstance(dep_payload, dict):
            callers = dep_payload.get("callers", ())
            for item in callers:
                if not isinstance(item, str) or "::" not in item:
                    continue
                caller_file, caller_fn = item.rsplit("::", 1)
                self.reverse_summary_dependencies.setdefault(
                    self._summary_tuple_key(file_path, function_name),
                    set(),
                ).add((caller_file, caller_fn))
        return summary

    def invalidate_changed_files(self, changed_files: Set[str]) -> Set[Tuple[str, str]]:
        """Invalidate summaries impacted by changed files and dependent callers.

        Returns the set of invalidated (file, function) summary keys.
        """
        if not changed_files:
            return set()

        changed_norm = {self._normalize_path(path) for path in changed_files}
        to_invalidate: Set[Tuple[str, str]] = {
            key for key in self.function_summaries if key[0] in changed_norm
        }
        queue: List[Tuple[str, str]] = list(to_invalidate)
        visited: Set[Tuple[str, str]] = set()
        while queue:
            callee_key = queue.pop(0)
            if callee_key in visited:
                continue
            visited.add(callee_key)
            for caller_key in self.reverse_summary_dependencies.get(callee_key, set()):
                if caller_key not in to_invalidate:
                    to_invalidate.add(caller_key)
                    queue.append(caller_key)

        if not to_invalidate:
            return set()

        with SQLiteStore(self._cache_path) as store:
            for file_path, function_name in to_invalidate:
                self.function_summaries.pop((file_path, function_name), None)
                cache_key = self._summary_key(file_path, function_name)
                store.delete(self._SUMMARY_BUCKET, cache_key)
                store.delete(self._DEPENDENCY_BUCKET, cache_key)

        for callee_key in list(self.reverse_summary_dependencies.keys()):
            callers = self.reverse_summary_dependencies[callee_key]
            updated_callers = {caller for caller in callers if caller not in to_invalidate}
            if updated_callers:
                self.reverse_summary_dependencies[callee_key] = updated_callers
            else:
                self.reverse_summary_dependencies.pop(callee_key, None)
        return to_invalidate

    def propagate_call_facts(
        self,
        *,
        caller_file: str,
        caller_name: str = "<module>",
        callee_file: str,
        callee_name: str,
        tainted_arg_indexes: Set[int],
        call_line: Optional[int] = None,
        call_string: Tuple[str, ...] = (),
        call_string_k: int = DEFAULT_CALL_STRING_K,
    ) -> Tuple[bool, Tuple[TraceFrame, ...], bool, Tuple[TraceFrame, ...]]:
        """Apply IFDS summary transfer for one callsite.

        Returns:
            (sink_reachable, sink_trace, return_tainted, return_trace)
        """
        summary = self.get_function_summary(callee_file, callee_name)
        if summary is None:
            summary = self.load_summary(callee_file, callee_name)
        if summary is None:
            return False, (), False, ()

        self.record_call_dependency(
            caller_file=caller_file,
            caller_name=caller_name,
            callee_file=callee_file,
            callee_name=callee_name,
        )

        sink_hit = bool(set(summary.args_to_sink) & set(tainted_arg_indexes))
        ret_hit = summary.return_from_source or bool(set(summary.args_to_return) & set(tainted_arg_indexes))

        call_site_label = f"{self._normalize_path(caller_file)}::{caller_name}@{call_line or 0}->{callee_name}"
        bounded_call_string = tuple(call_string + (call_site_label,))
        if call_string_k >= 0:
            bounded_call_string = bounded_call_string[-call_string_k:] if call_string_k else ()
        context_label = " > ".join(bounded_call_string) if bounded_call_string else "<root>"

        sink_trace: Tuple[TraceFrame, ...] = ()
        return_trace: Tuple[TraceFrame, ...] = ()
        if sink_hit:
            sink_trace = (
                TraceFrame(kind="call", label=f"call `{callee_name}()` [ctx: {context_label}]", line=call_line),
                TraceFrame(kind="sink", label=f"summary sink in `{callee_name}()`", line=call_line),
            )
        if ret_hit:
            label = "summary return tainted from source" if summary.return_from_source else "summary return tainted from argument"
            return_trace = (
                TraceFrame(kind="call", label=f"call `{callee_name}()` [ctx: {context_label}]", line=call_line),
                TraceFrame(kind="return", label=label, line=call_line),
            )

        fact_level = IDETaintLevel.TAINTED if (sink_hit or ret_hit) else IDETaintLevel.CLEAN
        fact_sources: Tuple[str, ...] = ()
        if ret_hit and summary.return_from_source:
            fact_sources = ("intrinsic-source",)
        elif tainted_arg_indexes:
            fact_sources = tuple(sorted(f"arg[{idx}]" for idx in tainted_arg_indexes))
        propagated_fact = IDETaintFact(
            level=fact_level,
            sources=fact_sources,
            call_string=bounded_call_string,
        )
        self.set_ide_fact(
            file_path=callee_file,
            function_name=callee_name,
            value_label="$ret",
            fact=propagated_fact,
            join=True,
            call_string_k=call_string_k,
        )
        return sink_hit, sink_trace, ret_hit, return_trace

    def resolve_cross_file_taint(
        self,
        file_path: str,
        symbol_name: str,
        visited: Optional[Set[Tuple[str, str]]] = None,
    ) -> Optional[Tuple[str, Tuple[TraceFrame, ...]]]:
        """Resolve taint for potentially-imported symbols across modules."""
        normalized_file = self._normalize_path(file_path)
        state = (normalized_file, symbol_name)
        if visited is None:
            visited = set()
        if state in visited:
            return None
        visited.add(state)

        for (fp, sym), taint in self.module_taint.items():
            if sym == symbol_name and self._paths_match(normalized_file, fp):
                return taint

        for (fp, sym), targets in self.imports.items():
            if sym == symbol_name and self._paths_match(normalized_file, fp):
                for target_fp, target_sym in targets:
                    imported_taint = self.resolve_cross_file_taint(target_fp, target_sym, visited=visited)
                    if imported_taint:
                        return imported_taint
        return None

    def find_all_paths(self, source_id: NodeID, sink_id: NodeID, max_depth: int = 5) -> List[List[NodeID]]:
        """Bounded DFS path discovery across the ICFG projection."""
        paths: List[List[NodeID]] = []

        def dfs(current: NodeID, path: List[NodeID], visited: Set[NodeID]) -> None:
            if len(path) > max_depth:
                return
            if current == sink_id:
                paths.append(list(path))
                return
            for edge in self.adjacency.get(current, []):
                neighbor = edge.target
                if neighbor in visited:
                    continue
                visited.add(neighbor)
                path.append(neighbor)
                dfs(neighbor, path, visited)
                path.pop()
                visited.remove(neighbor)

        dfs(source_id, [source_id], {source_id})
        return paths
