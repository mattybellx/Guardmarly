from __future__ import annotations

from guardmarly.graph.unified_source_graph import SourceEdge, SourceNode, UnifiedSourceGraph


def _sample_graph() -> UnifiedSourceGraph:
    graph = UnifiedSourceGraph()
    graph.add_node(SourceNode(
        id="file:///repo/api.py#func:get_user",
        kind="function",
        name="get_user",
        file_path="/repo/api.py",
        language="python",
        start_line=10,
        end_line=20,
    ))
    graph.add_node(SourceNode(
        id="file:///repo/client.ts#func:fetchUser",
        kind="function",
        name="fetchUser",
        file_path="/repo/client.ts",
        language="typescript",
        start_line=5,
        end_line=12,
    ))
    graph.add_node(SourceNode(
        id="file:///repo/dom.ts#prop:innerHTML",
        kind="sink",
        name="innerHTML",
        file_path="/repo/dom.ts",
        language="typescript",
        start_line=22,
        end_line=22,
    ))
    graph.add_edge(SourceEdge(
        source_id="file:///repo/api.py#func:get_user",
        target_id="file:///repo/client.ts#func:fetchUser",
        kind="route_pair",
        confidence=0.92,
    ))
    graph.add_edge(SourceEdge(
        source_id="file:///repo/client.ts#func:fetchUser",
        target_id="file:///repo/dom.ts#prop:innerHTML",
        kind="taint",
        confidence=0.88,
    ))
    return graph


def test_graph_round_trip_json():
    graph = _sample_graph()

    cloned = UnifiedSourceGraph.from_json(graph.to_json())

    assert len(cloned.nodes) == 3
    assert len(cloned.edges) == 2
    assert cloned.nodes["file:///repo/api.py#func:get_user"].language == "python"


def test_get_callers_and_callees():
    graph = _sample_graph()

    callers = graph.get_callers("file:///repo/client.ts#func:fetchUser")
    callees = graph.get_callees("file:///repo/client.ts#func:fetchUser")

    assert [node.name for node in callers] == ["get_user"]
    assert [node.name for node in callees] == ["innerHTML"]


def test_find_path_returns_edge_sequence():
    graph = _sample_graph()

    path = graph.find_path(
        "file:///repo/api.py#func:get_user",
        "file:///repo/dom.ts#prop:innerHTML",
    )

    assert len(path) == 2
    assert path[0].kind == "route_pair"
    assert path[1].kind == "taint"


def test_find_taint_paths_supports_glob_patterns():
    graph = _sample_graph()

    paths = graph.find_taint_paths("*get_user", "*innerHTML")

    assert len(paths) == 1
    assert len(paths[0]) == 2


def test_merge_preserves_unique_nodes_and_edges():
    left = _sample_graph()
    right = UnifiedSourceGraph()
    right.add_node(SourceNode(
        id="file:///repo/dom.ts#prop:innerHTML",
        kind="sink",
        name="innerHTML",
        file_path="/repo/dom.ts",
        language="typescript",
        start_line=22,
        end_line=22,
    ))
    right.add_node(SourceNode(
        id="file:///repo/sql.py#func:query",
        kind="function",
        name="query",
        file_path="/repo/sql.py",
        language="python",
        start_line=1,
        end_line=5,
    ))
    right.add_edge(SourceEdge(
        source_id="file:///repo/dom.ts#prop:innerHTML",
        target_id="file:///repo/sql.py#func:query",
        kind="calls",
        confidence=0.60,
    ))

    left.merge(right)

    assert len(left.nodes) == 4
    assert len(left.edges) == 3


def test_statistics_counts_languages_and_edge_kinds():
    graph = _sample_graph()

    stats = graph.statistics()

    assert stats["nodes"] == 3
    assert stats["edges"] == 2
    assert stats["languages"]["python"] == 1
    assert stats["languages"]["typescript"] == 2
    assert stats["edge_kinds"]["taint"] == 1
