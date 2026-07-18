"""Tests for GlobalGraph cross-language bridge convergence (DIR-3.3)."""
from __future__ import annotations

from guardmarly.ir.global_graph import GlobalGraph, IDETaintLevel


def test_publish_cross_language_bridges_creates_taint_facts():
    gg = GlobalGraph()
    bridges = [
        ("app.py", "get_user", "client.js", "fetchUser"),
        ("routes.py", "list_items", "app.js", "getItems"),
    ]
    count = gg.publish_cross_language_bridges(bridges)

    assert count == 2

    # Verify taint facts were created for source
    fact = gg.get_ide_fact(
        file_path="app.py",
        function_name="get_user",
        value_label="return",
    )
    assert fact.level >= IDETaintLevel.TAINTED
    assert "cross-lang:get_user" in fact.sources

    # Verify taint facts were created for target
    fact2 = gg.get_ide_fact(
        file_path="client.js",
        function_name="fetchUser",
        value_label="argument",
    )
    assert fact2.level >= IDETaintLevel.TAINTED

    # Verify ICFG dependency (reverse: target depends on source)
    # Keys are normalized via _summary_tuple_key which uses _normalize_path
    tgt_key = gg._summary_tuple_key("client.js", "fetchUser")
    src_key = gg._summary_tuple_key("app.py", "get_user")
    assert tgt_key in gg.reverse_summary_dependencies
    assert src_key in gg.reverse_summary_dependencies[tgt_key]


def test_publish_cross_language_bridges_empty():
    gg = GlobalGraph()
    count = gg.publish_cross_language_bridges([])
    assert count == 0


def test_publish_cross_language_bridges_chain_verification():
    gg = GlobalGraph()
    bridges = [
        ("backend.py", "get_profile", "frontend.js", "loadProfile"),
    ]
    gg.publish_cross_language_bridges(bridges)

    reachable, chain = gg.verify_call_chain_soundness(
        sink_file="frontend.js",
        sink_function="loadProfile",
        source_file="backend.py",
        source_function="get_profile",
    )
    assert reachable is True
    assert len(chain) >= 2
