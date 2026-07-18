from __future__ import annotations

import pytest

from guardmarly.ir.global_graph import (
    FunctionSummary,
    GlobalGraph,
    IDETaintFact,
    IDETaintLevel,
)


DEFAULT_K = GlobalGraph.DEFAULT_CALL_STRING_K


def test_global_graph_default_call_string_depth_is_three():
    assert DEFAULT_K == 3


def test_ide_taint_fact_join_and_meet():
    left = IDETaintFact(level=IDETaintLevel.CLEAN, sources=("arg[0]",), sanitizers=("xss",), call_string=("a",))
    right = IDETaintFact(level=IDETaintLevel.TAINTED, sources=("arg[1]",), sanitizers=("sql",), call_string=("a", "b"))

    joined = left.join(right)
    assert joined.level == IDETaintLevel.TAINTED
    assert joined.sources == ("arg[0]", "arg[1]")
    assert joined.sanitizers == ("sql", "xss")
    assert joined.call_string == ("a", "b")

    met = joined.meet(IDETaintFact(level=IDETaintLevel.CLEAN, sources=("arg[1]",), sanitizers=("sql",), call_string=("a", "b")))
    assert met.level == IDETaintLevel.CLEAN
    assert met.sources == ("arg[1]",)
    assert met.sanitizers == ("sql",)


def test_global_graph_set_ide_fact_joins_existing():
    graph = GlobalGraph()
    graph.set_ide_fact(
        file_path="a.py",
        function_name="f",
        value_label="$ret",
        fact=IDETaintFact(level=IDETaintLevel.CLEAN, sources=("arg[0]",), call_string=("w", "x", "y", "z")),
        join=True,
        call_string_k=DEFAULT_K,
    )
    merged = graph.set_ide_fact(
        file_path="a.py",
        function_name="f",
        value_label="$ret",
        fact=IDETaintFact(level=IDETaintLevel.TAINTED, sources=("arg[1]",), call_string=("a", "x", "y", "z")),
        join=True,
        call_string_k=DEFAULT_K,
    )

    assert merged.level == IDETaintLevel.TAINTED
    assert merged.sources == ("arg[0]", "arg[1]")
    fact = graph.get_ide_fact(
        file_path="a.py",
        function_name="f",
        value_label="$ret",
        call_string=("ignore", "x", "y", "z"),
        call_string_k=DEFAULT_K,
    )
    assert fact.level == IDETaintLevel.TAINTED


def test_propagate_call_facts_records_return_lattice_fact():
    graph = GlobalGraph()
    graph.record_function_summary(
        FunctionSummary(
            file_path="callee.js",
            function_name="helper",
            args_to_return=(0,),
        )
    )

    sink_hit, _, ret_hit, _ = graph.propagate_call_facts(
        caller_file="caller.js",
        caller_name="route",
        callee_file="callee.js",
        callee_name="helper",
        tainted_arg_indexes={0},
        call_line=9,
        call_string=("ctx0",),
        call_string_k=DEFAULT_K,
    )

    assert sink_hit is False
    assert ret_hit is True
    matching = [
        fact
        for (file_path, function_name, value_label, _), fact in graph.ide_facts.items()
        if file_path.endswith("callee.js") and function_name == "helper" and value_label == "$ret"
    ]
    assert matching
    fact = matching[-1]
    assert fact.level == IDETaintLevel.TAINTED
    assert fact.sources == ("arg[0]",)
    assert fact.call_string[0] == "ctx0"
    assert fact.call_string[-1].endswith("caller.js::route@9->helper")


def test_propagate_js_call_facts_uses_js_defaults():
    graph = GlobalGraph()
    graph.record_function_summary(
        FunctionSummary(
            file_path="callee.js",
            function_name="helper",
            args_to_return=(0,),
        )
    )

    sink_hit, _, ret_hit, _ = graph.propagate_js_call_facts(
        caller_file="caller.js",
        callee_file="callee.js",
        callee_name="helper",
        tainted_arg_indexes={0},
        call_line=11,
    )

    assert sink_hit is False
    assert ret_hit is True
    matching = [
        fact
        for (file_path, function_name, value_label, _), fact in graph.ide_facts.items()
        if file_path.endswith("callee.js") and function_name == "helper" and value_label == "$ret"
    ]
    assert matching
    fact = matching[-1]
    assert fact.level == IDETaintLevel.TAINTED
    assert fact.sources == ("arg[0]",)
    assert fact.call_string[-1].endswith("caller.js::<js-scope>@11->helper")


def test_resolve_taint_with_access_path_prefers_field_specific_fact():
    graph = GlobalGraph()
    graph.set_taint_with_access_path(
        file_path="app.py",
        function_name="handler",
        value_label="payload",
        level=IDETaintLevel.TAINTED,
        sources=("arg[0]",),
        access_path=("user", "email"),
        call_string=("ctx",),
        call_string_k=DEFAULT_K,
    )

    level, sources, sanitizers = graph.resolve_taint_with_access_path(
        file_path="app.py",
        function_name="handler",
        value_label="payload",
        access_path=("user", "email", "domain"),
        call_string=("ctx",),
        call_string_k=DEFAULT_K,
    )

    assert level == IDETaintLevel.TAINTED
    assert sources == ("arg[0]",)
    assert sanitizers == ()


def test_adjust_confidence_from_ide_boosts_and_suppresses():
    graph = GlobalGraph()
    graph.set_ide_fact(
        file_path="flow.py",
        function_name="sink",
        value_label="$ret",
        fact=IDETaintFact(level=IDETaintLevel.TAINTED, sources=("arg[0]",), call_string=("ctx",)),
        join=True,
        call_string_k=DEFAULT_K,
    )
    boosted = graph.adjust_confidence_from_ide(
        file_path="flow.py",
        function_name="sink",
        value_label="$ret",
        base_confidence=0.6,
        call_string=("ctx",),
        call_string_k=DEFAULT_K,
    )

    graph.set_ide_fact(
        file_path="flow.py",
        function_name="cleaner",
        value_label="$ret",
        fact=IDETaintFact(level=IDETaintLevel.CLEAN, sources=("clean-return",), call_string=("ctx",)),
        join=False,
        call_string_k=DEFAULT_K,
    )
    suppressed = graph.adjust_confidence_from_ide(
        file_path="flow.py",
        function_name="cleaner",
        value_label="$ret",
        base_confidence=0.6,
        call_string=("ctx",),
        call_string_k=DEFAULT_K,
    )

    assert boosted == pytest.approx(0.75)
    assert suppressed == pytest.approx(0.2)
