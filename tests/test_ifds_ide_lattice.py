from __future__ import annotations

from ansede_static.ir.global_graph import (
    FunctionSummary,
    GlobalGraph,
    IDETaintFact,
    IDETaintLevel,
)


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
        fact=IDETaintFact(level=IDETaintLevel.CLEAN, sources=("arg[0]",), call_string=("x", "y", "z")),
        join=True,
        call_string_k=2,
    )
    merged = graph.set_ide_fact(
        file_path="a.py",
        function_name="f",
        value_label="$ret",
        fact=IDETaintFact(level=IDETaintLevel.TAINTED, sources=("arg[1]",), call_string=("y", "z")),
        join=True,
        call_string_k=2,
    )

    assert merged.level == IDETaintLevel.TAINTED
    assert merged.sources == ("arg[0]", "arg[1]")
    fact = graph.get_ide_fact(
        file_path="a.py",
        function_name="f",
        value_label="$ret",
        call_string=("ignore", "y", "z"),
        call_string_k=2,
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
        call_string_k=2,
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
