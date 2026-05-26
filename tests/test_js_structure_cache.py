from __future__ import annotations

from ansede_static.js_engine.structure import collect_calls, collect_property_writes


def test_collect_calls_returns_fresh_list_when_cache_hits():
    code = "handler(foo(bar), baz);"

    first = collect_calls(code)
    assert len(first) == 2

    first.clear()
    second = collect_calls(code)

    assert [call.callee for call in second] == ["handler", "foo"]


def test_collect_property_writes_returns_fresh_list_when_cache_hits():
    code = "element.innerHTML = value + suffix;"

    first = collect_property_writes(code)
    assert len(first) == 1

    first.pop()
    second = collect_property_writes(code)

    assert len(second) == 1
    assert second[0].property_name == "innerHTML"