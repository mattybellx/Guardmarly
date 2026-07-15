"""Smoke test for new blueprint modules."""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

# ── Test execution_context ────────────────────────────────────────────
from ansede_static.execution_context import (
    classify_file, ExecutionEnvironment, get_context_for_language,
    should_suppress_for_context,
)

# Flask server code → should be SERVER
flask_code = '''from flask import Flask, request
app = Flask(__name__)
@app.route("/user/<id>")
def get_user(id):
    return db.execute(f"SELECT * FROM users WHERE id = {id}")
'''
r = classify_file("app.py", flask_code)
assert r.environment == ExecutionEnvironment.SERVER, f"Expected SERVER, got {r.environment}"
assert r.score >= 30, f"Score {r.score} should be >= 30"
print(f"  Flask app: {r.environment.value} (score={r.score}, conf={r.confidence})")

# React JSX → should be CLIENT
react_code = '''import React, {{ useState }} from "react";
const App = () => {{
  const [count, setCount] = useState(0);
  document.getElementById("root").innerHTML = "<h1>Hello</h1>";
  return <div className="app">{{count}}</div>;
}};
'''
r2 = classify_file("App.jsx", react_code)
assert r2.environment == ExecutionEnvironment.CLIENT, f"Expected CLIENT, got {r2.environment}"
assert r2.score <= -30, f"Score {r2.score} should be <= -30"
print(f"  React JSX: {r2.environment.value} (score={r2.score}, conf={r2.confidence})")

# Plain Python → should be UNKNOWN
plain_code = "x = 1\ny = x + 2\nprint(y)\n"
r3 = classify_file("util.py", plain_code)
assert r3.environment == ExecutionEnvironment.UNKNOWN, f"Expected UNKNOWN, got {r3.environment}"
print(f"  Plain script: {r3.environment.value} (score={r3.score}, conf={r3.confidence})")

# ── Test should_suppress_for_context ──────────────────────────────────
# CWE-22 (path traversal) on CLIENT file → should suppress
assert should_suppress_for_context("CWE-22", r2) == True
# CWE-22 on SERVER file → should NOT suppress
assert should_suppress_for_context("CWE-22", r) == False
# CWE-79 (XSS) on SERVER file → should suppress
assert should_suppress_for_context("CWE-79", r) == True
print("  should_suppress_for_context: OK")

# ── Test path-based heuristics ────────────────────────────────────────
assert get_context_for_language("python", "src/components/Button.tsx") == ExecutionEnvironment.CLIENT
assert get_context_for_language("go", "cmd/api/handlers/users.go") == ExecutionEnvironment.SERVER
assert get_context_for_language("python", "utils/helpers.py") == ExecutionEnvironment.UNKNOWN
print("  get_context_for_language: OK")

# ── Test DSE ──────────────────────────────────────────────────────────
from ansede_static.dse import ReDoSCircuitBreaker, GoldenCorpusValidator, PerfRegressionGuard

breaker = ReDoSCircuitBreaker(timeout_seconds=0.05)
# Safe pattern
r = breaker.evaluate(r"hello", "hello world")
assert r.matched and not r.timed_out
print(f"  DSE safe pattern: matched={r.matched}, elapsed={r.elapsed_ms:.3f}ms")

# Non-backtracking pattern
r2 = breaker.evaluate(r"\d+", "abc 123 def")
assert r2.matched and not r2.timed_out
print(f"  DSE digit pattern: matched={r2.matched}, elapsed={r2.elapsed_ms:.3f}ms")

# Blacklist test
breaker.blacklist_pattern(r"hello")
r3 = breaker.evaluate(r"hello", "hello world")
assert not r3.matched
assert "blacklisted" in str(r3.error)
print(f"  DSE blacklist: matched={r3.matched}, error={r3.error}")

# Perf regression guard
guard = PerfRegressionGuard(warning_budget_ms=100.0)
guard.record("test-rule", 5.0)
guard.record("test-rule", 8.0)
guard.record("slow-rule", 150.0)
assert len(guard.get_budget_violations()) == 1
print(f"  Perf guard budget violations: {len(guard.get_budget_violations())}")

# ── Test SummaryRegistry ─────────────────────────────────────────────
from ansede_static.ir.global_graph import FunctionSummary, SummaryRegistry

registry = SummaryRegistry()
summary = FunctionSummary(
    file_path="app.py",
    function_name="get_user",
    args_to_sink=(0,),
    args_to_return=(0,),
    return_from_source=False,
    sanitizers_applied=("html.escape",),
)
registry.register("app:get_user", summary)
retrieved = registry.lookup("app:get_user")
assert retrieved is not None
assert retrieved.sanitizers_applied == ("html.escape",)
assert retrieved.args_to_sink == (0,)
print(f"  SummaryRegistry: registered={len(registry)}, sanitizers={retrieved.sanitizers_applied}")

# ── Test FunctionSummary serialization round-trip ─────────────────────
d = summary.as_dict()
restored = FunctionSummary.from_dict(d)
assert restored.file_path == "app.py"
assert restored.sanitizers_applied == ("html.escape",)
print("  FunctionSummary round-trip: OK")

print("\n✅ All blueprint module smoke tests passed!")
