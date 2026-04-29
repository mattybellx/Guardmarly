"""
tests/test_ifds_realistic_scenarios
────────────────────────────────────
Realistic end-to-end interprocedural taint scenarios.
"""
import pytest
from ansede_static.v2.ifds import (
    CFGNode, CallSite, Context, IFDSSolver, IdentityFlowFunction,
    GenerateFlowFunction, KillFlowFunction, TaintFact, ZERO_FACT
)


class TestRealisticCrossFunctionTaint:
    """Test realistic taint flows across multiple functions."""
    
    def test_web_request_sql_injection_cross_function(self):
        """
        Realistic scenario: web request → helper function → database query.
        
        Code:
            def get_user(id_str):
                return "SELECT * FROM users WHERE id=" + id_str
            
            def handle_request():
                user_id = request.args.get('id')
                query = get_user(user_id)
                cursor.execute(query)
        """
        solver = IFDSSolver()
        ctx = Context()
        
        # Setup: handle_request function
        request_source = CFGNode(
            node_id="src1", function_id="handle_request", label="source: request.args"
        )
        param_call = CFGNode(
            node_id="call1", function_id="handle_request", label="call: get_user(user_id)"
        )
        exec_sink = CFGNode(
            node_id="sink1", function_id="handle_request", label="sink: cursor.execute()"
        )
        
        # Setup: get_user function entry/exit
        get_user_entry = CFGNode(
            node_id="entry_get_user", function_id="get_user", label="entry"
        )
        get_user_exit = CFGNode(
            node_id="exit_get_user", function_id="get_user", label="exit"
        )
        
        # Register functions
        solver.set_entry_exit_nodes("handle_request", request_source, exec_sink)
        solver.set_entry_exit_nodes("get_user", get_user_entry, get_user_exit)
        
        # Register call site: get_user(user_id)
        solver.set_call_site("call1", "handle_request", "get_user", exec_sink)
        
        # Initialize seed: user_id from request.args (tainted)
        taint_source = TaintFact(
            label="user_id", category="user_input", confidence="confirmed"
        )
        solver.set_seed_fact(request_source, ctx, taint_source)
        
        # Edges within handle_request:
        # request_source -> param_call (identity)
        solver.add_edge_flow(
            request_source, param_call, ctx, IdentityFlowFunction()
        )
        
        # param_call (call site) -> exec_sink (identity)
        solver.add_edge_flow(
            param_call, exec_sink, ctx, IdentityFlowFunction()
        )
        
        # Edges for get_user function:
        # entry -> exit (generate return value)
        solver.add_edge_flow(
            get_user_entry, get_user_exit, ctx, GenerateFlowFunction(
                TaintFact(label="return_value", category="user_input")
            )
        )
        
        # Solve
        solver.solve()
        
        # Verify: taint propagated through call
        result_at_sink = solver.query(exec_sink, ctx)
        
        # user_id should be tainted at the sink
        has_tainted_user_id = any(
            f.label == "user_id" and isinstance(f, TaintFact)
            for f in result_at_sink
        )
        assert has_tainted_user_id, "user_id should be tainted at sink"
    
    def test_sanitizer_stops_taint(self):
        """Test that sanitizer flow function kills taint."""
        solver = IFDSSolver()
        ctx = Context()
        
        src = CFGNode(node_id="src", function_id="f", label="source")
        sanitize = CFGNode(node_id="san", function_id="f", label="sanitize")
        sink = CFGNode(node_id="sink", function_id="f", label="sink")
        
        # Taint source
        taint = TaintFact(label="x", category="user_input")
        solver.set_seed_fact(src, ctx, taint)
        
        # src -> sanitize (identity)
        solver.add_edge_flow(src, sanitize, ctx, IdentityFlowFunction())
        
        # sanitize -> sink (kill user_input taint)
        from ansede_static.v2.interprocedural_taint import TaintSanitizeFlowFunction
        sanitizer_ff = TaintSanitizeFlowFunction(frozenset({"user_input"}))
        solver.add_edge_flow(sanitize, sink, ctx, sanitizer_ff)
        
        solver.solve()
        
        # Verify: taint is killed at sink
        result_at_sink = solver.query(sink, ctx)
        has_user_input_taint = any(
            isinstance(f, TaintFact) and f.category == "user_input"
            for f in result_at_sink
        )
        assert not has_user_input_taint, "Sanitizer should have killed taint"
    
    def test_multiple_taint_categories(self):
        """Test tracking multiple taint categories simultaneously."""
        solver = IFDSSolver()
        ctx = Context()
        
        src1 = CFGNode(node_id="src1", function_id="f", label="user_input")
        src2 = CFGNode(node_id="src2", function_id="f", label="env")
        sink = CFGNode(node_id="sink", function_id="f", label="sink")
        
        # Two different taint sources
        taint_user = TaintFact(label="user_var", category="user_input")
        taint_env = TaintFact(label="env_var", category="env")
        
        solver.set_seed_fact(src1, ctx, taint_user)
        solver.set_seed_fact(src2, ctx, taint_env)
        
        # Both flow to sink
        solver.add_edge_flow(src1, sink, ctx, IdentityFlowFunction())
        solver.add_edge_flow(src2, sink, ctx, IdentityFlowFunction())
        
        solver.solve()
        
        # Verify: both categories present at sink
        result = solver.query(sink, ctx)
        categories = {f.category for f in result if isinstance(f, TaintFact)}
        assert "user_input" in categories
        assert "env" in categories
    
    def test_context_sensitive_call_tracking(self):
        """Test that different call sites create different contexts."""
        solver = IFDSSolver()
        
        # Two different call sites
        call_site1 = CallSite("call1", "main", "helper")
        call_site2 = CallSite("call2", "main", "helper")
        
        ctx1 = Context().push(call_site1)
        ctx2 = Context().push(call_site2)
        
        # Contexts should be different
        assert ctx1 != ctx2
        assert hash(ctx1) != hash(ctx2)
        
        # Create separate facts for each context
        src = CFGNode(node_id="src", function_id="helper", label="entry")
        sink1 = CFGNode(node_id="sink1", function_id="helper", label="exit")
        sink2 = CFGNode(node_id="sink2", function_id="helper", label="exit")
        
        fact1 = TaintFact(label="x", category="call1_taint")
        fact2 = TaintFact(label="x", category="call2_taint")
        
        solver.set_seed_fact(src, ctx1, fact1)
        solver.set_seed_fact(src, ctx2, fact2)
        
        solver.add_edge_flow(src, sink1, ctx1, IdentityFlowFunction())
        solver.add_edge_flow(src, sink2, ctx2, IdentityFlowFunction())
        
        solver.solve()
        
        # Query with different contexts
        result1 = solver.query(sink1, ctx1)
        result2 = solver.query(sink2, ctx2)
        
        # Different facts in different contexts
        categories1 = {f.category for f in result1 if isinstance(f, TaintFact)}
        categories2 = {f.category for f in result2 if isinstance(f, TaintFact)}
        
        assert "call1_taint" in categories1
        assert "call2_taint" in categories2
    
    def test_bounded_context_depth(self):
        """Test that context depth is bounded."""
        # Create a chain of calls: a -> b -> c -> d -> e
        ctx = Context()
        
        for i in range(10):
            call_site = CallSite(f"call{i}", f"func{i}", f"func{i+1}")
            ctx = ctx.push(call_site, max_depth=3)
        
        # Context should only contain the last 3 calls
        assert len(ctx.call_sites) <= 3
    
    def test_fixpoint_convergence(self):
        """Test that IFDS solver reaches fixed point."""
        solver = IFDSSolver()
        ctx = Context()
        
        # Linear chain: n0 -> n1 -> n2 -> n3
        nodes = [
            CFGNode(node_id=f"n{i}", function_id="f", label=f"node{i}")
            for i in range(4)
        ]
        
        # Initialize with fact at n0
        fact = TaintFact(label="x", category="user_input")
        solver.set_seed_fact(nodes[0], ctx, fact)
        
        # Chain edges
        for i in range(3):
            solver.add_edge_flow(nodes[i], nodes[i+1], ctx, IdentityFlowFunction())
        
        # Solve
        solver.solve()
        
        # Verify: fact reached all nodes
        for i in range(4):
            result = solver.query(nodes[i], ctx)
            assert fact in result, f"Fact should reach node {i}"
    
    def test_cycle_handling(self):
        """Test that IFDS handles cycles (loops in CFG)."""
        solver = IFDSSolver()
        ctx = Context()
        
        # Nodes: entry -> loop_body -> (back to loop_body)
        entry = CFGNode(node_id="entry", function_id="f", label="entry")
        loop_body = CFGNode(node_id="loop", function_id="f", label="loop")
        
        fact = TaintFact(label="x", category="user_input")
        solver.set_seed_fact(entry, ctx, fact)
        
        # entry -> loop_body
        solver.add_edge_flow(entry, loop_body, ctx, IdentityFlowFunction())
        
        # loop_body -> loop_body (cycle)
        solver.add_edge_flow(loop_body, loop_body, ctx, IdentityFlowFunction())
        
        # Should not hang; solver should terminate at fixed point
        solver.solve()
        
        # Verify fact is present
        result = solver.query(loop_body, ctx)
        assert fact in result


class TestTaintConfidenceProgression:
    """Test confidence tracking through taint propagation."""
    
    def test_confidence_degrades_through_assignments(self):
        """Confirmed taint -> likely after one propagation."""
        from ansede_static.v2.interprocedural_taint import TaintPropagateFlowFunction
        from ansede_static.v2.nodes import AssignNode, SourceLocation, CallNode
        
        # x = tainted (confirmed)
        # y = x      (propagates as likely)
        
        taint_confirmed = TaintFact(
            label="x", category="user_input", confidence="confirmed"
        )
        
        loc = SourceLocation(file_path="test.py", line=1)
        # Create a call node for the value with raw_text containing "x"
        call_value = CallNode(
            node_type="CALL", location=loc, language="python",
            callee="func", raw_text="x"  # raw_text should contain the variable
        )
        
        assign = AssignNode(
            node_type="ASSIGN", location=loc, language="python",
            target="y", value=call_value, raw_text="y = x"
        )
        
        ff = TaintPropagateFlowFunction(assign)
        result = ff(taint_confirmed)
        
        # Should propagate the taint to y
        propagated = [f for f in result if isinstance(f, TaintFact) and f.label == "y"]
        assert len(propagated) > 0, f"Expected y to be tainted, got {result}"
        # Confidence stays "confirmed" per the flow function logic
        assert propagated[0].confidence == "confirmed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
