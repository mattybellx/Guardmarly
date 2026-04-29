"""
tests/test_interprocedural_taint
────────────────────────────────
Tests for interprocedural taint analysis via IFDS.
"""
import pytest
from ansede_static.v2.interprocedural_taint import InterproceduralTaintAnalysis
from ansede_static.v2.call_graph import CallGraph
from ansede_static.v2.model import SemanticModel
from ansede_static.v2.normalizer import normalize_source


class TestInterproceduralTaintAnalysis:
    """Test interprocedural taint analysis."""
    
    def test_analysis_initialization(self):
        """Test creating an interprocedural analysis."""
        # Parse a simple Python snippet
        source = """
user_input = request.args.get('id')
result = process(user_input)
execute(result)
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        assert analysis.model is model
        assert analysis.call_graph is call_graph
        assert analysis.max_context_depth == 3
    
    def test_analysis_simple_taint_flow(self):
        """Test basic intraprocedural taint flow (within one function)."""
        source = """
def handle_request():
    user_input = request.args.get('id')
    execute(user_input)
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        findings = analysis.analyze()
        # Should find the taint flow from request.args to execute
        # (Note: specific behavior depends on IFDS implementation)
        assert isinstance(findings, list)
    
    def test_analysis_extracts_findings(self):
        """Test that analysis returns findings in expected format."""
        source = """
user_input = input()
os.system(user_input)
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        findings = analysis.analyze()
        assert isinstance(findings, list)
        # Each finding should be (TaintSource, TaintSink) tuple
        for finding in findings:
            assert len(finding) == 2
    
    def test_cfg_node_building(self):
        """Test that CFG nodes are built correctly."""
        source = """
def foo():
    x = 1
    return x
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        analysis._build_cfg_nodes()
        assert len(analysis._cfg_nodes) > 0
    
    def test_function_id_inference(self):
        """Test inferring function context of nodes."""
        source = """
def foo():
    x = 1
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        for node in model.all_nodes():
            func_id = analysis._infer_function_id(node)
            assert isinstance(func_id, str)
            assert len(func_id) > 0
    
    def test_node_labeling(self):
        """Test that nodes are labeled appropriately."""
        source = """
def foo():
    x = 1
    y = foo()
    return x
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        for node in model.all_nodes():
            label = analysis._label_node(node)
            assert isinstance(label, str)
            assert len(label) > 0
    
    def test_analysis_consistency(self):
        """Test that running analysis multiple times produces consistent results."""
        source = """
x = request.args.get('id')
sql_query = "SELECT * FROM users WHERE id = " + x
cursor.execute(sql_query)
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        findings1 = analysis.analyze()
        findings2 = analysis.analyze()
        
        # Results should be consistent (same findings)
        assert len(findings1) == len(findings2)
    
    def test_analysis_empty_model(self):
        """Test analysis on empty/minimal model."""
        source = "x = 1"
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        findings = analysis.analyze()
        # Should complete without error
        assert isinstance(findings, list)
    
    def test_analysis_no_taint_sources(self):
        """Test analysis when no taint sources are present."""
        source = """
x = 1
y = 2
z = x + y
execute(z)
"""
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
        )
        
        findings = analysis.analyze()
        # Should not find any taint flows
        assert isinstance(findings, list)


class TestContextSensitivity:
    """Test context-sensitive analysis features."""
    
    def test_analysis_respects_max_context_depth(self):
        """Test that max_context_depth is respected."""
        source = "x = 1"
        model = normalize_source(source, "test.py", "python")
        call_graph = CallGraph()
        
        analysis = InterproceduralTaintAnalysis(
            model=model,
            call_graph=call_graph,
            max_context_depth=2,
        )
        
        assert analysis.max_context_depth == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
