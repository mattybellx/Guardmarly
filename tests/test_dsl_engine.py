import unittest
from guardmarly.dsl.engine import (
    ASTNode, KindPattern, MetavariablePattern, TextPattern,
    PatternsOperator, PatternEitherOperator, PatternNotOperator, EvaluatorContext
)

class TestDeclarativeDSLEngine(unittest.TestCase):
    def setUp(self):
        # Create a mock tree matching simple call structures
        # foo.bar(x, y)
        self.node_child_1 = ASTNode(id=2, kind="Name", text="foo", start_line=1, start_col=0)
        self.node_child_2 = ASTNode(id=3, kind="Attribute", text="bar", start_line=1, start_col=4)
        self.root_node = ASTNode(
            id=1,
            kind="Call",
            text="foo.bar(x, y)",
            start_line=1,
            start_col=0,
            children=[self.node_child_1, self.node_child_2]
        )

    def test_kind_pattern(self):
        ctx = EvaluatorContext()
        pattern = KindPattern(target_kinds={"Call"})
        self.assertTrue(pattern.match(self.root_node, ctx))
        
        pattern_fail = KindPattern(target_kinds={"Assign"})
        self.assertFalse(pattern_fail.match(self.root_node, ctx))

    def test_text_pattern(self):
        ctx = EvaluatorContext()
        pattern = TextPattern("foo")
        self.assertTrue(pattern.match(self.node_child_1, ctx))
        
        pattern_fail = TextPattern("baz")
        self.assertFalse(pattern_fail.match(self.node_child_1, ctx))

    def test_metavariable_pattern(self):
        ctx = EvaluatorContext()
        pattern_var = MetavariablePattern("$FUNC")
        
        # Test binding works
        self.assertTrue(pattern_var.match(self.node_child_1, ctx))
        self.assertEqual(ctx.registry.lookup("$FUNC").text, "foo")
        
        # Sibling match enforces equality
        self.assertTrue(pattern_var.match(self.node_child_1, ctx))
        
        # Sibling mismatch fails
        node_diff = ASTNode(id=4, kind="Name", text="different", start_line=1, start_col=0)
        self.assertFalse(pattern_var.match(node_diff, ctx))

    def test_logical_operators(self):
        ctx = EvaluatorContext()
        
        # Patterns Operator (AND)
        pattern_and = PatternsOperator([
            KindPattern({"Name"}),
            TextPattern("foo")
        ])
        self.assertTrue(pattern_and.match(self.node_child_1, ctx))
        
        # Pattern Either Operator (OR)
        pattern_or = PatternEitherOperator([
            TextPattern("foo"),
            TextPattern("different")
        ])
        self.assertTrue(pattern_or.match(self.node_child_1, ctx))
        
        # Pattern Not Operator (NOT)
        pattern_not = PatternNotOperator(TextPattern("different"))
        self.assertTrue(pattern_not.match(self.node_child_1, ctx))

    def test_query_ast_recursive(self):
        from guardmarly.dsl.engine import query_ast
        pattern = TextPattern("foo")
        matches = query_ast(self.root_node, pattern)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].text, "foo")

class TestDeclarativeDSLCompiler(unittest.TestCase):
    def test_compile_simple(self):
        from guardmarly.dsl.compiler import compile_pattern
        pat = compile_pattern("foo")
        self.assertIsInstance(pat, TextPattern)
        self.assertEqual(pat.text, "foo")

        pat_var = compile_pattern("$X_VAR")
        self.assertIsInstance(pat_var, MetavariablePattern)
        self.assertEqual(pat_var.var_name, "$X_VAR")

    def test_compile_list(self):
        from guardmarly.dsl.compiler import compile_pattern
        pat = compile_pattern(["foo", "$X"])
        self.assertIsInstance(pat, PatternsOperator)
        self.assertEqual(len(pat.operators), 2)
        self.assertIsInstance(pat.operators[0], TextPattern)
        self.assertIsInstance(pat.operators[1], MetavariablePattern)

    def test_compile_nested_dict(self):
        from guardmarly.dsl.compiler import compile_pattern
        schema = {
            "patterns": ["const x = 1", "$VAR"],
            "not": {
                "patterns": ["unsafe"]
            }
        }
        pat = compile_pattern(schema)
        self.assertIsInstance(pat, PatternsOperator)
        self.assertEqual(len(pat.operators), 2)  # parsed patterns + not

    def test_bridge_python_ast(self):
        from guardmarly.dsl.bridge import parse_python_to_dsl
        from guardmarly.dsl.engine import query_ast
        from guardmarly.dsl.compiler import compile_pattern
        
        # Parse test Python snippet:
        # app.route("/admin")
        code = "app.route('/admin')"
        dsl_tree = parse_python_to_dsl(code)
        
        # Test locating "app.route" or "/admin"
        pat = compile_pattern("app.route('/admin')")
        matches = query_ast(dsl_tree, pat)
        self.assertTrue(len(matches) >= 1)

if __name__ == "__main__":
    unittest.main()
