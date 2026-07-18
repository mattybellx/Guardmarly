from guardmarly.js_engine.backends import run_js_analysis
from guardmarly.js_engine.pratt.ast_nodes import TemplateLiteral, VariableDeclaration
from guardmarly.js_engine.pratt.lexer import TokenType, tokenize
from guardmarly.js_engine.pratt.parser import PrattParser


def test_pratt_parser_consumes_template_head_without_recursing():
    parser = PrattParser(tokenize("`${l.default.locals.unit}`", "template.js"))
    expr = parser.parse_expression()

    assert isinstance(expr, TemplateLiteral)
    assert len(expr.expressions) == 1
    assert expr.quasis[0].raw.startswith("`")
    assert expr.quasis[-1].tail is True
    assert parser.lexer.peek().type == TokenType.EOF


def test_pratt_backend_handles_member_expression_template_literal():
    result, backend = run_js_analysis(
        "const unit = `${l.default.locals.unit}`;",
        filename="template.js",
        requested_backend="pratt",
    )

    assert backend.key == "pratt"
    assert result.language == "javascript"
    assert result.parse_error in (None, "")


def test_pratt_parser_parses_top_level_const_declaration():
    parser = PrattParser(tokenize("const unit = `${l.default.locals.unit}`;", "template.js"))

    program = parser.parse_program()

    assert len(program.body) == 1
    declaration = program.body[0]
    assert isinstance(declaration, VariableDeclaration)
    assert declaration.kind == "const"
    assert len(declaration.declarations) == 1
    assert declaration.declarations[0].id.name == "unit"
    assert isinstance(declaration.declarations[0].init, TemplateLiteral)