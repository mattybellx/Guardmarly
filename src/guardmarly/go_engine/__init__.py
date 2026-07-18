"""
go_engine — Pure-Python Go security analysis engine.

Zero dependencies. Provides:
- go_parser: Recursive-descent parser for Go source
"""

from .go_parser import parse_go, GoFile, GoFuncDecl, GoCallExpr, GoSelectorExpr
