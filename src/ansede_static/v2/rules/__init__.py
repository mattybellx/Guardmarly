"""
ansede_static.v2.rules
──────────────────────
Rule package for the v2 engine.

Rules are discovered via ``_load_all_rules()`` which imports every
sub-module, causing @REGISTRY.register decorators to execute and
populate the module-level REGISTRY singleton.

Adding a new rule file:
  1. Create the module under python/, shared/, or javascript/.
  2. Implement a class decorated with @REGISTRY.register(...).
  3. Import it here (or let load_all_rules() auto-discover it).
"""
from __future__ import annotations


def load_all_rules() -> None:
    """
    Import every rule sub-module so @REGISTRY.register decorators fire.

    Call this once at engine startup before the first scan.
    """
    # Python rules
    from ansede_static.v2.rules.python import secrets       # noqa: F401
    from ansede_static.v2.rules.python import injection     # noqa: F401
    from ansede_static.v2.rules.python import ssrf          # noqa: F401
    from ansede_static.v2.rules.python import deserialization  # noqa: F401
    from ansede_static.v2.rules.python import path_traversal   # noqa: F401
    from ansede_static.v2.rules.python import crypto        # noqa: F401
    from ansede_static.v2.rules.python import auth          # noqa: F401
    from ansede_static.v2.rules.python import logging_      # noqa: F401

    # Shared rules (language-agnostic)
    from ansede_static.v2.rules.shared import sql_injection  # noqa: F401

    # JavaScript / TypeScript rules
    from ansede_static.v2.rules.javascript import injection  # noqa: F401
    from ansede_static.v2.rules.javascript import xss        # noqa: F401
    from ansede_static.v2.rules.javascript import crypto as js_crypto  # noqa: F401
