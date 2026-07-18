"""guardmarly.v2.rules.javascript (package init)."""

# Import all rule modules to trigger @REGISTRY.register decorators
from guardmarly.v2.rules.javascript import crypto  # noqa: F401
from guardmarly.v2.rules.javascript import framework  # noqa: F401
from guardmarly.v2.rules.javascript import injection  # noqa: F401
from guardmarly.v2.rules.javascript import xss  # noqa: F401
