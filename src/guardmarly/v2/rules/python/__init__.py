"""guardmarly.v2.rules.python — Python-specific rule modules."""

# Import all rule modules to trigger @REGISTRY.register decorators
from guardmarly.v2.rules.python import auth  # noqa: F401
from guardmarly.v2.rules.python import crypto  # noqa: F401
from guardmarly.v2.rules.python import deserialization  # noqa: F401
from guardmarly.v2.rules.python import framework  # noqa: F401
from guardmarly.v2.rules.python import injection  # noqa: F401
from guardmarly.v2.rules.python import logging_  # noqa: F401
from guardmarly.v2.rules.python import path_traversal  # noqa: F401
from guardmarly.v2.rules.python import secrets  # noqa: F401
from guardmarly.v2.rules.python import ssrf  # noqa: F401
