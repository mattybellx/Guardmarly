"""
Framework profiles — domain-specific knowledge for each major web framework.

Each profile defines:
  - GUARDS: patterns indicating a route/method is protected (auth, CSRF, etc.)
  - SINKS: security-sensitive sink patterns specific to the framework
  - SOURCES: patterns that introduce user-controlled data

These are consumed by language analyzers to improve precision (fewer FPs)
and recall (detect framework-specific vulnerability patterns).
"""

from guardmarly.frameworks.spring import SpringProfile  # noqa: F401
from guardmarly.frameworks.aspnet import AspNetProfile  # noqa: F401
from guardmarly.frameworks.django import DjangoProfile  # noqa: F401
from guardmarly.frameworks.express import ExpressProfile  # noqa: F401
from guardmarly.frameworks.gin import GinProfile  # noqa: F401
from guardmarly.frameworks.quarkus import QuarkusProfile  # noqa: F401
