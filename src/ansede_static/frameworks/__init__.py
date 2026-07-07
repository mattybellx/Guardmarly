"""
Framework profiles — domain-specific knowledge for each major web framework.

Each profile defines:
  - GUARDS: patterns indicating a route/method is protected (auth, CSRF, etc.)
  - SINKS: security-sensitive sink patterns specific to the framework
  - SOURCES: patterns that introduce user-controlled data

These are consumed by language analyzers to improve precision (fewer FPs)
and recall (detect framework-specific vulnerability patterns).
"""

from ansede_static.frameworks.spring import SpringProfile  # noqa: F401
from ansede_static.frameworks.aspnet import AspNetProfile  # noqa: F401
from ansede_static.frameworks.django import DjangoProfile  # noqa: F401
from ansede_static.frameworks.express import ExpressProfile  # noqa: F401
from ansede_static.frameworks.gin import GinProfile  # noqa: F401
from ansede_static.frameworks.quarkus import QuarkusProfile  # noqa: F401
