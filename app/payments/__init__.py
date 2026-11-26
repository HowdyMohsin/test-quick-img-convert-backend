"""Payment providers package for Quick IMG Convert v5.

See :mod:`app.payments.providers` for the provider interface and plugin
guide. Importing this package exposes :data:`REGISTRY` (all 8 providers).
"""
from app.payments.providers import REGISTRY, get_provider, registry

__all__ = ["REGISTRY", "get_provider", "registry"]
