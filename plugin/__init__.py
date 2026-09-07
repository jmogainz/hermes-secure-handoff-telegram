"""Hermes Telegram browser-login plugin entry point."""

from .logincheck import register as register_v1
from .browser_login import register as register_v2

__version__ = "0.2.0"


def register(ctx):
    """Register the legacy connection check and browser handoff surfaces."""
    register_v1(ctx)
    return register_v2(ctx)


__all__ = ["register", "__version__"]
