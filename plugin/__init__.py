"""Hermes Secure Handoff Telegram plugin entry point."""

from .connection_check import register as register_connection_check
from .secure_handoff import register as register_secure_handoff

__version__ = "1.0.0"


def register(ctx):
    """Register the connection check and secure handoff surfaces."""
    register_connection_check(ctx)
    return register_secure_handoff(ctx)


__all__ = ["register", "__version__"]
