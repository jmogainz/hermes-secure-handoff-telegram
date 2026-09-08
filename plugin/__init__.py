"""Hermes Secure Handoff Telegram plugin entry point."""

from .connection_check import register as register_connection_check
from .secure_handoff import register as register_secure_handoff

__version__ = "1.1.0"


def register(ctx):
    """Register the connection check and secure handoff surfaces."""
    connection = register_connection_check(ctx)
    controller = register_secure_handoff(ctx)
    if connection is not None:
        connection.secure_controller = controller
    return controller


__all__ = ["register", "__version__"]
