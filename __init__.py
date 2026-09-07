"""Directory-install compatibility entry point for Hermes.

Pip installs expose the namespaced ``hermes_telegram_browser_login`` package;
Git-based directory installs load this repository root directly.
"""

try:
    from .plugin import register
except ImportError:  # pytest/importlib may load the repository root standalone.
    from plugin import register

__all__ = ["register"]
