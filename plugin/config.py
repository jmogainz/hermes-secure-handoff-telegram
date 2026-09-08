"""Shared security validation for Hermes Secure Handoff Telegram."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional
from urllib.parse import urlsplit

DEFAULT_CDP_URL = "http://127.0.0.1:9222"
DEFAULT_MINI_APP_URL = "https://hermes-secure-handoff-telegram.vercel.app"


def validate_browser_cdp_url(raw: Any) -> Optional[str]:
    """Accept only a local HTTP DevTools endpoint.

    CDP exposes browser cookies and page control. Remote, websocket, credential
    bearing, and path/query-bearing endpoints are intentionally rejected.
    """

    # Only an absent setting selects the default; never repair malformed input.
    value = DEFAULT_CDP_URL if raw is None else raw
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = 9222 if parsed.port is None else parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme.lower() != "http"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.netloc.endswith(":")
        or not 1 <= port <= 65535
    ):
        return None
    host = host.rstrip(".").lower()
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                return None
        except ValueError:
            return None
    rendered_host = f"[{host}]" if ":" in host else host
    return f"http://{rendered_host}:{port}"


__all__ = ["DEFAULT_CDP_URL", "DEFAULT_MINI_APP_URL", "validate_browser_cdp_url"]
