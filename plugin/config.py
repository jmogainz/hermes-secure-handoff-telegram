"""Shared security validation for the Telegram browser-login plugin."""

from __future__ import annotations

import ipaddress
from typing import Any, Optional
from urllib.parse import urlsplit

DEFAULT_CDP_URL = "http://127.0.0.1:9222"
DEFAULT_MINI_APP_URL = "https://hermes-remote-web-login-telegram.vercel.app"


def validate_browser_cdp_url(raw: Any) -> Optional[str]:
    """Accept only a local HTTP DevTools endpoint.

    CDP exposes browser cookies and page control. Remote, websocket, credential
    bearing, and path/query-bearing endpoints are intentionally rejected.
    """

    value = str(raw or DEFAULT_CDP_URL).strip().rstrip("/")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port or 9222
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
