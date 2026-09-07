"""First-run setup and diagnostics for the Hermes Telegram browser handoff.

This CLI deliberately never accepts or prints the Telegram bot token. Hermes's
own ``hermes gateway setup`` wizard owns that secret boundary.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence
from urllib.error import URLError
from urllib.request import urlopen
from urllib.parse import urlsplit

try:
    from .config import DEFAULT_CDP_URL, DEFAULT_MINI_APP_URL, validate_browser_cdp_url
except ImportError:  # Standalone Hermes plugin loader path.
    from config import DEFAULT_CDP_URL, DEFAULT_MINI_APP_URL, validate_browser_cdp_url

PLUGIN_ID = "telegram-secure-handoff"

def _validate_mini_app_url(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValueError("Mini App URL must be a string")
    value = raw.strip().rstrip("/")
    if not value or len(value) > 4096 or any(character.isspace() for character in value):
        raise ValueError("Mini App URL must be a bounded HTTPS origin without whitespace")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Mini App URL is not valid") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
    ):
        raise ValueError("Mini App URL must be an HTTPS origin without query or fragment")
    return value


def _validate_browser_cdp_url(raw: str) -> str:
    value = validate_browser_cdp_url(raw)
    if value is None:
        raise ValueError("browser CDP URL must be loopback HTTP without credentials, path, query, or fragment")
    return value


def _parse_user_ids(values: Iterable[str]) -> list[int]:
    parsed: list[int] = []
    for raw in values:
        for token in str(raw).replace(",", " ").split():
            if not token.isdigit() or int(token) <= 0:
                raise ValueError(f"Telegram user ID must be a positive integer: {token!r}")
            parsed.append(int(token))
    deduped = list(dict.fromkeys(parsed))
    if not deduped:
        raise ValueError("One Telegram owner user ID is required")
    if len(deduped) != 1:
        raise ValueError("Use one Telegram owner user ID per Hermes/Chrome profile")
    return deduped


def _prompt(prompt: str) -> str:
    try:
        value = input(prompt).strip()
    except EOFError as exc:
        raise SystemExit("Interactive input is unavailable; pass the value as a CLI option") from exc
    if not value:
        raise SystemExit("A value is required")
    return value


def _run(command: Sequence[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run a local command without exposing environment secrets."""
    return subprocess.run(
        list(command),
        check=check,
        text=True,
        capture_output=capture,
    )


def _require_hermes() -> None:
    if shutil.which("hermes") is None:
        raise SystemExit(
            "Hermes CLI was not found on PATH. Install Hermes first, then rerun "
            "telegram-secure-handoff setup."
        )


def _set_plugin_config(key: str, value: str) -> None:
    _run(
        [
            "hermes",
            "config",
            "set",
            "--force",
            f"plugins.entries.{PLUGIN_ID}.settings.{key}",
            value,
        ]
    )


def _read_plugin_config(key: str):
    result = _run(
        [
            "hermes",
            "config",
            "get",
            "--json",
            f"plugins.entries.{PLUGIN_ID}.settings.{key}",
        ],
        capture=True,
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return lines[-1]


def _browser_ready(cdp_url: str = DEFAULT_CDP_URL) -> bool:
    try:
        with urlopen(cdp_url.rstrip("/") + "/json/version", timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return isinstance(payload, dict) and bool(payload.get("Browser"))
    except (OSError, URLError, ValueError, json.JSONDecodeError):
        return False


def _browser_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return (
            'Start the dedicated profile with: "${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}" '
            '--remote-debugging-port=9222 --user-data-dir="$HOME/.hermes/chrome-debug" '
            "--no-first-run --no-default-browser-check"
        )
    if system == "Windows":
        return (
            'Start Chrome with --remote-debugging-port=9222 and '
            '--user-data-dir="%USERPROFILE%\\.hermes\\chrome-debug".'
        )
    return (
        'Start Chrome/Chromium with --remote-debugging-port=9222 and '
        '--user-data-dir="$HOME/.hermes/chrome-debug".'
    )


def _enable_plugin() -> None:
    _run(["hermes", "plugins", "enable", PLUGIN_ID, "--no-allow-tool-override"])


def setup(args: argparse.Namespace) -> int:
    _require_hermes()

    mini_app_url = args.mini_app_url or DEFAULT_MINI_APP_URL
    if not args.mini_app_url:
        print(f"Using official shared Mini App: {mini_app_url}")
    try:
        mini_app_url = _validate_mini_app_url(mini_app_url)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    user_values = args.user_id or [_prompt("Allowed Telegram user ID(s), comma-separated: ")]
    try:
        user_ids = _parse_user_ids(user_values)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        browser_cdp_url = _validate_browser_cdp_url(args.browser_cdp_url or DEFAULT_CDP_URL)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    _enable_plugin()
    _set_plugin_config("mini_app_url", mini_app_url)
    _set_plugin_config("allowed_user_ids", json.dumps(user_ids, separators=(",", ":")))
    _set_plugin_config("browser_cdp_url", browser_cdp_url)

    if _read_plugin_config("mini_app_url") != mini_app_url:
        raise SystemExit("Hermes did not read back the configured Mini App URL")
    if _read_plugin_config("allowed_user_ids") != user_ids:
        raise SystemExit("Hermes did not read back the configured Telegram user ID")
    if _read_plugin_config("browser_cdp_url") != browser_cdp_url:
        raise SystemExit("Hermes did not read back the configured browser CDP URL")

    if not args.skip_gateway:
        print("Launching Hermes Telegram setup. Enter the bot token only in that wizard.")
        _run(["hermes", "gateway", "setup"])

    if not args.skip_browser and not _browser_ready(browser_cdp_url):
        print("⚠ Dedicated Hermes Chrome CDP profile is not reachable yet.")
        print(_browser_hint())
        print("Then run /browser connect from the Hermes CLI, or rerun this setup check.")
    elif not args.skip_browser:
        print("✓ Dedicated Hermes Chrome CDP endpoint is reachable.")

    if not args.no_restart:
        _run(["hermes", "gateway", "restart"])

    print("\nSetup complete.")
    print(f"  Plugin: {PLUGIN_ID}")
    print(f"  Mini App: {mini_app_url}")
    print(f"  Allowed Telegram users: {len(user_ids)}")
    print("  Next: message your Telegram bot and ask Hermes to open a site that needs login.")
    return 0


def doctor(args: argparse.Namespace) -> int:
    _require_hermes()
    plugin_result = _run(["hermes", "plugins", "list"], capture=True)
    mini_app_url = _read_plugin_config("mini_app_url")
    user_ids = _read_plugin_config("allowed_user_ids")
    cdp_raw = _read_plugin_config("browser_cdp_url") or DEFAULT_CDP_URL
    try:
        validated_url = _validate_mini_app_url(mini_app_url)
    except (TypeError, ValueError):
        validated_url = None
    try:
        validated_cdp = _validate_browser_cdp_url(cdp_raw)
    except (TypeError, ValueError):
        validated_cdp = None
    owner_ok = isinstance(user_ids, list) and len(user_ids)==1 and isinstance(user_ids[0],int) and user_ids[0]>0
    browser_ok = bool(validated_cdp and _browser_ready(validated_cdp))
    result = {
        "plugin_listed": bool(plugin_result.stdout.strip()),
        "mini_app_configured": validated_url is not None,
        "owner_configured": owner_ok,
        "browser_cdp_url": validated_cdp,
        "cdp_reachable": browser_ok,
    }
    if args.json:
        print(json.dumps(result, separators=(",", ":")))
    else:
        print(plugin_result.stdout, end="")
        print(f"Mini App configured: {'yes' if result['mini_app_configured'] else 'no'}")
        print(f"One owner configured: {'yes' if result['owner_configured'] else 'no'}")
        print(f"CDP URL valid: {'yes' if validated_cdp else 'no'}")
        print(f"CDP reachable: {'yes' if browser_ok else 'no'}")
    return 0 if result["mini_app_configured"] and result["owner_configured"] and (not args.strict or browser_ok) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="telegram-secure-handoff")
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser(
        "setup",
        help="configure the plugin and optionally run Hermes Telegram setup",
    )
    setup_parser.add_argument(
        "--mini-app-url",
        help=f"HTTPS Mini App URL (default: {DEFAULT_MINI_APP_URL}; pass a self-hosted URL to override)",
    )
    setup_parser.add_argument(
        "--user-id",
        action="append",
        help="allowed numeric Telegram user ID; repeat or use comma-separated values",
    )
    setup_parser.add_argument(
        "--browser-cdp-url",
        default=DEFAULT_CDP_URL,
        help="loopback HTTP Chrome DevTools endpoint (default: http://127.0.0.1:9222)",
    )
    setup_parser.add_argument(
        "--skip-gateway",
        action="store_true",
        help="do not launch the interactive Hermes Telegram gateway wizard",
    )
    setup_parser.add_argument(
        "--skip-browser",
        action="store_true",
        help="do not check the local Chrome CDP endpoint",
    )
    setup_parser.add_argument(
        "--no-restart",
        action="store_true",
        help="do not restart the Hermes gateway after configuration",
    )
    setup_parser.set_defaults(handler=setup)

    doctor_parser = subparsers.add_parser("doctor", help="check plugin settings and the local CDP endpoint")
    doctor_parser.add_argument("--strict", action="store_true", help="fail unless the local CDP endpoint is reachable")
    doctor_parser.add_argument("--json", action="store_true", help="print a secret-free JSON result")
    doctor_parser.set_defaults(handler=doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
