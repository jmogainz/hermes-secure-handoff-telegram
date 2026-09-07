from __future__ import annotations

import json
import tomllib
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from plugin import cli

ROOT = Path(__file__).parents[1]


def test_distribution_metadata_exposes_namespaced_hermes_entry_point():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata["project"]
    assert project["name"] == "hermes-telegram-browser-login"
    assert project["entry-points"]["hermes_agent.plugins"]["telegram-browser-login"] == (
        "hermes_telegram_browser_login:register"
    )
    assert project["scripts"]["telegram-browser-login"] == "hermes_telegram_browser_login.cli:main"
    assert metadata["tool"]["setuptools"]["package-dir"]["hermes_telegram_browser_login"] == "plugin"


def test_directory_and_package_manifests_stay_in_sync():
    assert (ROOT / "plugin.yaml").read_text(encoding="utf-8") == (
        ROOT / "plugin" / "plugin.yaml"
    ).read_text(encoding="utf-8")


def test_setup_validation_rejects_non_https_or_ambiguous_urls():
    assert cli._validate_mini_app_url("https://example.test/app") == "https://example.test/app"
    with pytest.raises(ValueError):
        cli._validate_mini_app_url("http://example.test/app")
    with pytest.raises(ValueError):
        cli._validate_mini_app_url("https://example.test/app?request=secret")
    with pytest.raises(ValueError):
        cli._validate_mini_app_url("https://user:pass@example.test/app")


def test_setup_validation_deduplicates_numeric_owner_id():
    assert cli._parse_user_ids(["7, 7"]) == [7]
    with pytest.raises(ValueError):
        cli._parse_user_ids(["7, 8"])
    with pytest.raises(ValueError):
        cli._parse_user_ids(["alice"])
    with pytest.raises(ValueError):
        cli._parse_user_ids([])


def test_setup_validation_rejects_remote_cdp():
    assert cli._validate_browser_cdp_url("http://127.0.0.1:9222") == "http://127.0.0.1:9222"
    assert cli._validate_browser_cdp_url("http://localhost:9223") == "http://localhost:9223"
    for value in (
        "https://127.0.0.1:9222",
        "http://192.0.2.1:9222",
        "ws://127.0.0.1:9222",
        "http://user:pass@127.0.0.1:9222",
    ):
        with pytest.raises(ValueError):
            cli._validate_browser_cdp_url(value)


def test_browser_controller_fails_closed_for_invalid_runtime_settings():
    from plugin.browser_login import BrowserController

    class InvalidContext:
        def get_config(self, key):
            return {
                "mini_app_url": "https://mini.example/app?untrusted=1",
                "allowed_user_ids": [7, 8],
                "browser_cdp_url": "http://192.0.2.1:9222",
            }[key]

    controller = BrowserController(InvalidContext())
    assert controller.config is None
    assert controller._owners() == set()
    with pytest.raises(ValueError):
        controller._configured_cdp_url()


def test_setup_uses_official_shared_mini_app_by_default(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/local/bin/hermes")
    monkeypatch.setattr(cli, "_read_plugin_config", lambda key: {
        "mini_app_url": cli.DEFAULT_MINI_APP_URL,
        "allowed_user_ids": [7],
        "browser_cdp_url": cli.DEFAULT_CDP_URL,
    }[key])

    def fake_run(command, *, check=True, capture=False):
        calls.append(list(command))
        return CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_run", fake_run)
    args = cli.build_parser().parse_args([
        "setup", "--user-id", "7", "--skip-gateway", "--skip-browser", "--no-restart",
    ])
    assert cli.setup(args) == 0
    assert [
        "hermes", "config", "set", "--force",
        "plugins.entries.telegram-browser-login.settings.mini_app_url",
        cli.DEFAULT_MINI_APP_URL,
    ] in calls


def test_setup_writes_namespaced_settings_and_verifies_them(monkeypatch, capsys):
    calls: list[list[str]] = []

    monkeypatch.setattr(cli.shutil, "which", lambda _name: "/usr/local/bin/hermes")
    monkeypatch.setattr(cli, "_browser_ready", lambda _url: True)
    monkeypatch.setattr(cli, "_read_plugin_config", lambda key: {
        "mini_app_url": "https://mini.example/app",
        "allowed_user_ids": [7],
        "browser_cdp_url": "http://localhost:9223",
    }[key])

    def fake_run(command, *, check=True, capture=False):
        calls.append(list(command))
        return CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(cli, "_run", fake_run)
    args = cli.build_parser().parse_args([
        "setup",
        "--mini-app-url",
        "https://mini.example/app/",
        "--user-id",
        "7",
        "--browser-cdp-url",
        "http://localhost:9223",
        "--skip-gateway",
        "--no-restart",
    ])

    assert cli.setup(args) == 0
    assert ["hermes", "plugins", "enable", "telegram-browser-login", "--no-allow-tool-override"] in calls
    assert [
        "hermes", "config", "set", "--force",
        "plugins.entries.telegram-browser-login.settings.mini_app_url",
        "https://mini.example/app",
    ] in calls
    allowed_call = next(
        call for call in calls
        if "settings.allowed_user_ids" in " ".join(call)
    )
    assert json.loads(allowed_call[-1]) == [7]
    cdp_call = next(call for call in calls if "settings.browser_cdp_url" in " ".join(call))
    assert cdp_call[-1] == "http://localhost:9223"
    assert "bot token" not in capsys.readouterr().out.lower()
