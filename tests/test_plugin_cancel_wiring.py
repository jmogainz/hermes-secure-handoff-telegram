"""The owner command surface must cancel the real secure handoff too."""
from types import SimpleNamespace

import plugin


def test_plugin_wires_connection_cancel_to_secure_controller(monkeypatch):
    connection = SimpleNamespace()
    secure = SimpleNamespace()
    monkeypatch.setattr(plugin, "register_connection_check", lambda ctx: connection)
    monkeypatch.setattr(plugin, "register_secure_handoff", lambda ctx: secure)
    assert plugin.register(object()) is secure
    assert getattr(connection, "secure_controller", None) is secure


def test_invalid_connection_config_does_not_break_registration(monkeypatch):
    monkeypatch.setattr(plugin, "register_connection_check", lambda ctx: None)
    monkeypatch.setattr(plugin, "register_secure_handoff", lambda ctx: None)
    assert plugin.register(object()) is None
