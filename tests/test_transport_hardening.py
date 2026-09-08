"""Synthetic transport and CLI regressions; never use live config or browsers."""
import json
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest
from telegram.ext import ApplicationHandlerStop

from plugin import cli, connection_check as transport
from plugin.config import DEFAULT_CDP_URL, validate_browser_cdp_url


def make_plugin(tmp_path):
    return transport.TelegramSecureHandoffPlugin(
        transport.RuntimeConfig("https://mini.example/app", frozenset({7})),
        SimpleNamespace(data_dir=tmp_path), clock=lambda: 1000.0,
    )


def make_update(thread=3, chat_type="private"):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=7),
        effective_chat=SimpleNamespace(id=70, type=chat_type),
        effective_message=SimpleNamespace(message_thread_id=thread),
    )


@pytest.mark.parametrize("raw", [
    '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e999}',
    '{"x":[' + '[' * 1500 + '0' + ']' * 1500 + ']}',
])
def test_json_parser_rejects_nonfinite_or_recursive_inputs(raw):
    assert transport._load_json_object(raw) is None


@pytest.mark.parametrize("version", [True, 1.0])
def test_ciphertext_version_requires_integer(version):
    raw = json.dumps({"v": version, "id": "synthetic", "ciphertext": transport._b64url_encode(bytes(256))})
    assert transport._parse_ciphertext(raw, "synthetic") is None


def test_ciphertext_parser_rejects_unpaired_surrogate():
    assert transport._parse_ciphertext('\ud800', 'synthetic') is None


@pytest.mark.parametrize("thread,chat_type", [(4, "private"), (None, "private"), (3, "group"), (True, "private")])
def test_submission_origin_requires_private_chat_and_exact_thread(tmp_path, thread, chat_type):
    p = make_plugin(tmp_path)
    req = p.issue(7, 70, 3).request
    raw = json.dumps({"v": 1, "id": req.request_id, "ciphertext": "invalid"})
    out = p.process_submission(make_update(thread, chat_type), raw)
    assert out.status == "rejected"
    assert p.pending_count == 1
    assert req.private_key is not None


def test_receipts_are_byte_bounded_and_retain_latest_record(tmp_path, monkeypatch):
    monkeypatch.setattr(transport, "MAX_RECEIPT_BYTES", 1024, raising=False)
    store = transport.ReceiptStore(SimpleNamespace(data_dir=tmp_path))
    req = transport.PendingRequest("synthetic", 7, 70, 3, 0, 10000, "https://mini.example")
    for i in range(30):
        store.append(req, "rejected", i)
    path = store.path
    assert path.stat().st_size <= 1024
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[-1]["updated_at"] == 29
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["send_error", "missing_bot", "keyboard_error"])
async def test_failed_keyboard_publication_cancels_exact_request(tmp_path, monkeypatch, failure):
    p = make_plugin(tmp_path)
    async def send_message(**kwargs):
        raise RuntimeError("synthetic send failure")
    def bad_keyboard(url):
        raise RuntimeError("synthetic keyboard failure")
    context = SimpleNamespace(bot=SimpleNamespace(send_message=send_message))
    if failure == "missing_bot":
        context = SimpleNamespace()
    if failure == "keyboard_error":
        monkeypatch.setattr(p, "_keyboard", bad_keyboard)
    with pytest.raises(ApplicationHandlerStop):
        await p.handle_handoffcheck(make_update(), context)
    assert p.pending_count == 0
    req = next(iter(p._history.values()))
    assert req.status == "publication_failed"
    assert req.private_key is None


@pytest.mark.parametrize("raw", [
    False, 0, [], b"http://localhost:9222", "", " http://localhost:9222",
    "\nhttp://localhost:9222", "http://local\thost:9222", "http://localhost:9222\n",
    "\x00http://localhost:9222", "http://localhost:0", "http://localhost:",
    "http://localhost:9222///", "http://localhost:9222\x7f",
])
def test_cdp_validation_rejects_coercion_controls_and_ambiguous_ports(raw):
    assert validate_browser_cdp_url(raw) is None


@pytest.mark.parametrize("raw,expected", [
    (None, DEFAULT_CDP_URL),
    ("http://127.0.0.1:9222/", DEFAULT_CDP_URL),
    ("http://localhost", "http://localhost:9222"),
    ("http://[::1]:9223", "http://[::1]:9223"),
])
def test_cdp_validation_preserves_documented_local_defaults(raw, expected):
    assert validate_browser_cdp_url(raw) == expected


@pytest.mark.parametrize("output,expected", [
    ('[\n  7\n]\n', [7]),
    ('{\n  "nested": [7]\n}\n', {"nested": [7]}),
    ('https://mini.example/app', None),
    ('warning\n"https://mini.example/app"', None),
])
def test_config_readback_parses_whole_json_document(monkeypatch, output, expected):
    monkeypatch.setattr(cli, "_run", lambda *a, **k: CompletedProcess(a, 0, stdout=output))
    assert cli._read_plugin_config("allowed_user_ids") == expected


@pytest.mark.parametrize("owner,listing,cdp,field", [
    ([True], '[{"name":"telegram-secure-handoff"}]', DEFAULT_CDP_URL, "owner_configured"),
    ([7], 'No plugins installed.', DEFAULT_CDP_URL, "plugin_listed"),
    ([7], '[{"name":"other","description":"telegram-secure-handoff"}]', DEFAULT_CDP_URL, "plugin_listed"),
    ([7], '[{"name":"telegram-secure-handoff-extra"}]', DEFAULT_CDP_URL, "plugin_listed"),
    ([7], '[{"name":"telegram-secure-handoff"}]', False, "browser_cdp_url"),
    ([7], '[{"name":"telegram-secure-handoff"}]', 'http://remote.example:9222', "browser_cdp_url"),
])
def test_doctor_fails_closed_on_invalid_identity_listing_or_cdp(monkeypatch, capsys, owner, listing, cdp, field):
    monkeypatch.setattr(cli, "_require_hermes", lambda: None)
    monkeypatch.setattr(cli, "_run", lambda *a, **k: CompletedProcess(a, 0, stdout=listing))
    monkeypatch.setattr(cli, "_read_plugin_config", lambda key: {
        "mini_app_url": "https://mini.example/app", "allowed_user_ids": owner,
        "browser_cdp_url": cdp,
    }[key])
    monkeypatch.setattr(cli, "_browser_ready", lambda url: True)
    status = cli.doctor(SimpleNamespace(json=True, strict=False))
    result = json.loads(capsys.readouterr().out)
    assert not result[field]
    assert status == 1


def test_register_returns_connection_instance_for_cancel_integration(tmp_path):
    handlers = []
    ctx = SimpleNamespace(
        data_dir=tmp_path, register_telegram_handler=handlers.append,
        get_config=lambda key: {"mini_app_url": "https://mini.example", "allowed_user_ids": [7]}[key],
    )
    p = transport.register(ctx)
    assert isinstance(p, transport.TelegramSecureHandoffPlugin)
    assert handlers == [p.wire]
    assert p.secure_controller is None


@pytest.mark.asyncio
async def test_cancel_delegates_to_secure_controller_and_reports_success(tmp_path):
    p = make_plugin(tmp_path)
    calls, sent = [], []
    async def cancel_from_update(update):
        calls.append(update)
        return True
    async def send_message(**kwargs):
        sent.append(kwargs)
    p.secure_controller = SimpleNamespace(cancel_from_update=cancel_from_update)
    update = make_update()
    with pytest.raises(ApplicationHandlerStop):
        await p.handle_handoffcancel(update, SimpleNamespace(bot=SimpleNamespace(send_message=send_message)))
    assert calls == [update]
    assert sent[0]["text"] == "Secure handoff cancelled."


@pytest.mark.asyncio
async def test_cancel_in_wrong_thread_preserves_connection_request(tmp_path):
    p = make_plugin(tmp_path)
    req = p.issue(7, 70, 3).request
    with pytest.raises(ApplicationHandlerStop):
        await p.handle_handoffcancel(make_update(thread=4), SimpleNamespace())
    assert p.pending_count == 1
    assert req.private_key is not None


@pytest.mark.parametrize("raw", ["\x00https://mini.example/app", "https://mini.example/\x7f", "https://mini.example:0/app"])
@pytest.mark.parametrize("validator", ["transport", "cli"])
def test_mini_app_validators_reject_controls_and_zero_port(raw, validator):
    if validator == "transport":
        assert transport._validate_mini_app_url(raw) is None
    else:
        with pytest.raises(ValueError):
            cli._validate_mini_app_url(raw)
