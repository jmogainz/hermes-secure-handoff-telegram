import asyncio
import base64
import json
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from telegram import Chat, Message, Update, User
from telegram.ext import Application, ApplicationHandlerStop

from plugin.connection_check import (
    FIXED_MARKER,
    MAX_PENDING,
    RuntimeConfig,
    TelegramSecureHandoffPlugin,
    load_runtime_config,
    register,
)


@dataclass
class Ctx:
    data_dir: str

    def get_config(self, key):
        return {"mini_app_url": "https://example.test/app", "allowed_user_ids": [7]}[key]


def update(user=7, chat=70, thread=3, raw=None, command=None):
    from types import SimpleNamespace
    message = SimpleNamespace(message_thread_id=thread, web_app_data=SimpleNamespace(data=raw), text=command or raw)
    return SimpleNamespace(effective_user=SimpleNamespace(id=user), effective_chat=SimpleNamespace(id=chat, type="private"), effective_message=message)


def ptb_command(text, bot=None):
    from telegram import MessageEntity
    msg = Message(message_id=2, date=__import__("datetime").datetime.now(), chat=Chat(70, "private"), from_user=User(7, "u", False), text=text, entities=[MessageEntity(MessageEntity.BOT_COMMAND, 0, len(text))], message_thread_id=3)
    if bot is not None:
        msg.set_bot(bot)
    return Update(2, message=msg)


def plugin(tmp_path, clock=lambda: 1000.0):
    return TelegramSecureHandoffPlugin(RuntimeConfig("https://example.test/app", frozenset({7})), Ctx(str(tmp_path)), clock=clock)


def wire_payload(req, plaintext=FIXED_MARKER, key=None):
    key = key or req.private_key.public_key()
    # The private key is intentionally used only to make a real ciphertext in tests.
    public = req.private_key.public_key()
    ciphertext = public.encrypt(plaintext.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return json.dumps({"v": 1, "id": req.request_id, "ciphertext": base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()})


def test_real_rsa_success_and_replay(tmp_path):
    p = plugin(tmp_path); req = p.issue(7, 70, 3).request; raw = wire_payload(req)
    assert p.process_submission(update(raw=raw), raw).status == "success"
    assert p.process_submission(update(raw=raw), raw).status == "replay"


@pytest.mark.parametrize("case", ["wrong_sender", "wrong_chat", "malformed", "wrong_marker"])
def test_rejections(tmp_path, case):
    p = plugin(tmp_path); req = p.issue(7, 70, 3).request
    if case == "wrong_sender":
        out = p.process_submission(update(user=8, raw=wire_payload(req)), wire_payload(req))
    elif case == "wrong_chat":
        out = p.process_submission(update(chat=71, raw=wire_payload(req)), wire_payload(req))
    elif case == "malformed":
        bad = '{"v":1,"id":"%s","ciphertext":"%%"}' % req.request_id
        out = p.process_submission(update(raw=bad), bad)
    else:
        raw = wire_payload(req, "not-the-marker"); out = p.process_submission(update(raw=raw), raw)
    assert out.status == "rejected" if case in ("wrong_sender", "wrong_chat") else out.status == "invalid"


def test_expiry_cancel_and_bounded_state(tmp_path):
    now = [1000.0]; p = plugin(tmp_path, lambda: now[0])
    req = p.issue(7, 70, 3).request; now[0] += 601
    assert p.process_submission(update(raw=wire_payload(req)), wire_payload(req)).status == "expired"
    assert p.issue(7, 70, 3).status == "created"
    assert p.cancel(7) is not None
    assert p.pending_count == 0
    for i in range(MAX_PENDING):
        p.issue(100 + i, 100 + i, None)
    assert p.pending_count == MAX_PENDING
    assert p.issue(999, 999, None).status == "cap"


def test_config_fail_closed_and_register(tmp_path):
    class Bad:
        data_dir = str(tmp_path)
        def get_config(self, key): raise KeyError(key)
    assert load_runtime_config(Bad()) is None
    called = []
    class Good(Ctx):
        def register_telegram_handler(self, handler): called.append(handler)
    register(Good(str(tmp_path))); assert len(called) == 1


@pytest.mark.asyncio
async def test_process_update_stops_owned_command_and_allows_unrelated(tmp_path):
    app = Application.builder().token("123:TEST").build(); p = plugin(tmp_path); p.wire(app, None)
    events = []
    from telegram.ext import MessageHandler, filters
    async def generic(update, context): events.append("generic")
    app.add_handler(MessageHandler(filters.ALL, generic), group=0)
    async def send_message(**kwargs): pass
    app.bot.__class__.send_message = send_message
    app.bot.__class__.username = "testbot"
    app._initialized = True
    await app.process_update(ptb_command("/handoffcheck", app.bot))
    assert events == []
    await app.process_update(ptb_command("/other", app.bot))
    assert events == ["generic"]
