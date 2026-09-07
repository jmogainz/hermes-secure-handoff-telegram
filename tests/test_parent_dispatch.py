"""Parent verification of native Telegram dispatch; no network or real data."""
import base64
import json
from datetime import datetime, timezone
from types import SimpleNamespace
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from telegram import Chat, Message, MessageEntity, Update, User, WebAppData
from telegram.ext import Application, TypeHandler
from plugin.logincheck import RuntimeConfig, TelegramLoginPlugin

@pytest.mark.asyncio
async def test_native_web_app_data_returns_to_origin_and_never_reaches_observer(tmp_path, monkeypatch):
    app = Application.builder().token('123:TEST').build()
    sent, observed = [], []
    async def capture(self, *args, **kwargs):
        sent.append(kwargs)
    monkeypatch.setattr(type(app.bot), 'send_message', capture)
    # Supply bot identity without getMe/network.
    object.__setattr__(app.bot, '_bot_user', User(999, 'Test', True, username='testbot'))
    p = TelegramLoginPlugin(RuntimeConfig('https://example.test/', frozenset({7})), SimpleNamespace(data_dir=tmp_path))
    p.wire(app, None)
    async def observe(update, context):
        observed.append(update.update_id)
    app.add_handler(TypeHandler(Update, observe), group=99)
    app._initialized = True
    def message(mid, thread, **kwargs):
        m = Message(message_id=mid, date=datetime.now(timezone.utc), chat=Chat(7, 'private'), from_user=User(7, 'Tester', False), message_thread_id=thread, **kwargs)
        m.set_bot(app.bot)
        return Update(mid, message=m)
    await app.process_update(message(1, 42, text='/logincheck', entities=[MessageEntity('bot_command', 0, 11)]))
    assert not observed
    assert sent[-1]['message_thread_id'] == 42
    url = sent[-1]['reply_markup'].keyboard[0][0].web_app.url
    encoded = url.split('#request=', 1)[1]
    metadata = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    req = p._pending[metadata['id']]
    ciphertext = req.private_key.public_key().encrypt(b'telegram-roundtrip-ok', padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    raw = json.dumps({'v': 1, 'id': req.request_id, 'ciphertext': base64.urlsafe_b64encode(ciphertext).rstrip(b'=').decode()})
    await app.process_update(message(2, None, web_app_data=WebAppData(raw, 'Open connection test')))
    assert not observed
    assert sent[-1]['text'] == 'Connection test succeeded.'
    assert sent[-1]['message_thread_id'] == 42
    assert sent[-1]['reply_markup'].remove_keyboard
    assert req.private_key is None
    assert p.pending_count == 0
    receipts = list(tmp_path.glob('*.jsonl'))
    assert receipts
    for line in receipts[0].read_text().splitlines():
        row = json.loads(line)
        assert set(row) <= {'id', 'status', 'created_at', 'expires_at', 'updated_at', 'thread'}
    await app.process_update(message(3, 99, web_app_data=WebAppData(raw, 'Open connection test')))
    assert not observed
    assert sent[-1]['text'] == 'Connection test already used.'
    assert sent[-1]['message_thread_id'] == 42
    await app.process_update(message(4, 42, text='ordinary message'))
    assert observed == [4]
