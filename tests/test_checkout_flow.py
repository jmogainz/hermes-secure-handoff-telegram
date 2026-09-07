import asyncio
import base64
import json
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop

from plugin.browser_login import BrowserController
from plugin.demo_site import start_demo


class Ctx:
    def __init__(self, path):
        self.data_dir = path
        self.state = SimpleNamespace(data_dir=path)

    def get_config(self, name):
        return {
            "allowed_user_ids": [7],
            "mini_app_url": "https://mini.example/app",
            "browser_cdp_url": "http://127.0.0.1:9222",
        }[name]


class Bot:
    def __init__(self):
        self.sent = []

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return SimpleNamespace(message_id=len(self.sent))


async def disposable_controller(tmp_path):
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(
        channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chrome"),
        headless=True,
    )
    context = await browser.new_context(ignore_https_errors=True)
    return BrowserController(Ctx(tmp_path), browser=browser, playwright=playwright, context=context, owns_browser=True)


def envelope(session, body):
    aes = b"a" * 32
    iv = b"b" * 12
    plaintext = json.dumps(body, separators=(",", ":")).encode()
    wrapped = session.key.public_key().encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return json.dumps({
        "v": session.request["v"],
        "id": session.request["id"],
        "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
        "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
        "ciphertext": base64.urlsafe_b64encode(
            AESGCM(aes).encrypt(iv, plaintext, session.request["id"].encode())
        ).decode().rstrip("="),
    })


def update(raw):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=7),
        effective_chat=SimpleNamespace(id=8, type="private"),
        effective_message=SimpleNamespace(
            message_thread_id=42,
            web_app_data=SimpleNamespace(data=raw),
        ),
    )


@pytest.mark.asyncio
async def test_checkout_requires_fresh_confirmation_before_payment_action(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    session = None
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><form id="checkout" method="post" action="/purchase">'
            '<input name="cardNumber" autocomplete="cc-number" type="text">'
            '<input name="expiry" autocomplete="cc-exp" type="text">'
            '<input name="cvc" autocomplete="cc-csc" type="text">'
            '<button id="buy" type="submit">Buy</button></form>'
            '<script>window.__purchaseClicks=0; document.querySelector("#checkout").addEventListener("submit", event => {'
            'event.preventDefault(); window.__purchaseClicks += 1; document.body.innerHTML="<h1>Purchase accepted</h1>";});</script></main>'
        )
        first = await controller._snapshot(session)
        assert first["status"] == "waiting_for_login"
        assert session.request["v"] == 3
        assert session.request["mode"] == "checkout"
        first_request_id = session.request["id"]
        values = {field["id"]: f"synthetic-{field['type']}" for field in session.request["fields"]}

        with pytest.raises(ApplicationHandlerStop):
            await controller._web_data(
                update(envelope(session, {"values": values})),
                SimpleNamespace(bot=controller.bot),
            )

        assert session.status == "waiting_for_confirmation"
        assert session.request["id"] != first_request_id
        assert session.request["mode"] == "payment_confirmation"
        assert session.request["fields"] == []
        assert await session.page.evaluate("window.__purchaseClicks") == 0

        with pytest.raises(ApplicationHandlerStop):
            await controller._web_data(
                update(envelope(session, {"confirm": True})),
                SimpleNamespace(bot=controller.bot),
            )

        assert session.status == "submitted"
        assert await session.page.evaluate("window.__purchaseClicks") == 1
        assert await session.page.locator("h1").inner_text() == "Purchase accepted"
    finally:
        if session is not None:
            await controller._close(identity)
        await controller._dispose(session)
        site.close()
