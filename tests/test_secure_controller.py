import os
from types import SimpleNamespace

import pytest
from playwright.async_api import async_playwright

from plugin.secure_handoff import SecureHandoffController
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
    return SecureHandoffController(Ctx(tmp_path), browser=browser, playwright=playwright, context=context, owns_browser=True)


@pytest.mark.asyncio
async def test_bind_stage_supports_generic_checkout_fields_and_payment_action(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.bot = Bot()
    identity = (7, 8, 42)
    session = None
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><form id="checkout" method="post" action="/purchase">'
            '<label>Billing name<input name="name" autocomplete="name" type="text"></label>'
            '<label>Billing email<input name="email" autocomplete="email" type="email"></label>'
            '<label>Card number<input name="cardNumber" autocomplete="cc-number" type="text"></label>'
            '<label>Expiration date<input name="expiry" autocomplete="cc-exp" type="text"></label>'
            '<label>Security code<input name="cvc" autocomplete="cc-csc" type="text"></label>'
            '<button type="submit">Buy</button></form></main>'
        )

        await controller._bind_stage(session)

        assert session.mode == "checkout"
        assert session.stage == "checkout_details"
        assert [session.ref_meta[f"f{i}"]["type"] for i in range(5)] == [
            "text", "email", "card_number", "card_expiry", "cvc"
        ]
        assert session.ref_meta["f2"]["label"] == "Card number"
        assert "submit" in session.refs
        result = await controller._present(session, SimpleNamespace(bot=None))
        assert result["status"] == "waiting_for_handoff"
        assert session.request["v"] == 3
        assert session.request["mode"] == "checkout"
        assert session.request["fields"][2]["type"] == "card_number"
        await controller._preflight(session)
    finally:
        if session is not None:
            await controller._close(identity)
        await controller._dispose(session)
        site.close()


@pytest.mark.asyncio
async def test_bind_stage_supports_checkout_fields_in_an_https_child_frame(tmp_path):
    top_site = start_demo()
    frame_site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    session = None
    try:
        session = await controller._new_session(identity, top_site.login_url, demo=True)
        await session.page.set_content(
            f'<main><div>Checkout</div><iframe title="secure payment fields" src="{frame_site.origin}/checkout-frame"></iframe>'
            '<button type="button">Pay</button></main>'
        )
        await session.page.frames[-1].wait_for_load_state("domcontentloaded")

        await controller._bind_stage(session)

        assert session.mode == "checkout"
        assert any(frame != session.page.main_frame for frame in session.field_frames.values())
        assert {meta["type"] for key, meta in session.ref_meta.items() if key.startswith("f")} == {
            "card_number", "card_expiry", "cvc"
        }
    finally:
        if session is not None:
            await controller._close(identity)
        await controller._dispose(session)
        top_site.close()
        frame_site.close()
