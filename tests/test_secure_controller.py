import json
import os
from types import SimpleNamespace

import pytest
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop

from plugin.secure_handoff import SecureHandoffController
from plugin.demo_site import start_demo
from test_checkout_flow import envelope, update


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
async def test_checkout_uses_the_active_dialog_and_excludes_background_controls(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    session = None
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><input type="search" aria-label="Search">'
            '<button type="submit">Buy</button>'
            '<div role="dialog" style="display:block;position:fixed;inset:0">'
            '<h2>Billing Information</h2>'
            '<label>Billing name<input name="name" autocomplete="name" type="text"></label>'
            '<label>Billing email<input name="email" autocomplete="email" type="email"></label>'
            '<label>Card number<input name="cardNumber" autocomplete="cc-number" type="text"></label>'
            '<button type="submit">Buy</button></div></main>'
        )

        await controller._bind_stage(session)

        assert session.mode == "checkout"
        assert [meta["type"] for key, meta in session.ref_meta.items() if key.startswith("f")] == [
            "text", "email", "card_number"
        ]
        assert await session.page.evaluate(
            "e => e.closest('[role=\\\"dialog\\\"]') !== null", session.refs["submit"]
        ) is True
    finally:
        if session is not None:
            await controller._close(identity)
        await controller._dispose(session)
        site.close()


@pytest.mark.asyncio
async def test_checkout_omits_space_separated_autocomplete_from_public_manifest(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.bot = Bot()
    identity = (7, 8, 42)
    session = None
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><form action="/purchase">'
            '<label>Street address<input name="address1" type="text" autocomplete="billing address-line1"></label>'
            '<label>Billing email<input name="email" type="email" autocomplete="email"></label>'
            '<button type="submit">Buy</button></form></main>'
        )

        await controller._bind_stage(session)
        result = await controller._present(session, SimpleNamespace(bot=controller.bot))

        assert result["status"] == "waiting_for_handoff"
        assert "autocomplete" not in session.request["fields"][0]
    finally:
        if session is not None:
            await controller._close(identity)
        await controller._dispose(session)
        site.close()


@pytest.mark.asyncio
async def test_checkout_large_select_uses_private_exact_label_mapping(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.bot = Bot()
    identity = (7, 8, 42)
    session = None
    options = "".join(f'<option value="country-{i}">Country {i}</option>' for i in range(70))
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><form action="/purchase">'
            f'<label>Country<select name="country">{options}</select></label>'
            '<label>Billing email<input name="email" type="email" autocomplete="email"></label>'
            '<button type="submit">Buy</button></form></main>'
        )

        await controller._bind_stage(session)
        result = await controller._present(session, SimpleNamespace(bot=controller.bot))
        public_request = json.dumps(session.request)

        assert result["status"] == "waiting_for_handoff"
        country = session.request["fields"][0]
        assert country["type"] == "select"
        assert country["selectionMode"] == "search"
        assert "options" not in country
        assert "country-69" not in public_request

        with pytest.raises(ApplicationHandlerStop):
            await controller._web_data(
                update(envelope(session, {"values": {"f0": "Country 69", "f1": "synthetic@example.test"}})),
                SimpleNamespace(bot=controller.bot),
            )

        assert await session.page.locator("select").input_value() == "country-69"
        assert session.status == "human_action_required"
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
