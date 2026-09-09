"""Real disposable HTTPS cross-frame checkout coverage (synthetic values only)."""
from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop

from plugin.demo_site import start_demo
from plugin.purchase_facts import PurchaseFactRegistry
from plugin.secure_handoff import SecureHandoffController
from test_checkout_flow import Bot, Ctx, envelope, update
from test_observed_purchase_integration import miniapp

IDENT = (7, 7, 42)


@pytest_asyncio.fixture
async def cross_frame_controller(tmp_path):
    top = start_demo()
    payment = start_demo()
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch(
        channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chrome"),
        headless=True,
    )
    context = await browser.new_context(ignore_https_errors=True)
    page = await context.new_page()
    await page.goto(top.login_url)
    await page.set_content(
        f"""
        <main>
          <form id="checkout" action="/purchase" method="post">
            <label>PRIVATE BILLING LABEL
              <input required name="billing" autocomplete="billing address-line1" type="text">
            </label>
            <textarea name="optional" aria-label="PRIVATE OPTIONAL"></textarea>
            <iframe title="payment one" src="{payment.origin}/checkout-frame"></iframe>
            <button id="buy" type="submit">Buy</button>
          </form>
        </main>
        <script>
          window.clicks = 0;
          document.querySelector('#checkout').addEventListener('submit', event => {{
            event.preventDefault(); window.clicks += 1;
          }});
        </script>
        """
    )
    await page.frames[-1].wait_for_load_state("domcontentloaded")
    await page.frames[-1].locator("input").evaluate_all("els => els.forEach(e => e.required = true)")
    controller = SecureHandoffController(
        Ctx(tmp_path),
        browser=browser,
        playwright=playwright,
        context=context,
        owns_browser=True,
    )
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    controller._identity = lambda: IDENT
    try:
        yield controller, page, payment
    finally:
        await context.close()
        await browser.close()
        await playwright.stop()
        top.close()
        payment.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(("layout", "include_optional"), [("stack", False), ("sections", True)])
async def test_real_https_child_frame_composed_entry_roundtrip_has_opaque_metadata(cross_frame_controller, layout, include_optional):
    controller, page, payment = cross_frame_controller
    attached = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"},
        )
    )
    assert attached["status"] == "attached"
    session_ref = attached["session_ref"]

    found = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "discover_components", "session_ref": session_ref},
        )
    )
    assert found["status"] == "composition_available", found
    assert len(found["refs"]) == 5
    assert sum(ref["required"] for ref in found["refs"]) == 4
    assert all(set(ref) == {"ref", "kind", "required", "ordinal", "frameOrdinal"} for ref in found["refs"])
    public = json.dumps(found)
    assert "PRIVATE" not in public
    assert payment.origin not in public
    assert "cardNumber" not in public
    assert "cc-number" not in public

    result = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {
                "action": "present_composition",
                "snapshot_ref": found["snapshot_ref"],
                "layout": layout,
                "groups":[
                    {"title":"payment", "refs":[ref["ref"] for ref in found["refs"] if ref["kind"] in {"card_number", "card_expiry", "cvc"}]},
                    {"title":"details","refs":[ref["ref"] for ref in found["refs"] if ref["kind"] == "text" and (include_optional or ref["required"]) ]},
                ],
            },
        )
    )
    assert result["status"] == "waiting_for_handoff", result
    launch = controller.bot.sent[-1]["reply_markup"].keyboard[0][0].web_app.url
    assert payment.origin not in launch
    assert "PRIVATE" not in launch
    assert "cardNumber" not in launch
    assert "cc-number" not in launch

    frame = next(frame for frame in page.frames if frame is not page.main_frame)
    assert await page.locator("input[name=billing]").input_value() == ""
    assert await page.locator("textarea").input_value() == ""
    assert await frame.locator("input").evaluate_all("els => els.every(e => e.value === '')")

    app = await miniapp(controller.sessions[IDENT], controller)
    assert await app.locator(".app-card").get_attribute("data-state") == "secureReady"
    assert await app.locator(".field-row input, .field-row textarea").evaluate_all("els => els.every(e => e.value === '')")
    values = {"f0": "synthetic billing", "f1": "synthetic optional", "f2": "synthetic card", "f3": "synthetic expiry", "f4": "synthetic cvc"}
    for field in controller.sessions[IDENT].request["fields"]:
        await app.locator("#field-" + field["id"]).fill(values[field["id"]])
    await app.get_by_role("button", name="Fill fields", exact=True).click()
    await app.wait_for_function("typeof window.sent === 'string'")
    raw = await app.evaluate("window.sent")
    assert "synthetic card" not in raw
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))

    session = controller.sessions[IDENT]
    assert session.status == "filled"
    assert await page.locator("input[name=billing]").input_value() == "synthetic billing"
    assert await page.locator("textarea").input_value() == ("synthetic optional" if include_optional else "")
    assert await frame.locator("input").evaluate_all("els => els.map(e => e.value)") == ["synthetic card", "synthetic expiry", "synthetic cvc"]
    assert await page.evaluate("window.clicks") == 0
    assert "synthetic" not in json.dumps(controller.bot.sent, default=str)
    await app.close()


async def _cross_frame_registry(session):
    registry = await PurchaseFactRegistry.create(
        owner=(session.user, session.chat, session.thread),
        session=session,
        page=session.page,
        scope=session.scope,
    )
    observation = await registry.capture_public_product(await session.page.query_selector("#catalog"))
    await registry.bind_product(observation, await session.page.query_selector("#item"))
    await registry.capture_money(await session.page.query_selector("#total"), role="displayed_total", currency="USD")
    await registry.capture_action(session.refs["submit"])
    return registry


async def _compose_cross_frame_session(controller, page):
    attached = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"},
        )
    )
    assert attached["status"] == "attached"
    found = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "discover_components", "session_ref": attached["session_ref"]},
        )
    )
    assert found["status"] == "composition_available", found
    result = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {
                "action": "present_composition",
                "snapshot_ref": found["snapshot_ref"],
                "layout": "stack",
                "groups": [
                    {"title": "payment", "refs": [
                        ref["ref"] for ref in found["refs"]
                        if ref["kind"] in {"card_number", "card_expiry", "cvc"}
                    ]},
                    {"title": "details", "refs": [
                        ref["ref"] for ref in found["refs"] if ref["kind"] == "text"
                    ]},
                ],
            },
        )
    )
    assert result["status"] == "waiting_for_handoff", result
    return controller.sessions[IDENT]


@pytest.mark.asyncio
async def test_cross_frame_parent_guard_click_consumes_and_dispatches_once(cross_frame_controller):
    controller, page, _payment = cross_frame_controller
    session = await _compose_cross_frame_session(controller, page)
    lease = await controller._pin_cross_frame_guard(session, allow_click=True)
    await page.evaluate("window.buttonClicks = 0; document.querySelector('#buy').addEventListener('click', () => window.buttonClicks += 1)")
    try:
        assert await lease.evaluate(
            "(g,a) => g.commit(a)",
            {"index": 1, "click": True, "deadline": session.request["expiresAt"]},
        ) is True
        assert await lease.parent_guard.evaluate("g => g.consumed") is True
        assert await page.evaluate("window.buttonClicks") == 1
    finally:
        await controller._release_guard(lease)


@pytest.mark.asyncio
@pytest.mark.parametrize("lose_ack", [False, True])
async def test_cross_frame_observed_purchase_approval_is_one_shot(cross_frame_controller, lose_ack):
    controller, page, payment = cross_frame_controller
    await page.set_content(
        f"""
        <p id="catalog">Example subscription</p>
        <main>
          <form id="checkout" action="/purchase" method="post">
            <input required name="billing" autocomplete="billing address-line1" type="text">
            <iframe title="payment one" src="{payment.origin}/checkout-frame"></iframe>
            <p id="item">Example subscription</p>
            <p id="total">USD 12.34</p>
            <button id="buy" type="submit">Complete purchase</button>
          </form>
        </main>
        <script>
          window.clicks = 0;
          document.querySelector('#checkout').addEventListener('submit', event => {{
            event.preventDefault(); window.clicks += 1;
          }});
        </script>
        """
    )
    await page.frames[-1].wait_for_load_state("domcontentloaded")
    await page.frames[-1].locator("input").evaluate_all("els => els.forEach(e => e.required = true)")

    attached = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "attach", "origin": page.url.split("/login")[0]},
        )
    )
    assert attached["status"] == "waiting_for_handoff"
    session = controller.sessions[IDENT]
    await controller.arm_purchase_review(session, _cross_frame_registry)
    values = {field["id"]: "synthetic-entry" for field in session.request["fields"]}
    event = update(envelope(session, {"values": values}))
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "purchase_review_ready"

    found = await controller.inspect_purchase(
        {"action": "inspect_purchase", "session_ref": session.session_ref}, IDENT
    )
    result = await controller.compose_purchase(
        {
            "action": "compose_purchase",
            "session_ref": session.session_ref,
            "revision": found["revision"],
            "fact_refs": [fact["ref"] for fact in found["facts"]],
            "action_ref": found["actions"][0]["ref"],
        },
        IDENT,
    )
    assert result["status"] == "waiting_for_confirmation", result
    raw = envelope(session, {"approve": session.request["transaction"]["id"]})
    if lose_ack:
        original = session.commit_guard

        class LostAcknowledgment:
            async def evaluate(self, expression, arg=None):
                result = await original.evaluate(expression, arg)
                if "g.commit" in expression:
                    raise ConnectionError("synthetic lost acknowledgement")
                return result

            async def dispose(self):
                await original.dispose()

        session.commit_guard = LostAcknowledgment()
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == ("outcome_unknown" if lose_ack else "purchase_submitted")
    assert await page.evaluate("window.clicks") == 1
    frame = next(frame for frame in page.frames if frame is not page.main_frame)
    assert await frame.locator("input").evaluate_all("els => els.every(e => e.value === 'synthetic-entry')")
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
    assert await page.evaluate("window.clicks") == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["document", "host", "epoch"])
async def test_cross_frame_entry_rejects_stale_child_binding(cross_frame_controller, change):
    controller, page, payment = cross_frame_controller
    session = await _compose_cross_frame_session(controller, page)
    frame = next(frame for frame in page.frames if frame is not page.main_frame)
    raw = envelope(session, {"values": {field["id"]: "synthetic-entry" for field in session.request["fields"]}})
    if change == "document":
        await frame.goto(f"{payment.origin}/checkout-frame")
    elif change == "host":
        await page.locator("iframe").evaluate("e => e.replaceWith(e.cloneNode(true))")
        await page.frames[-1].wait_for_load_state("domcontentloaded")
    else:
        await frame.locator("input").first.fill("synthetic-A")
        await frame.locator("input").first.fill("")
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert await page.locator("input[name=billing]").input_value() == ""
    replacement = next(frame for frame in page.frames if frame is not page.main_frame)
    assert await replacement.locator("input").evaluate_all("els => els.every(e => e.value === '')")


@pytest.mark.asyncio
@pytest.mark.parametrize("where", ["parent", "child"])
async def test_cross_frame_entry_rejects_same_document_history_roundtrip(cross_frame_controller, where):
    controller, page, _payment = cross_frame_controller
    session = await _compose_cross_frame_session(controller, page)
    raw = envelope(session, {"values": {field["id"]: "synthetic-entry" for field in session.request["fields"]}})
    if where == "parent":
        await page.evaluate("""() => {
            const original = location.href;
            history.pushState({}, '', original + '?history-b');
            history.replaceState({}, '', original);
        }""")
    else:
        frame = next(frame for frame in page.frames if frame is not page.main_frame)
        await frame.evaluate("""() => {
            const original = location.href;
            history.pushState({}, '', original + '?history-b');
            history.replaceState({}, '', original);
        }""")
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert await page.locator("input[name=billing]").input_value() == ""


@pytest.mark.asyncio
async def test_cross_frame_entry_expiry_and_cancel_leave_no_capability(cross_frame_controller):
    controller, page, _payment = cross_frame_controller
    session = await _compose_cross_frame_session(controller, page)
    raw = envelope(session, {"values": {field["id"]: "synthetic-entry" for field in session.request["fields"]}})
    session.request["expiresAt"] = 1
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert session.request is None and session.key is None

    session = await _compose_cross_frame_session(controller, page)
    raw = envelope(session, {"values": {field["id"]: "synthetic-entry" for field in session.request["fields"]}})
    await controller._close(IDENT)
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
    assert IDENT not in controller.sessions
    assert session.status == "cancelled"


@pytest.mark.asyncio
async def test_cross_frame_discovery_ignores_hidden_provider_helper_frame(cross_frame_controller):
    controller, page, payment = cross_frame_controller
    await page.set_content(
        f'<main><form action="/purchase"><input required autocomplete="cc-number">'
        f'<iframe title="payment fields" src="{payment.origin}/checkout-frame"></iframe>'
        f'<iframe title="invisible security helper" style="display:none" src="{payment.origin}/checkout-frame"></iframe>'
        '<button type="button">Pay</button></form></main>'
    )
    for frame in page.frames[1:]:
        await frame.wait_for_load_state("domcontentloaded")
        await frame.locator("input").evaluate_all("els => els.forEach(e => e.required = true)")
    attached = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"
    }))
    assert attached["status"] == "attached"
    found = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "discover_components", "session_ref": attached["session_ref"]
    }))
    assert found["status"] == "composition_available", found
    assert [ref["kind"] for ref in found["refs"]].count("card_number") == 2


@pytest.mark.asyncio
async def test_cross_frame_helper_becoming_visible_invalidates_lease(cross_frame_controller):
    controller, page, payment = cross_frame_controller
    await page.set_content(
        f'<main><form action="/purchase"><input required autocomplete="cc-number">'
        f'<iframe title="payment fields" src="{payment.origin}/checkout-frame"></iframe>'
        f'<iframe title="invisible security helper" style="display:none" src="{payment.origin}/checkout-frame"></iframe>'
        '<button title="Pay" type="button">Pay</button></form></main>'
    )
    for frame in page.frames[1:]:
        await frame.wait_for_load_state("domcontentloaded")
        await frame.locator("input").evaluate_all("els => els.forEach(e => e.required = true)")
    attached = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"
    }))
    found = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "discover_components", "session_ref": attached["session_ref"]
    }))
    assert found["status"] == "composition_available", found
    await page.locator("iframe").nth(1).evaluate("e => e.style.display = 'block'")
    await asyncio.sleep(0.05)
    with pytest.raises(ValueError):
        await controller.sessions[IDENT].commit_guard.evaluate("g => g.check()")


@pytest.mark.asyncio
async def test_cross_frame_allows_structural_controls_with_native_fields(cross_frame_controller):
    controller, page, payment = cross_frame_controller
    await page.set_content(
        f'<main><form action="/purchase">'
        '<div role="combobox"><input required autocomplete="billing address-line1"></div>'
        '<div role="button" tabindex="0">Choose country</div>'
        f'<iframe title="payment fields" src="{payment.origin}/checkout-frame"></iframe>'
        '<button type="button">Pay</button></form></main>'
    )
    frame = page.frames[-1]
    await frame.wait_for_load_state("domcontentloaded")
    await frame.set_content(
        '<div role="tablist">'
        '<button role="tab" aria-selected="true">Card payment</button>'
        '<button role="tab">Wallet payment</button>'
        '</div>'
        '<label>Card number<input autocomplete="cc-number" type="text"></label>'
        '<label>Expiration date<input autocomplete="cc-exp" type="text"></label>'
        '<label>Security code<input autocomplete="cc-csc" type="text"></label>'
    )
    attached = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"
    }))
    assert attached["status"] == "attached"
    found = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "discover_components", "session_ref": attached["session_ref"]
    }))
    assert found["status"] == "composition_available", found


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["custom", "blank", "canvas", "generic", "top-custom", "http"])
async def test_cross_frame_discovery_rejects_unsupported_embedded_controls(cross_frame_controller, shape):
    controller, page, payment = cross_frame_controller
    if shape in {"custom", "blank", "canvas", "generic", "top-custom"}:
        frame_markup = f'<iframe src="{payment.origin}/checkout-frame"></iframe>'
    else:
        frame_markup = '<iframe src="http://processor.example/fields"></iframe>'
    await page.set_content(
        f'<main><form action="/purchase"><input required autocomplete="cc-number">'
        + ('<div role="button" tabindex="0">Custom pay widget</div>' if shape == "top-custom" else '')
        + f'{frame_markup}'
        '<button type="button">Pay</button></form></main>'
    )
    if shape in {"custom", "blank", "canvas", "generic"}:
        frame = page.frames[-1]
        await frame.wait_for_load_state("domcontentloaded")
        child_markup = {
            "custom": '<div contenteditable="true">custom payment widget</div>',
            "blank": '<div></div>',
            "canvas": '<canvas width="300" height="80"></canvas>',
            "generic": '<div role="button" tabindex="0">Pay securely</div>',
        }[shape]
        await frame.set_content(child_markup)
    result = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "attach", "origin": page.url.split("/login")[0]},
        )
    )
    assert result["status"] == "unsupported_stage"
    assert result.get("reason") in {"binding_rejected", "frame_unsupported"}
    assert not controller.bot.sent



@pytest.mark.asyncio
async def test_cross_frame_mixed_top_select_metadata_is_opaque_and_fill_maps_private_value(cross_frame_controller):
    controller, page, _payment = cross_frame_controller
    await page.locator("form").evaluate("""form => {
        const label = document.createElement('label');
        label.textContent = 'PRIVATE TOP SELECT LABEL';
        const select = document.createElement('select');
        select.required = true;
        select.name = 'private_top_select';
        select.innerHTML = '<option value="private-option-1">PRIVATE OPTION ONE</option><option value="private-option-2">PRIVATE OPTION TWO</option>';
        label.appendChild(select);
        form.insertBefore(label, form.querySelector('iframe'));
    }""")
    attached = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"
    }))
    assert attached["status"] == "attached"
    found = json.loads(await asyncio.to_thread(controller.tool, {
        "action": "discover_components", "session_ref": attached["session_ref"]
    }))
    assert found["status"] == "composition_available", found
    session = controller.sessions[IDENT]
    select_field = next(field for field in session.request["fields"] if field["type"] == "select")
    public = json.dumps(session.request)
    assert "PRIVATE" not in public and "private-option" not in public
    assert select_field["options"] == [
        {"value": "o0", "label": "Option 1"}, {"value": "o1", "label": "Option 2"}
    ]
    raw = envelope(session, {"values": {field["id"]: ("o1" if field["id"] == select_field["id"] else "synthetic-entry") for field in session.request["fields"]}})
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert await page.locator("select[name=private_top_select]").input_value() == "private-option-2"


@pytest.mark.asyncio
async def test_cross_frame_cancel_removes_navigation_watchers(cross_frame_controller):
    controller, page, _payment = cross_frame_controller
    frame = next(frame for frame in page.frames if frame is not page.main_frame)
    await page.evaluate("() => { window.__originalPush = history.pushState; window.__originalReplace = history.replaceState; }")
    await frame.evaluate("() => { window.__originalPush = history.pushState; window.__originalReplace = history.replaceState; }")
    await _compose_cross_frame_session(controller, page)

    controller._scrub_binding(controller.sessions[IDENT])
    await asyncio.sleep(0.1)
    assert await page.evaluate("() => { const k=Symbol.for('hermes.secure_handoff.navigation'); return !window[k] && history.pushState === window.__originalPush && history.replaceState === window.__originalReplace; }")
    assert await frame.evaluate("() => { const k=Symbol.for('hermes.secure_handoff.navigation'); return !window[k] && history.pushState === window.__originalPush && history.replaceState === window.__originalReplace; }")


@pytest.mark.asyncio
async def test_cross_frame_source_acquisition_reaches_observed_approval(cross_frame_controller):
    controller, page, payment = cross_frame_controller
    await page.set_content(
        f"""
        <main>
          <form id="checkout" action="/purchase" method="post">
            <input required name="billing" autocomplete="billing address-line1" type="text">
            <div itemscope itemtype="https://schema.org/Product"><span id="item" itemprop="name">Example subscription</span></div>
            <dl><dt>Total</dt><dd>USD 12.34</dd><dt>Tax</dt><dd>USD 1.00</dd></dl>
            <iframe title="payment one" src="{payment.origin}/checkout-frame"></iframe>
            <button id="buy" type="submit">Complete purchase</button>
          </form>
        </main>
        <script>
          window.clicks = 0;
          document.querySelector('#checkout').addEventListener('submit', event => {{
            event.preventDefault(); window.clicks += 1;
          }});
        </script>
        """
    )
    await page.frames[-1].wait_for_load_state("domcontentloaded")
    await page.frames[-1].locator("input").evaluate_all("els => els.forEach(e => e.required = true)")
    catalog = await page.context.new_page()
    await catalog.goto(payment.login_url)
    await catalog.set_content(
        '<main itemscope itemtype="https://schema.org/Product">'
        '<span itemprop="name">Example subscription</span></main>'
    )

    attached = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "attach", "origin": page.url.split("/login")[0], "mode": "compose"},
        )
    )
    assert attached["status"] == "attached"
    session = controller.sessions[IDENT]
    fields = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "discover_components", "session_ref": session.session_ref},
        )
    )
    assert fields["status"] == "composition_available"
    await controller.authorize_purchase_catalog(session, catalog)
    sources = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {"action": "discover_purchase_sources", "session_ref": session.session_ref},
        )
    )
    assert sources["status"] == "purchase_sources_available", sources
    assert len(sources["refs"]) >= 4
    selected = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {
                "action": "select_purchase_sources",
                "session_ref": session.session_ref,
                "source_revision": sources["source_revision"],
                "source_refs": [ref["source_ref"] for ref in sources["refs"]],
            },
        )
    )
    assert selected["status"] == "purchase_intent_armed", selected
    composed = json.loads(
        await asyncio.to_thread(
            controller.tool,
            {
                "action": "present_composition",
                "snapshot_ref": fields["snapshot_ref"],
                "layout": "sections",
                "groups": [
                    {"title": "payment", "refs": [
                        ref["ref"] for ref in fields["refs"]
                        if ref["kind"] in {"card_number", "card_expiry", "cvc"}
                    ]},
                    {"title": "details", "refs": [
                        ref["ref"] for ref in fields["refs"] if ref["kind"] == "text"
                    ]},
                ],
            },
        )
    )
    assert composed["status"] == "waiting_for_handoff", composed
    raw = envelope(session, {"values": {field["id"]: "synthetic-entry" for field in session.request["fields"]}})
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "purchase_review_ready"
    review = await controller.inspect_purchase(
        {"action": "inspect_purchase", "session_ref": session.session_ref}, IDENT
    )
    approval = await controller.compose_purchase(
        {
            "action": "compose_purchase",
            "session_ref": session.session_ref,
            "revision": review["revision"],
            "fact_refs": [fact["ref"] for fact in review["facts"]],
            "action_ref": review["actions"][0]["ref"],
        },
        IDENT,
    )
    assert approval["status"] == "waiting_for_confirmation", approval
    raw = envelope(session, {"approve": session.request["transaction"]["id"]})
    event = update(raw)
    event.effective_chat.id = IDENT[1]
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(event, SimpleNamespace(bot=controller.bot))
    assert session.status == "purchase_submitted"
    assert await page.evaluate("window.clicks") == 1
