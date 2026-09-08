"""General forms: synthetic values and disposable/offline browser contexts only."""
import json
from types import SimpleNamespace

import pytest

from plugin.secure_handoff import make_request, decrypt_submission
from test_checkout_flow import envelope, update, Ctx, Bot
from plugin.secure_handoff import SecureHandoffController, Session
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop
import pytest_asyncio


@pytest_asyncio.fixture
async def form_controller(tmp_path):
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel="chrome", headless=True)
        context = await browser.new_context()
        await context.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body="<main></main>"))
        page = await context.new_page()
        await page.goto("https://fixture.example/form")
        controller = SecureHandoffController(Ctx(tmp_path), browser=browser, context=context)
        controller.bot = Bot()
        session = Session(7, 8, 42, page=page, context=context)
        controller.sessions[(7, 8, 42)] = session
        try:
            yield controller, session
        finally:
            await context.close()
            await browser.close()


@pytest.mark.asyncio
async def test_explicit_form_all_controls_fill_encrypted_values_without_submit(form_controller):
    controller, session = form_controller
    kinds = [k for k in GENERIC_TYPES if k not in {"otp", "select", "textarea"}]
    html = '<form><input name="otp" autocomplete="one-time-code"><textarea name="notes"></textarea><select name="choice"><option value="a">Alpha</option><option value="b">Beta</option></select>'
    html += ''.join(f'<input type="{kind}" name="{kind}" aria-label="{kind}">' for kind in kinds)
    html += '<fieldset><legend>Plan</legend><label>First<input type="radio" name="plan" value="internal-a"></label><label>Second<input type="radio" name="plan" value="internal-b"></label></fieldset>'
    html += '<button type="submit">Register</button></form><script>window.submits=0;document.querySelector("form").onsubmit=e=>{e.preventDefault();window.submits++}</script>'
    await session.page.set_content(html)
    result = await controller._run("present", {"mode": "form"}, (7, 8, 42))
    assert result["status"] == "waiting_for_handoff"
    assert session.request["mode"] == "form"
    assert "submit" not in session.refs
    assert set(field["type"] for field in session.request["fields"]) == set(GENERIC_TYPES)
    values_by_type = {"text": "Synthetic", "email": "synthetic@example.test", "tel": "123", "number": "12", "password": "synthetic-only", "otp": "123456", "textarea": "Synthetic\nnotes", "checkbox": "true", "date": "2026-09-07", "time": "12:34", "datetime-local": "2026-09-07T12:34", "month": "2026-09", "week": "2026-W37", "url": "https://example.test", "search": "Synthetic", "color": "#123456", "range": "42"}
    values = {f["id"]: f["options"][-1]["value"] if f["type"] == "select" else values_by_type[f["type"]] for f in session.request["fields"]}
    assert "internal-a" not in json.dumps(session.request)
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(envelope(session, {"values": values})), SimpleNamespace(bot=controller.bot))
    assert session.status == "filled"
    assert session.key is None
    assert await session.page.evaluate("window.submits") == 0
    for kind in kinds:
        field = session.page.locator(f'input[name="{kind}"]')
        if kind == "checkbox":
            assert await field.is_checked()
        else:
            assert await field.input_value() == values_by_type[kind]
    assert await session.page.locator("textarea").input_value() == "Synthetic\nnotes"
    assert await session.page.locator("select").input_value() == "b"
    assert await session.page.locator('input[value="internal-b"]').is_checked()
    assert all("synthetic-only" not in str(message) for message in controller.bot.sent)



@pytest.mark.asyncio
@pytest.mark.parametrize("html", [
    '<form><textarea name="notes"></textarea><button>Save</button></form>',
    '<form><input type="email" name="email"><input type="password"><button>Register</button></form>',
    '<form><input name="title"><button>Submit</button></form>',
    '<main><input type="search" name="search"></main>',
])
async def test_automatic_generic_discovery_is_fill_only(form_controller, html):
    controller, session = form_controller
    await session.page.set_content(html)
    result = await controller._run("present", {}, (7, 8, 42))
    assert result["status"] == "waiting_for_handoff"
    assert session.request["mode"] == "form"
    assert "submit" not in session.refs


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", [
    "document.querySelector('textarea').outerHTML='<textarea name=notes></textarea>'",
    "document.querySelector('option').textContent='Changed'",
    "document.querySelector('option').value='changed'",
    "document.querySelector('textarea').setAttribute('aria-label','Changed')",
    "document.querySelector('textarea').setAttribute('readonly','')",
    "document.querySelector('textarea').parentElement.inert=true",
    "document.querySelector('textarea').parentElement.style.opacity='0'",
    "document.querySelector('textarea').parentElement.setAttribute('aria-hidden','true')",
    "document.querySelector('form').action='https://other.example'",
    "document.querySelector('form').insertAdjacentHTML('beforeend','<input name=added>')",
    "navigate_same_origin",
    "navigate_other_origin",
])
async def test_changed_form_rejected_before_decrypt(form_controller, monkeypatch, mutation):
    controller, session = form_controller
    await session.page.set_content('<form><textarea name="notes"></textarea><select><option value="a">Alpha</option></select></form>')
    assert (await controller._run("present", {"mode": "form"}, (7, 8, 42)))["status"] == "waiting_for_handoff"
    raw = envelope(session, {"values": {"f0": "Synthetic", "f1": "a"}})
    if mutation.startswith("navigate"):
        origin = "https://fixture.example" if mutation == "navigate_same_origin" else "https://other.example"
        await session.page.goto(origin + '/replacement')
        await session.page.set_content('<form><textarea name="notes"></textarea><select><option value="a">Alpha</option></select></form>')
    else:
        await session.page.evaluate(mutation)
    decrypts = []
    monkeypatch.setattr("plugin.secure_handoff.decrypt_submission", lambda *args: decrypts.append(True))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert decrypts == []
    assert session.key is None


@pytest.mark.asyncio
async def test_auth_navigation_cannot_be_rebound_before_decrypt(form_controller, monkeypatch):
    controller, session = form_controller
    html = '<form><input type="password" autocomplete="current-password"><button>Sign in</button></form>'
    await session.page.set_content(html)
    assert (await controller._run("present", {}, (7, 8, 42)))["status"] == "waiting_for_handoff"
    raw = envelope(session, {"values": {"f0": "Synthetic"}})
    await session.page.goto('https://fixture.example/replaced')
    await session.page.set_content(html)
    decrypts = []
    monkeypatch.setattr("plugin.secure_handoff.decrypt_submission", lambda *args: decrypts.append(True))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert decrypts == []


@pytest.mark.asyncio
@pytest.mark.parametrize("html", [
    '<form><input type="file"><textarea></textarea></form>',
    '<form><input type="unknown-native"><textarea></textarea></form>',
    '<form><select multiple><option>A</option></select></form>',
    '<form><div contenteditable="true">Editable</div><textarea></textarea></form>',
    '<form><div role="combobox">Custom</div><textarea></textarea></form>',
    '<form><input name="x"></form><form><textarea></textarea></form>',
    '<form><input type="radio"><input type="radio"></form>',
    '<form><input type="radio" name="plan"></form>',
    '<main><textarea></textarea><iframe src="https://other.example"></iframe></main>',
])
async def test_unsafe_generic_controls_fail_closed(form_controller, html):
    controller, session = form_controller
    await session.page.set_content(html)
    result = await controller._run("present", {"mode": "form"}, (7, 8, 42))
    assert result == {"status": "unsupported_stage", "reason": "binding_rejected"}
    assert session.key is None
    assert session.request is None


@pytest.mark.asyncio
async def test_read_never_exposes_echoed_body_text_or_safe_refs(form_controller):
    controller, session = form_controller
    await session.page.set_content('<main>synthetic-private-echo<button>synthetic-private-label</button></main>')
    result = await controller._run("read", {}, (7, 8, 42))
    assert set(result) <= {"status", "url", "reason"}
    assert 'synthetic-private' not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["click", "type"])
async def test_ordinary_actions_cannot_bypass_encrypted_handoff(form_controller, action):
    controller, session = form_controller
    await session.page.set_content('<main><input type="file"><button onclick="window.clicked=true">Buy</button></main>')
    session.refs = {"rtest": await session.page.locator("button").element_handle()}
    result = await controller._ordinary(session, action, {"ref": "rtest", "text": "synthetic"})
    assert result == {"status": "forbidden"}
    assert await session.page.evaluate("window.clicked || false") is False


@pytest.mark.asyncio
async def test_safe_diagnostics_distinguish_missing_session_and_ambiguous_target(form_controller):
    controller, session = form_controller
    assert await controller._run("present", {}, (7, 8, 99)) == {"status": "unavailable", "reason": "session_missing"}
    second = await session.context.new_page()
    await second.goto('https://fixture.example/other')
    result = await controller._run("attach", {"origin": "https://fixture.example", "mode": "form"}, (7, 8, 99))
    assert result == {"status": "unsupported_stage", "reason": "ambiguous_target"}


@pytest.mark.asyncio
async def test_cancel_requires_exact_owner_chat_thread_and_preserves_page(form_controller):
    controller, session = form_controller
    await session.page.set_content('<form><textarea name="notes"></textarea></form>')
    await controller._run("present", {"mode": "form"}, (7, 8, 42))
    request_id = session.request['id']
    wrong = update('')
    wrong.effective_message.message_thread_id = 99
    assert await controller.cancel_from_update(wrong) is False
    assert session.key is not None
    assert session.request['id'] == request_id
    assert await controller.cancel_from_update(update('')) is True
    assert (7, 8, 42) not in controller.sessions
    assert session.key is None and session.request is None
    assert not session.page.is_closed()
    assert session.status == "cancelled"


@pytest.mark.asyncio
async def test_checkout_fill_leaves_final_payment_user_owned(form_controller):
    controller, session = form_controller
    await session.page.set_content('<main><form action="/buy"><input name="cardNumber" autocomplete="cc-number"><input name="cvc" autocomplete="cc-csc"><button type="button" onclick="window.bought=true">Buy</button></form><p>USD 1</p></main>')
    await controller._run("present", {}, (7, 8, 42))
    assert session.request["mode"] == "checkout"
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(envelope(session, {"values": {"f0": "Synthetic-card", "f1": "Synthetic-cvc"}})), SimpleNamespace(bot=controller.bot))
    assert session.status == "human_action_required"
    assert session.request is None
    assert session.key is None
    assert await session.page.evaluate("window.bought || false") is False
    result = await controller._present_confirmation(session, SimpleNamespace(bot=controller.bot))
    assert result["status"] == "human_action_required"
    assert session.key is None
    assert await session.page.evaluate("window.bought || false") is False


@pytest.mark.asyncio
async def test_checkout_input_event_cannot_redirect_later_field(form_controller):
    controller, session = form_controller
    await session.page.set_content('<form action="/buy"><input name="cardNumber" autocomplete="cc-number" oninput="this.form.action=\'https://sink.example\'"><input name="cvc" autocomplete="cc-csc"><button type="button">Buy</button></form>')
    await controller._run("present", {}, (7, 8, 42))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(envelope(session, {"values": {"f0": "Synthetic-card", "f1": "Synthetic-cvc"}})), SimpleNamespace(bot=controller.bot))
    assert session.status == "rejected"
    assert await session.page.locator('[name=cvc]').input_value() == ""


@pytest.mark.asyncio
async def test_close_waits_for_apply_and_prevents_later_mutation(form_controller, monkeypatch):
    import asyncio
    controller, session = form_controller
    await session.page.set_content('<form><textarea name="notes"></textarea></form>')
    await controller._run("present", {"mode": "form"}, (7, 8, 42))
    entered, release = asyncio.Event(), asyncio.Event()
    real = controller._fill_bound_field
    async def blocked(*args):
        entered.set()
        await release.wait()
        await real(*args)
    monkeypatch.setattr(controller, '_fill_bound_field', blocked)
    task = asyncio.create_task(controller._web_data(update(envelope(session, {"values": {"f0": "Synthetic"}})), SimpleNamespace(bot=controller.bot)))
    await entered.wait()
    closing = asyncio.create_task(controller._close((7, 8, 42)))
    await asyncio.sleep(0)
    assert not closing.done()
    release.set()
    with pytest.raises(ApplicationHandlerStop):
        await task
    assert await closing == {"status": "closed"}
    assert await session.page.locator('textarea').input_value() == ""
    assert session.status == "cancelled"
    assert not session.refs and session.document is None and session.request is None


@pytest.mark.asyncio
async def test_pending_read_preserves_exact_request_and_binding(form_controller):
    controller, session = form_controller
    await session.page.set_content('<form><textarea name="notes"></textarea></form>')
    await controller._run("present", {"mode": "form"}, (7, 8, 42))
    old = session.refs['f0']
    request = session.request
    await controller._run('read', {}, (7, 8, 42))
    assert session.refs['f0'] is old
    assert session.request is request


@pytest.mark.parametrize("identity", [(7, -100123, None), (7, 8, None), (True, 1, None), (7, 7, True)])
def test_tool_requires_strict_private_owner_route(monkeypatch, identity):
    controller = SecureHandoffController(Ctx(None))
    monkeypatch.setattr(controller, '_identity', lambda: identity)
    called = []
    def submit(coro):
        coro.close()
        called.append(True)
        return {'status': 'unexpected'}
    monkeypatch.setattr(controller, '_submit', submit)
    assert json.loads(controller.tool({'action': 'read'})) == {'status': 'rejected'}
    assert not called


def test_envelope_rejects_noninteger_version_and_duplicate_outer_keys():
    request, key = make_request('https://fixture.example', [spec('text')], mode='form')
    session = SimpleNamespace(request=request, key=key)
    raw = envelope(session, {'values': {'f0': 'Synthetic'}})
    for changed in [raw.replace('"v": 3', '"v": 3.0'), raw.replace('"v": 3', '"v": 2, "v": 3')]:
        with pytest.raises(ValueError, match='^invalid submission$'):
            decrypt_submission(changed, request, key)


def test_duplicate_select_option_ids_rejected_before_publication():
    with pytest.raises(ValueError):
        make_request('https://fixture.example', [spec('select', options=[{'value':'a','label':'A'}, {'value':'a','label':'B'}])], mode='form')


def test_schema_exposes_explicit_form_mode():
    from plugin.secure_handoff import SCHEMA
    assert SCHEMA['parameters']['properties']['mode']['enum'] == ['form']


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,html,mutation", [
    ("auth", '<form action="/login"><input type="password"><button>Sign in</button></form>', "document.querySelector('form').action='/different'"),
    ("checkout", '<form><input autocomplete="cc-number"><select><option value="a">A</option></select><button type="button">Buy</button></form>', "document.querySelector('option').value='changed'"),
    ("checkout", '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"><button type="button">Buy</button></form>', "document.querySelector('button').outerHTML='<button type=button>Buy</button>'"),
])
async def test_auth_checkout_preserve_original_scope_action_and_options(form_controller, monkeypatch, mode, html, mutation):
    controller, session = form_controller
    await session.page.set_content(html)
    await controller._run('present', {}, (7, 8, 42))
    assert session.mode == mode
    raw = envelope(session, {'values': {f['id']: 'a' if f['type']=='select' else 'Synthetic' for f in session.request['fields']}})
    await session.page.evaluate(mutation)
    decrypts=[]
    monkeypatch.setattr('plugin.secure_handoff.decrypt_submission', lambda *args: decrypts.append(True))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(raw), SimpleNamespace(bot=controller.bot))
    assert session.status == 'rejected'
    assert not decrypts


@pytest.mark.asyncio
async def test_expiry_scrubs_pending_key_and_claims_late_envelope(form_controller):
    import time
    controller, session = form_controller
    await session.page.set_content('<form><textarea></textarea></form>')
    await controller._run('present', {'mode':'form'}, (7,8,42))
    request_id=session.request['id']
    session.request['expiresAt']=int(time.time()*1000)-1
    controller._expire()
    assert session.key is None
    assert session.status == 'expired'
    assert not session.refs and session.document is None
    assert controller._owns_request_id(request_id)


@pytest.mark.asyncio
async def test_two_threads_cannot_lease_same_browser_page(form_controller):
    controller, session = form_controller
    with pytest.raises(ValueError):
        await controller._attach_session((7,8,99), 'https://fixture.example')
    assert (7,8,99) not in controller.sessions


@pytest.mark.asyncio
async def test_real_deadline_expires_without_tool_polling(form_controller):
    import asyncio
    import time
    controller, session = form_controller
    await session.page.set_content('<form><textarea></textarea></form>')
    await controller._run('present', {'mode':'form'}, (7,8,42))
    session.request['expiresAt']=int(time.time()*1000)+20
    controller._arm_deadline(session)
    await asyncio.sleep(0.1)
    assert session.status == 'expired'
    assert session.key is None and session.request is None
    assert not session.refs and session.document is None


@pytest.mark.asyncio
async def test_form_terminal_state_releases_private_handles_and_deadline(form_controller):
    controller, session = form_controller
    await session.page.set_content('<form><textarea></textarea></form>')
    await controller._run('present', {'mode':'form'}, (7,8,42))
    with pytest.raises(ApplicationHandlerStop):
        await controller._web_data(update(envelope(session, {'values': {'f0':'Synthetic'}})), SimpleNamespace(bot=controller.bot))
    assert session.status == 'filled'
    assert session.deadline is None
    assert not session.refs and not session.field_parts and not session.form_controls
    assert session.document is None


def test_auth_adapter_never_suggests_purchase_actions():
    from plugin.handoff_adapters import GENERIC_ADAPTER
    from plugin.secure_handoff import CHECKOUT_ACTIONS
    assert not set(label.lower() for label in GENERIC_ADAPTER.submit_labels) & CHECKOUT_ACTIONS


@pytest.mark.parametrize('url', ['\x00https://fixture.example', 'https://fixture.example/\x7f', 'https://fixture.example:0', ' https://fixture.example', 'https://fixture.example\\@sink.example', 'https://fixture.example:invalid'])
def test_origin_rejects_unsafe_or_ambiguous_url_literals(url):
    from plugin.secure_handoff import _origin
    with pytest.raises(ValueError):
        _origin(url)


GENERIC_TYPES = (
    "text", "email", "tel", "number", "password", "otp", "select", "textarea",
    "checkbox", "date", "time", "datetime-local", "month", "week", "url", "search", "color", "range",
)


def spec(kind, **extra):
    result = {"id": "f0", "label": "Synthetic field", "type": kind, "required": False}
    if kind == "select":
        result["options"] = [{"value": "o0", "label": "First"}, {"value": "o1", "label": "Second"}]
    return result | extra


@pytest.mark.parametrize("kind", GENERIC_TYPES)
def test_form_wire_admits_native_types_without_values(kind):
    request, key = make_request("https://fixture.example", [spec(kind)], mode="form", stage="general_form")
    assert request["v"] == 3
    assert request["mode"] == "form"
    assert request["actionLabel"] == "Fill fields"
    assert request["fields"] == [spec(kind)]
    assert "value" not in request["fields"][0]
    assert key is not None


@pytest.mark.parametrize("label", ["Submit", "Buy", "Continue"])
def test_form_action_label_cannot_imply_submission(label):
    with pytest.raises(ValueError):
        make_request("https://fixture.example", [spec("text")], mode="form", action_label=label)


@pytest.mark.parametrize("kind,value,required", [
    ("checkbox", True, False), ("checkbox", "yes", False), ("checkbox", "false", True),
    ("select", "unpublished", False),
])
def test_form_decryption_rejects_invalid_choice_values(kind, value, required):
    request, key = make_request("https://fixture.example", [spec(kind, required=required)], mode="form")
    session = SimpleNamespace(request=request, key=key)
    with pytest.raises(ValueError, match="^invalid submission$"):
        decrypt_submission(envelope(session, {"values": {"f0": value}}), request, key)


@pytest.mark.parametrize("kind,value", [("checkbox", "false"), ("checkbox", "true"), ("select", "o1"), ("textarea", "Synthetic\nmessage")])
def test_form_decryption_accepts_only_encrypted_string_values(kind, value):
    request, key = make_request("https://fixture.example", [spec(kind)], mode="form")
    session = SimpleNamespace(request=request, key=key)
    assert decrypt_submission(envelope(session, {"values": {"f0": value}}), request, key) == {"f0": value}
