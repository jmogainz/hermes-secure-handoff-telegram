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

import plugin.secure_handoff as secure_handoff
from plugin.handoff_adapters import BrowserAdapter
from plugin.secure_handoff import SecureHandoffController, decrypt_submission, make_request
from plugin.demo_site import AUTHENTICATED_MARKER, start_demo


def test_secure_handoff_hybrid_roundtrip():
    fields = [{"id": "f0", "label": "Username or email", "type": "text", "required": True}]
    req, key = make_request("https://demo.example", fields, True)
    aes = b"x" * 32
    iv = b"y" * 12
    body = json.dumps({"values": {"f0": "demo"}}, separators=(",", ":")).encode()
    wrapped = key.public_key().encrypt(
        aes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    raw = json.dumps(
        {
            "v": 3,
            "id": req["id"],
            "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
            "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
            "ciphertext": base64.urlsafe_b64encode(
                AESGCM(aes).encrypt(iv, body, req["id"].encode())
            ).decode().rstrip("="),
        }
    )
    assert decrypt_submission(raw, req, key) == {"f0": "demo"}


def test_secure_handoff_rejects_missing_required():
    req, key = make_request(
        "https://demo.example",
        [{"id": "f0", "label": "Password", "type": "password", "required": True}],
    )
    with pytest.raises(ValueError):
        decrypt_submission(
            json.dumps({"v": 3, "id": req["id"], "wrappedKey": "x", "iv": "x", "ciphertext": "x"}),
            req,
            key,
        )


class Ctx:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.state = SimpleNamespace(data_dir=data_dir)

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
    browser = await playwright.chromium.launch(channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chrome"), headless=True)
    context = await browser.new_context(ignore_https_errors=True)
    return SecureHandoffController(
        Ctx(tmp_path),
        browser=browser,
        playwright=playwright,
        context=context,
        owns_browser=True,
    )


@pytest.mark.asyncio
async def test_real_chrome_encrypted_submit_reuses_demo_context_and_rejects_replay(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    try:
        result = await controller._run(
            "open",
            {"url": site.login_url, "demo": True},
            identity,
        )
        assert result["status"] == "waiting_for_handoff"
        session = controller.sessions[identity]
        session.site = site
        assert controller.bot.sent[-1]["reply_markup"]

        plaintext = json.dumps(
            {"values": {"f0": "demo", "f1": "demo-pass"}},
            separators=(",", ":"),
        ).encode()
        aes, iv = b"a" * 32, b"b" * 12
        wrapped = session.key.public_key().encrypt(
            aes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        raw = json.dumps(
            {
                "v": 3,
                "id": session.request["id"],
                "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                "ciphertext": base64.urlsafe_b64encode(
                    AESGCM(aes).encrypt(iv, plaintext, session.request["id"].encode())
                ).decode().rstrip("="),
            }
        )
        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=7),
            effective_chat=SimpleNamespace(id=8, type="private"),
            effective_message=SimpleNamespace(
                message_thread_id=42,
                web_app_data=SimpleNamespace(data=raw),
            ),
        )
        with pytest.raises(BaseException):
            await controller._web_data(update, SimpleNamespace(bot=controller.bot))
        await session.page.goto(site.account_url)
        assert AUTHENTICATED_MARKER in await session.page.locator("body").inner_text()
        assert session.status == "submitted"
        with pytest.raises(BaseException):
            await controller._web_data(update, SimpleNamespace(bot=controller.bot))
        receipt = (tmp_path / "secure_handoff_receipts.jsonl").read_text()
        assert "demo-pass" not in receipt
        assert session.request["id"] in receipt
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_bind_auth_stage_accepts_identifier_only_and_secret_only_stages(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<form method="post" action="/login">'
            '<input name="username" autocomplete="username" type="text">'
            '<input name="password" type="password" inert style="position:absolute;opacity:0;pointer-events:none">'
            '<button type="submit">Continue</button></form>'
        )
        await controller._bind_auth_stage(session)
        assert [field["type"] for field in session.ref_meta.values()] == ["text"]

        await session.page.set_content(
            '<form method="post" action="/login">'
            '<input name="password" autocomplete="current-password" type="password">'
            '<button type="submit">Sign in</button></form>'
        )
        await controller._bind_auth_stage(session)
        assert [field["type"] for field in session.ref_meta.values()] == ["password"]
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_bind_auth_stage_accepts_native_email_identifier_for_ios_autofill(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<form method="post" action="/login">'
            '<label>Email<input type="email" name="email"></label>'
            '<button type="submit">Continue</button></form>'
        )
        await controller._bind_auth_stage(session)
        assert session.ref_meta["f0"]["type"] == "email"
        assert session.stage == "identifier"
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_bind_auth_stage_supports_clickable_text_continue_control(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<form method="post" action="/login">'
            '<input name="username" autocomplete="username" type="text">'
            '<div><p>Continue</p></div></form>'
        )
        await controller._bind_auth_stage(session)
        assert "submit" in session.refs
        assert session.ref_meta["f0"]["type"] == "text"
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_bind_auth_stage_accepts_otp_with_continue_in_sibling_form(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<dialog open>'
            '<form method="post" action="/login">'
            '<input name="username" autocomplete="username" type="text" inert>'
            '<button type="submit">Continue</button></form>'
            '<form>'
            '<input autocomplete="one-time-code" inputmode="numeric" type="text">'
            '</form>'
            '</dialog>'
        )
        await controller._bind_auth_stage(session)
        assert session.ref_meta["f0"]["type"] == "otp"
        assert "submit" in session.refs
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_otp_fill_clicks_continue_when_rerender_splits_forms(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<dialog open>'
            '<form id="shell" method="post" action="/login">'
            '<button type="submit">Continue</button></form>'
            '<form id="otp"><input autocomplete="one-time-code" type="text"></form>'
            '</dialog>'
            '<script>'
            'document.querySelector("#shell").addEventListener("submit",e=>{'
            'e.preventDefault(); document.body.innerHTML="<h1>Authenticated</h1>";});'
            'document.querySelector("#otp input").addEventListener("input",()=>{'
            'const otp=document.querySelector("#otp");'
            'const next=otp.cloneNode(true); otp.replaceWith(next);'
            '});'
            '</script>'
        )
        first = await controller._snapshot(session)
        assert first["status"] == "waiting_for_handoff"
        assert [f["type"] for f in session.request["fields"]] == ["otp"]
        aes, iv = b"e" * 32, b"f" * 12
        body = json.dumps({"values": {session.request["fields"][0]["id"]: "123456"}}).encode()
        wrapped = session.key.public_key().encrypt(
            aes,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        raw = json.dumps(
            {
                "v": 3,
                "id": session.request["id"],
                "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                "ciphertext": base64.urlsafe_b64encode(
                    AESGCM(aes).encrypt(iv, body, session.request["id"].encode())
                ).decode().rstrip("="),
            }
        )
        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=7),
            effective_chat=SimpleNamespace(id=8, type="private"),
            effective_message=SimpleNamespace(message_thread_id=42, web_app_data=SimpleNamespace(data=raw)),
        )
        with pytest.raises(BaseException):
            await controller._web_data(update, SimpleNamespace(bot=controller.bot))
        assert session.status == "submitted"
        assert await session.page.locator("h1").inner_text() == "Authenticated"
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_identifier_then_password_mints_fresh_requests_and_reuses_page(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<form id="login" method="post" action="/login">'
            '<input name="username" autocomplete="username" type="text">'
            '<button type="submit">Continue</button></form>'
            '<script>const f=document.querySelector("#login");'
            'f.addEventListener("submit",e=>{e.preventDefault();'
            'if(f.querySelector("input").type==="text"){'
            "f.innerHTML='<input name=\"password\" autocomplete=\"current-password\" type=\"password\"><button type=\"submit\">Sign in</button>';"
            '}else{document.body.innerHTML="<h1>Authenticated</h1>";}});</script>'
        )
        first = await controller._snapshot(session)
        assert first["status"] == "waiting_for_handoff"
        assert [f["type"] for f in session.request["fields"]] == ["text"]
        first_id = session.request["id"]
        # X can replace the React form nodes while the Mini App is open.
        await session.page.evaluate("""() => {
            const oldForm = document.querySelector('#login');
            const form = oldForm.cloneNode(true);
            oldForm.replaceWith(form);
            form.addEventListener('submit', event => {
                event.preventDefault();
                if (form.querySelector('input').type === 'text') {
                    form.innerHTML = '<input name="password" autocomplete="current-password" type="password"><button type="submit">Sign in</button>';
                } else {
                    document.body.innerHTML = '<h1>Authenticated</h1>';
                }
            });
        }""")
        await session.page.locator('#login input').evaluate("input => input.addEventListener('input', () => { const oldButton = input.form.querySelector('button'); const button = oldButton.cloneNode(true); oldButton.replaceWith(button); })")

        def envelope(value):
            aes, iv = b"a" * 32, b"b" * 12
            body = json.dumps({"values": {session.request["fields"][0]["id"]: value}}).encode()
            wrapped = session.key.public_key().encrypt(
                aes,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return json.dumps(
                {
                    "v": 3,
                    "id": session.request["id"],
                    "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                    "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                    "ciphertext": base64.urlsafe_b64encode(
                        AESGCM(aes).encrypt(iv, body, session.request["id"].encode())
                    ).decode().rstrip("="),
                }
            )

        def web_update(raw):
            return SimpleNamespace(
                effective_user=SimpleNamespace(id=7),
                effective_chat=SimpleNamespace(id=8, type="private"),
                effective_message=SimpleNamespace(
                    message_thread_id=42,
                    web_app_data=SimpleNamespace(data=raw),
                ),
            )

        with pytest.raises(BaseException):
            await controller._web_data(web_update(envelope("demo")), SimpleNamespace(bot=controller.bot))
        assert session.status == "waiting_for_handoff"
        assert session.request["id"] != first_id
        assert [f["type"] for f in session.request["fields"]] == ["password"]
        second_id = session.request["id"]

        with pytest.raises(BaseException):
            await controller._web_data(web_update(envelope("demo-pass")), SimpleNamespace(bot=controller.bot))
        assert session.status == "submitted"
        assert session.request["id"] == second_id
        assert await session.page.locator("h1").inner_text() == "Authenticated"
        assert len([message for message in controller.bot.sent if message.get("reply_markup")]) == 2
        assert controller.bot.sent[-1]["text"] == "Secure handoff action submitted."
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_password_only_form_uses_one_secure_request(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<form method="post" action="/login">'
            '<input name="password" autocomplete="current-password" type="password">'
            '<button type="submit">Sign in</button></form>'
            '<script>document.querySelector("form").addEventListener("submit",e=>{e.preventDefault();document.body.innerHTML="<h1>Authenticated</h1>";});</script>'
        )
        result = await controller._snapshot(session)
        assert result["status"] == "waiting_for_handoff"
        assert [f["type"] for f in session.request["fields"]] == ["password"]
        aes, iv = b"c" * 32, b"d" * 12
        body = json.dumps({"values": {session.request["fields"][0]["id"]: "demo-pass"}}).encode()
        wrapped = session.key.public_key().encrypt(
            aes,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        raw = json.dumps(
            {
                "v": 3,
                "id": session.request["id"],
                "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                "ciphertext": base64.urlsafe_b64encode(AESGCM(aes).encrypt(iv, body, session.request["id"].encode())).decode().rstrip("="),
            }
        )
        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=7),
            effective_chat=SimpleNamespace(id=8, type="private"),
            effective_message=SimpleNamespace(message_thread_id=42, web_app_data=SimpleNamespace(data=raw)),
        )
        with pytest.raises(BaseException):
            await controller._web_data(update, SimpleNamespace(bot=controller.bot))
        assert session.status == "submitted"
        assert await session.page.locator("h1").inner_text() == "Authenticated"
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_formless_adapter_binding_is_generic_and_preflighted(tmp_path, monkeypatch):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.bot = Bot()
    identity = (7, 8, 42)

    class FormlessCodeAdapter(BrowserAdapter):
        def classify_input(self, metadata):
            if metadata.get("type") == "tel" and metadata.get("name") == "pin":
                return "otp"
            return super().classify_input(metadata)

    adapter = FormlessCodeAdapter("fixture-formless", (), ("Next",), True)
    monkeypatch.setattr(secure_handoff, "adapter_for_url", lambda _url: adapter)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        await session.page.set_content(
            '<main><input type="tel" name="Pin" aria-label="Enter code">'
            '<button type="button" formAction="/verify">Next</button></main>'
        )
        await controller._bind_auth_stage(session)
        assert session.form is None
        assert session.ref_meta["f0"]["type"] == "otp"
        await controller._present(session, SimpleNamespace(bot=controller.bot))
        await controller._preflight(session)
    finally:
        await controller._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_split_otp_digits_auto_submit_without_submit_control(tmp_path):
    site = start_demo()
    controller = await disposable_controller(tmp_path)
    controller.loop = asyncio.get_running_loop()
    controller.bot = Bot()
    identity = (7, 8, 42)
    try:
        session = await controller._new_session(identity, site.login_url, demo=True)
        digits = "".join(
            f'<input type="text" inputmode="numeric" maxlength="1" aria-label="digit {index} of 6">'
            for index in range(1, 7)
        )
        await session.page.set_content(
            f'<form id="otp" method="post" action="/verify">{digits}</form>'
            '<script>'
            'const form=document.querySelector("#otp");'
            'const inputs=()=>[...form.querySelectorAll("input")];'
            'inputs().forEach((input,index)=>input.addEventListener("input",()=>{'
            'if(index===5 && input.value) document.body.innerHTML="<h1>Authenticated</h1>";'
            '}));'
            '</script>'
        )
        first = await controller._snapshot(session)
        assert first["status"] == "waiting_for_handoff"
        assert session.request is not None
        request = session.request
        assert [f["type"] for f in request["fields"]] == ["otp"]
        assert session.auto_submit is True
        assert len(session.field_parts["f0"]) == 6

        aes, iv = b"g" * 32, b"h" * 12
        body = json.dumps({"values": {request["fields"][0]["id"]: "123456"}}).encode()
        wrapped = session.key.public_key().encrypt(
            aes,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        raw = json.dumps(
            {
                "v": 3,
                "id": session.request["id"],
                "wrappedKey": base64.urlsafe_b64encode(wrapped).decode().rstrip("="),
                "iv": base64.urlsafe_b64encode(iv).decode().rstrip("="),
                "ciphertext": base64.urlsafe_b64encode(
                    AESGCM(aes).encrypt(iv, body, session.request["id"].encode())
                ).decode().rstrip("="),
            }
        )
        update = SimpleNamespace(
            effective_user=SimpleNamespace(id=7),
            effective_chat=SimpleNamespace(id=8, type="private"),
            effective_message=SimpleNamespace(message_thread_id=42, web_app_data=SimpleNamespace(data=raw)),
        )
        with pytest.raises(BaseException):
            await controller._web_data(update, SimpleNamespace(bot=controller.bot))
        assert session.status == "submitted"
        assert await session.page.locator("h1").inner_text() == "Authenticated"
    finally:
        await controller._close(identity)
        site.close()
