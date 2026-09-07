"""Parent gate: deployed UI -> native plugin -> shared browser controller, synthetic only."""
import asyncio
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright
from telegram.ext import ApplicationHandlerStop
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from plugin.secure_handoff import SecureHandoffController
from plugin.demo_site import start_demo


class Ctx:
    def __init__(self, path):
        self.data_dir = path
        self.state = SimpleNamespace(data_dir=path)

    def get_config(self, key):
        return {
            "allowed_user_ids": [7],
            "mini_app_url": "https://fixture-mini.example/",
            "browser_cdp_url": "http://127.0.0.1:9222",
        }[key]


class Bot:
    def __init__(self):
        self.sent = []

    async def send_message(self, **kw):
        self.sent.append(kw)
        return SimpleNamespace(message_id=len(self.sent))


WEB_ROOT = Path(__file__).parents[1] / "web"


async def serve_mini_app(route):
    relative = urlsplit(route.request.url).path.lstrip("/") or "index.html"
    if relative not in {"index.html", "app.js", "styles.css"}:
        await route.fulfill(status=404, body="Not found")
        return
    content_type = {
        "index.html": "text/html; charset=utf-8",
        "app.js": "application/javascript; charset=utf-8",
        "styles.css": "text/css; charset=utf-8",
    }[relative]
    await route.fulfill(
        status=200,
        content_type=content_type,
        body=(WEB_ROOT / relative).read_bytes(),
    )


async def serve_telegram_sdk(route):
    await route.fulfill(
        status=200,
        content_type="application/javascript",
        body=(
            "window.Telegram={WebView:{initParams:{tgWebAppData:''}},"
            "WebApp:{platform:'tdesktop',initData:'',initDataUnsafe:{},"
            "ready(){},sendData(v){window.TelegramWebviewProxy.postEvent('web_app_data_send',JSON.stringify({data:v}))}}}"
        ),
    )


async def disposable_controller(path):
    pw = await async_playwright().start()
    browser = await pw.chromium.launch(channel=os.environ.get("PLAYWRIGHT_CHANNEL", "chrome"), headless=True)
    context = await browser.new_context(ignore_https_errors=True)
    return SecureHandoffController(Ctx(path), browser=browser, playwright=pw, context=context, owns_browser=True)


def update(text=None, data=None, thread=42, user=7):
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user),
        effective_chat=SimpleNamespace(id=7, type="private"),
        effective_message=SimpleNamespace(
            text=text,
            message_thread_id=thread,
            web_app_data=SimpleNamespace(data=data),
        ),
    )


@pytest.mark.asyncio
async def test_deployed_form_native_demo_roundtrip(tmp_path):
    c = await disposable_controller(tmp_path)
    c.loop = asyncio.get_running_loop()
    c.bot = Bot()
    site = start_demo()
    ui_context = None
    identity = (7, 7, 42)
    try:
        result = await c._run("open", {"url": site.login_url, "demo": True}, identity)
        assert result["status"] == "waiting_for_handoff"
        session = c.sessions[identity]
        prompt = next(m for m in reversed(c.bot.sent) if m.get("reply_markup"))
        assert prompt["message_thread_id"] == 42
        launch = prompt["reply_markup"].keyboard[0][0].web_app.url
        assert session.request and session.request["v"] == 3

        ui_context = await c._browser.new_context(viewport={"width": 375, "height": 812})
        ui = await ui_context.new_page()
        await ui.route("https://fixture-mini.example/**", serve_mini_app)
        await ui.route("https://telegram.org/js/telegram-web-app.js", serve_telegram_sdk)
        await ui.add_init_script(
            "window.__sent=[];window.TelegramWebviewProxy={postEvent:(kind,data)=>{"
            "if(kind==='web_app_data_send')window.__sent.push(JSON.parse(data).data)}};"
        )
        await ui.goto(
            launch + "&tgWebAppVersion=9.6&tgWebAppPlatform=ios&tgWebAppThemeParams=%7B%7D",
            wait_until="networkidle",
        )
        await ui.wait_for_function("document.querySelector('.app-card')?.dataset.state==='secureReady'")
        for f in session.request["fields"]:
            await ui.locator("#field-" + f["id"]).fill(
                "demo-pass" if f["type"] == "password" else "demo"
            )
        assert not await ui.evaluate("document.documentElement.scrollWidth>innerWidth")
        await ui.locator("#send-button").click()
        await ui.wait_for_function("window.__sent.length===1")
        raw = await ui.evaluate("window.__sent[0]")
        assert json.loads(raw)["v"] == 3
        with pytest.raises(ApplicationHandlerStop):
            await c._web_data(update(data=raw, thread=42), SimpleNamespace(bot=c.bot))
        assert session.status == "submitted"
        await session.page.goto(site.account_url)
        result = await c._run("read", {}, identity)
        assert "Demo account verified" in result.get("text", "")
        assert "demo-pass" not in json.dumps(result)
        assert session.context is c._context
        assert session.key is None
    finally:
        if ui_context:
            await ui_context.close()
        await c._close(identity)
        site.close()


@pytest.mark.asyncio
async def test_real_agent_controls_prompt_wait_type_click_and_stale_refs(tmp_path):
    c = await disposable_controller(tmp_path)
    c.loop = asyncio.get_running_loop()
    c.bot = Bot()
    site = start_demo()
    ident = (7, 7, 42)
    enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    try:
        result = await c._run("open", {"url": site.login_url, "demo": True}, ident)
        assert result["status"] == "waiting_for_handoff"
        assert len(c.bot.sent) == 1
        s = c.sessions[ident]
        assert (await c._run("read", {}, ident))["status"] == "waiting_for_handoff"
        assert len(c.bot.sent) == 1
        waiter = asyncio.create_task(c._run("wait", {"timeout": 3}, ident))
        await asyncio.sleep(0)
        aes, iv = b"a" * 32, b"b" * 12
        values = {f["id"]: ("demo-pass" if f["type"] == "password" else "demo") for f in s.request["fields"]}
        wrapped = s.key.public_key().encrypt(
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
                "id": s.request["id"],
                "wrappedKey": enc(wrapped),
                "iv": enc(iv),
                "ciphertext": enc(
                    AESGCM(aes).encrypt(
                        iv,
                        json.dumps({"values": values}).encode(),
                        s.request["id"].encode(),
                    )
                ),
            }
        )
        with pytest.raises(ApplicationHandlerStop):
            await asyncio.wait_for(c._web_data(update(data=raw, thread=42), SimpleNamespace(bot=c.bot)), 2)
        assert (await asyncio.wait_for(waiter, 1))["status"] == "submitted"
        await s.page.goto(site.account_url)
        assert "Demo account verified" in (await c._run("read", {}, ident))["text"]
        await s.page.set_content(
            '<main><p id="result">Ready</p><input type="search" id="query">'
            "<button id=\"go\" onclick=\"document.querySelector('#result').textContent='Clicked'\">Go</button></main>"
        )
        snap = await c._run("read", {}, ident)
        ref = next(k for k, v in snap["refs"].items() if v["tag"] == "input")
        typed = await c._run("type", {"ref": ref, "text": "synthetic-search"}, ident)
        assert await s.page.locator("#query").input_value() == "synthetic-search"
        assert "synthetic-search" not in json.dumps(typed)
        button = next(k for k, v in typed["refs"].items() if v["text"] == "Go")
        clicked = await c._run("click", {"ref": button}, ident)
        assert "Clicked" in clicked["text"]
        stale = next(k for k, v in clicked["refs"].items() if v["text"] == "Go")
        await s.page.locator("#go").evaluate("e => e.replaceWith(e.cloneNode(true))")
        assert (await c._run("click", {"ref": stale}, ident))["status"] == "stale_ref"
    finally:
        await c._close(ident)
        site.close()
