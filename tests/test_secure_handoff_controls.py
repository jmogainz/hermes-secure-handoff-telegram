import asyncio
import json
from urllib.request import urlopen
from types import SimpleNamespace

import pytest

from plugin.secure_handoff import SecureHandoffController, Session


class Ctx:
    def get_config(self, name):
        return {"allowed_user_ids": [7], "mini_app_url": "https://mini.example/app"}[name]


class Bot:
    def __init__(self, result=True):
        self.sent = []
        self.result = result

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return self.result


@pytest.mark.asyncio
async def test_attaches_to_running_hermes_chrome_without_owning_or_closing_it():
    controller = SecureHandoffController(Ctx())
    await controller._ensure_runtime()
    assert controller._cdp_url == "http://127.0.0.1:9222"
    assert controller._browser is not None
    assert controller._browser.contexts
    await controller._dispose(Session(7, 8, None))
    with urlopen("http://127.0.0.1:9222/json/version", timeout=3) as response:
        assert response.status == 200


@pytest.mark.asyncio
async def test_wait_releases_lock_for_concurrent_submit_and_close_wakes_waiter():
    controller = SecureHandoffController(Ctx())
    session = Session(7, 8, None, wake=asyncio.Event())
    controller.sessions[(7, 8, None)] = session

    waiting = asyncio.create_task(controller._run("wait", {"timeout": 2}, (7, 8, None)))
    await asyncio.sleep(0)
    async with session.lock:
        session.status = "submitted"
        session.wake.set()
    assert await asyncio.wait_for(waiting, 1) == {"status": "submitted"}

    session = Session(7, 8, None, wake=asyncio.Event())
    session.key = object()
    controller.sessions[(7, 8, None)] = session
    waiting = asyncio.create_task(controller._run("wait", {"timeout": 2}, (7, 8, None)))
    await asyncio.sleep(0)
    assert await controller._close((7, 8, None)) == {"status": "closed"}
    assert await asyncio.wait_for(waiting, 1) == {"status": "cancelled"}
    assert session.key is None


def test_tool_rejects_user_outside_native_allowed_scope(monkeypatch):
    controller = SecureHandoffController(Ctx())
    monkeypatch.setattr(controller, "_identity", lambda: (99, 8, None))
    assert json.loads(controller.tool({"action": "read"})) == {"status": "rejected"}


@pytest.mark.asyncio
async def test_replaced_safe_ref_is_rejected_without_action():
    class Locator:
        async def count(self):
            return 0

        async def all(self):
            return []

    class Page:
        def locator(self, _):
            return Locator()

        async def evaluate(self, _script, _args):
            return True

    class Handle:
        async def is_visible(self):
            return True

        async def is_enabled(self):
            return True

        async def click(self, **_):
            raise AssertionError("detached ref must never be clicked")

    controller = SecureHandoffController(Ctx())
    session = Session(7, 8, None, page=Page())
    session.refs = {"rgen": Handle()}
    assert await controller._ordinary(session, "click", {"ref": "rgen"}) == {"status": "stale_ref"}


@pytest.mark.asyncio
async def test_open_binds_auth_and_publishes_in_existing_session(monkeypatch):
    controller = SecureHandoffController(Ctx())
    controller.bot = Bot()
    monkeypatch.setattr(controller, "_identity", lambda: (7, 8, None))

    class Page:
        url = "https://fixture.example/login"

    async def new_session(identity, url, demo=False):
        session = Session(*identity, page=Page(), context=SimpleNamespace(close=lambda: None), wake=asyncio.Event())
        controller.sessions[identity] = session
        return session

    async def bind(session):
        session.ref_meta = {
            "f0": {"label": "Password", "type": "password", "required": True}
        }

    monkeypatch.setattr(controller, "_new_session", new_session)
    monkeypatch.setattr(controller, "_bind_auth_stage", bind)
    presented = []
    async def present(session, context, demo=False):
        presented.append((session, context, demo))
        return {"status": "waiting_for_handoff"}
    monkeypatch.setattr(controller, "_present", present)
    result = await controller._run("open", {"url": "https://fixture.example/login"}, (7, 8, None))
    assert result["status"] == "waiting_for_handoff"
    assert presented and presented[0][0] is controller.sessions[(7, 8, None)]


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata,labels", [
    ({"f0": {"label": "Password", "type": "password", "required": True}}, ["Password"]),
    ({"f0": {"label": "One-time code", "type": "otp", "required": True}}, ["One-time code"]),
])
async def test_publication_uses_exact_bound_password_or_otp_controls(metadata, labels):
    controller = SecureHandoffController(Ctx())
    controller.bot = Bot()
    session = Session(7, 8, None, page=SimpleNamespace(url="https://fixture.example/login"), ref_meta=metadata)
    result = await controller._present(session, SimpleNamespace(bot=controller.bot))
    assert result["status"] == "waiting_for_handoff"
    assert [field["label"] for field in session.request["fields"]] == labels


@pytest.mark.asyncio
async def test_login_wakeup_targets_origin_chat_with_status_only_text():
    controller = SecureHandoffController(Ctx())
    controller.adapter = object()
    controller.loop = asyncio.get_running_loop()
    captured = []

    async def capture(adapter, text, source):
        captured.append({"text": text, "chat": source.chat_id, "user": source.user_id, "thread": source.thread_id, "adapter": adapter})

    controller._deliver_wake = capture
    session = Session(7, 8, 42)
    session.status = "rejected"
    session.page = SimpleNamespace(url="https://x.com/i/flow/login")
    controller._schedule_wake(session)
    await asyncio.sleep(0)
    assert len(captured) == 1
    assert captured[0]["chat"] == "8"
    assert captured[0]["user"] == "7"
    assert captured[0]["thread"] == "42"
    assert captured[0]["adapter"] is controller.adapter
    assert "rejected" in captured[0]["text"]
    assert "https://x.com" in captured[0]["text"]
    assert "secure-handoff wakeup" in captured[0]["text"]
    assert "secret-value" not in captured[0]["text"]


@pytest.mark.asyncio
async def test_login_wakeup_is_skipped_without_adapter():
    controller = SecureHandoffController(Ctx())
    controller.loop = asyncio.get_running_loop()
    called = []

    async def capture(*args, **kwargs):
        called.append(True)

    controller._deliver_wake = capture
    session = Session(7, 8, 42)
    session.status = "submitted"
    controller._schedule_wake(session)
    await asyncio.sleep(0)
    assert called == []


@pytest.mark.asyncio
async def test_attach_targets_existing_nonfirst_page_without_navigation(monkeypatch):
    controller = SecureHandoffController(Ctx())
    controller.bot = Bot()
    identity = (7, 8, None)

    class Page:
        def __init__(self, url):
            self.url = url
            self.goto_calls = []

        def is_closed(self):
            return False

        async def goto(self, *args, **kwargs):
            self.goto_calls.append((args, kwargs))

    first_page = Page("https://popup.example/other")
    target_page = Page("https://popup.example/login")
    target_page.target_id = "A" * 32
    controller._browser = object()
    controller._context = SimpleNamespace(pages=[first_page, target_page])

    async def bind(session):
        session.ref_meta = {
            "f0": {"label": "One-time code", "type": "otp", "required": True}
        }

    async def present(session, context, demo=False):
        assert session.page is target_page
        return {"status": "waiting_for_handoff"}

    async def page_target_id(page):
        return getattr(page, "target_id", None)

    monkeypatch.setattr(controller, "_bind_auth_stage", bind)
    monkeypatch.setattr(controller, "_present", present)
    monkeypatch.setattr(controller, "_page_target_id", page_target_id, raising=False)

    result = await controller._run(
        "attach",
        {"origin": "https://popup.example", "ref": target_page.target_id},
        identity,
    )

    assert result == {"status": "waiting_for_handoff"}
    assert first_page.goto_calls == []
    assert target_page.goto_calls == []


@pytest.mark.asyncio
async def test_present_current_stage_does_not_reload_attached_page(monkeypatch):
    controller = SecureHandoffController(Ctx())
    controller.bot = Bot()
    identity = (7, 8, None)

    class Page:
        url = "https://popup.example/login"

        def __init__(self):
            self.goto_calls = []

        async def goto(self, *args, **kwargs):
            self.goto_calls.append((args, kwargs))

    page = Page()
    session = Session(*identity, page=page)
    controller.sessions[identity] = session

    async def bind(current):
        current.ref_meta = {
            "f0": {"label": "One-time code", "type": "otp", "required": True}
        }

    async def present(current, context, demo=False):
        assert current is session
        return {"status": "waiting_for_handoff"}

    monkeypatch.setattr(controller, "_bind_auth_stage", bind)
    monkeypatch.setattr(controller, "_present", present)

    result = await controller._run("present", {}, identity)

    assert result == {"status": "waiting_for_handoff"}
    assert page.goto_calls == []
