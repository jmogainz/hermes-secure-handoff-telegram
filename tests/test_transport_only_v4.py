"""RED contract for the v4 transport-only secure handoff (no real browser/profile)."""
import asyncio
import base64
import json
import time
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from telegram.ext import ApplicationHandlerStop

from plugin.protocol_v4 import make_entry_request
from plugin.secure_handoff import SCHEMA, SecureHandoffController, Session


IDENT = (7, 8, 42)
ORIGIN = "https://fixture.example"
TARGET_ID = "A" * 32
SESSION_REF = "ss_" + "S" * 32
SNAPSHOT_REF = "sn_" + "N" * 32
FIELD_REF = "fr_" + "F" * 32
CHILD_REF = "fr_" + "C" * 32
ACTION_REF = "ar_" + "A" * 32
SAFE_RECEIPT_KEYS = {
    "status", "request_kind", "operations_requested", "browser_calls_returned",
    "browser_errors", "browser_error_categories",
}


class Ctx:
    def __init__(self, path):
        self.data_dir = path
        self.state = SimpleNamespace(data_dir=path)

    def get_config(self, key):
        return {
            "allowed_user_ids": [IDENT[0]],
            "mini_app_url": "https://mini.example/app",
            "browser_cdp_url": "http://127.0.0.1:9222",
        }[key]


class Page:
    def __init__(self, target_id=TARGET_ID, origin=ORIGIN):
        self.target_id = target_id
        self.url = origin + "/private?do-not-publish=this"
        self.goto_calls = 0

    def is_closed(self):
        return False


class Context:
    def __init__(self, *pages):
        self.pages = list(pages)


class Publisher:
    def __init__(self):
        self.sent = []

    async def send_message(self, **kwargs):
        self.sent.append(kwargs)
        return SimpleNamespace(message_id=len(self.sent))


class Adapter:
    def __init__(self):
        self.sent = []

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        self.sent.append((chat_id, content, metadata))
        return SimpleNamespace(success=True)


class Control:
    def __init__(self, frame, *, error=None):
        self.frame = frame
        self.error = error
        self.calls = []

    async def apply(self, strategy, value=None):
        self.calls.append((strategy, value))
        if self.error:
            raise self.error


class InventoryExecutor:
    def __init__(self, records):
        self.records = records

    async def inventory(self, _page):
        return self.records


async def noop(*_args, **_kwargs):
    return None


def controller(tmp_path, *pages):
    c = SecureHandoffController(Ctx(tmp_path), context=Context(*pages))
    c.bot = Publisher()
    c.adapter = Adapter()

    async def target_id(page):
        return page.target_id

    c._page_target_id = target_id
    c._refresh_same_stage = noop
    c._preflight = noop
    c._schedule_wake = lambda *_args, **_kwargs: None
    return c


def attached(c, page=None, *, session_ref=SESSION_REF, ident=IDENT):
    page = page or Page()
    session = Session(*ident, page=page, context=c._context, wake=asyncio.Event())
    session.status = "attached"
    session.session_ref = session_ref
    session.snapshot_ref = SNAPSHOT_REF
    session.inventory_snapshot = SNAPSHOT_REF
    session.inventory_refs = {}
    session.control_refs = session.inventory_refs
    c.sessions[session_ref] = session
    return session


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def v4_request(kind="entry", *, expired=False, request_id=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    request = {
        "v": 4,
        "id": request_id or "sh_" + "R" * 32,
        "kind": kind,
        "origin": ORIGIN,
        "expiresAt": int(time.time() * 1000) + (-1 if expired else 60_000),
        "publicKey": {
            "kty": "RSA",
            "n": b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        },
    }
    if kind == "entry":
        request["fields"] = [
            {"id": "f0", "label": "Account", "type": "text", "required": True, "strategy": "keyboard"},
            {"id": "f1", "label": "Code", "type": "text", "required": True, "strategy": "fill"},
        ]
    else:
        request.update({"approvalNonce": "approve_" + "P" * 24, "summary": "Run the selected synthetic action"})
    return request, key


def envelope(session, body, *, aad=None):
    aes, iv = b"a" * 32, b"b" * 12
    wrapped = session.key.public_key().encrypt(
        aes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    ciphertext = AESGCM(aes).encrypt(
        iv, json.dumps(body, separators=(",", ":")).encode(),
        (aad or session.request["id"]).encode(),
    )
    return json.dumps({
        "v": 4, "id": session.request["id"], "wrappedKey": b64(wrapped),
        "iv": b64(iv), "ciphertext": b64(ciphertext),
    }, separators=(",", ":"))


def update(raw, identity=IDENT):
    user, chat, thread = identity
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user),
        effective_chat=SimpleNamespace(id=chat, type="private"),
        effective_message=SimpleNamespace(
            message_thread_id=thread,
            web_app_data=SimpleNamespace(data=raw),
        ),
    )


def seed_entry(c, *, expired=False, errors=(None, None), page=None,
               session_ref=SESSION_REF, request_id=None, ident=IDENT):
    session = attached(c, page, session_ref=session_ref, ident=ident)
    session.request, session.key = v4_request(expired=expired, request_id=request_id)
    session.status = "waiting_for_handoff"
    session.mode = "entry"
    top = Control("top", error=errors[0])
    child = Control("child", error=errors[1])
    session.execution_plan = [
        {"field_id": "f0", "ref": FIELD_REF, "strategy": "keyboard", "target": top},
        {"field_id": "f1", "ref": CHILD_REF, "strategy": "fill", "target": child},
    ]
    session.refs = {FIELD_REF: top, CHILD_REF: child}

    async def apply(active_session, field, value):
        op = next(item for item in active_session.execution_plan if item["field_id"] == field["id"])
        await op["target"].apply(op["strategy"], value)

    c._fill_bound_field = apply
    return session, top, child


async def callback(c, session, body, *, identity=IDENT, raw=None):
    raw = raw or envelope(session, body)
    with pytest.raises(ApplicationHandlerStop):
        await c._web_data(update(raw, identity), SimpleNamespace(bot=c.bot))
    return await c._run(
        "read", {"session_ref": session.session_ref},
        (session.user, session.chat, session.thread),
    )


def assert_mechanical(result, *, kind="entry", requested=2, returned=2, errors=0):
    assert set(result) <= SAFE_RECEIPT_KEYS
    assert result["status"] == "execution_complete"
    assert result["request_kind"] == kind
    assert result["operations_requested"] == requested
    assert result["browser_calls_returned"] == returned
    assert result["browser_errors"] == errors


@pytest.mark.asyncio
async def test_inventory_cannot_rotate_refs_while_owner_handoff_is_pending(tmp_path):
    c = controller(tmp_path)
    session, _, _ = seed_entry(c)
    original_request = session.request
    original_snapshot = session.snapshot_ref
    c.executor = InventoryExecutor([])

    result = await c._inventory(session)

    assert result == {"status": "rejected", "reason": "request_pending"}
    assert session.request is original_request
    assert session.snapshot_ref == original_snapshot
    assert session.status == "waiting_for_handoff"


@pytest.mark.asyncio
async def test_close_waits_for_blocked_publication_before_removing_session(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    control = Control("field")
    session.status = "inventory_available"
    session.inventory_refs = {FIELD_REF: control}
    session.control_refs = session.inventory_refs
    session.inventory_meta = {
        FIELD_REF: {"capabilities": ["keyboard"], "category": "editable"},
    }
    publication_started = asyncio.Event()
    release_publication = asyncio.Event()

    async def blocked_publish(session: Session, text: str) -> bool:
        del session, text
        publication_started.set()
        await release_publication.wait()
        return True

    c._publish = blocked_publish
    present = asyncio.create_task(c._run("present_entry", {
        "session_ref": SESSION_REF,
        "snapshot_ref": SNAPSHOT_REF,
        "fields": [{
            "ref": FIELD_REF,
            "label": "Synthetic field",
            "type": "text",
            "required": True,
            "strategy": "keyboard",
        }],
    }, IDENT))
    await publication_started.wait()
    close = asyncio.create_task(c._run(
        "close", {"session_ref": session.session_ref}, IDENT
    ))
    await asyncio.sleep(0)

    assert not close.done()
    assert c.sessions.get(session.session_ref) is session

    release_publication.set()
    assert await present == {"status": "waiting_for_handoff"}
    assert await close == {"status": "closed"}
    assert session.session_ref not in c.sessions


@pytest.mark.asyncio
async def test_parallel_attach_allows_same_scope_on_a_different_target(tmp_path):
    first_page = Page("A" * 32)
    second_page = Page("B" * 32)
    c = controller(tmp_path, first_page, second_page)
    first = await c._run("attach", {"origin": ORIGIN, "ref": first_page.target_id}, IDENT)
    second = await c._run("attach", {"origin": ORIGIN, "ref": second_page.target_id}, IDENT)

    assert first["status"] == second["status"] == "attached"
    assert first["session_ref"] != second["session_ref"]
    assert c.sessions[first["session_ref"]].page is first_page
    assert c.sessions[second["session_ref"]].page is second_page


@pytest.mark.asyncio
async def test_parallel_attach_rejects_reusing_an_attached_target(tmp_path):
    page = Page("A" * 32)
    c = controller(tmp_path, page)
    first = await c._run("attach", {"origin": ORIGIN, "ref": page.target_id}, IDENT)
    second = await c._run("attach", {"origin": ORIGIN, "ref": page.target_id}, IDENT)

    assert first["status"] == "attached"
    assert second == {"status": "rejected", "reason": "attach_failed"}
    assert list(c.sessions) == [first["session_ref"]]


def test_schema_exposes_only_compact_v4_workflow_actions():
    parameters = SCHEMA["parameters"]
    actions = set(parameters["properties"]["action"]["enum"])
    assert {"attach", "inventory", "present_entry", "present_action", "read", "close"} <= actions
    assert not ({"open", "present", "select_auth_action", "discover_components", "present_composition"} & actions)

    requirements = {
        clause["if"]["properties"]["action"]["enum"][0]: set(clause["then"]["required"])
        for clause in parameters["allOf"]
    }
    assert requirements == {
        "attach": {"action", "origin"},
        "inventory": {"action", "session_ref"},
        "present_entry": {"action", "session_ref", "snapshot_ref", "fields"},
        "present_action": {"action", "session_ref", "snapshot_ref", "action_ref", "summary"},
        "read": {"action", "session_ref"},
        "close": {"action", "session_ref"},
    }

    field_variants = parameters["properties"]["fields"]["items"]["oneOf"]
    assert len(field_variants) == 3
    assert set(field_variants[0]["properties"]["type"]["enum"]) == {
        "text", "password", "email", "tel", "url", "number", "search", "textarea",
        "select", "checkbox", "radio", "date", "time", "datetime-local", "month", "week",
        "color", "range",
    }
    assert all(variant["additionalProperties"] is False for variant in field_variants)

    view = parameters["properties"]["view"]
    assert view["additionalProperties"] is False
    assert view["properties"]["schema"]["enum"] == ["secure-handoff.ui/1"]
    node_variants = parameters["$defs"]["view_node"]["oneOf"]
    assert {variant["properties"]["kind"]["enum"][0] for variant in node_variants} == {
        "stack", "row", "section", "text", "divider", "field",
    }
    assert all(variant["additionalProperties"] is False for variant in node_variants)


@pytest.mark.asyncio
async def test_one_segmented_value_can_fan_out_to_exact_controls_without_provider_logic(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    refs = [FIELD_REF, *["fr_" + character * 32 for character in "ABCDE"]]
    controls = [Control(str(index)) for index in range(6)]
    session.inventory_refs = dict(zip(refs, controls))
    session.control_refs = session.inventory_refs
    session.inventory_meta = {
        ref: {"capabilities": ["keyboard"], "category": "editable"}
        for ref in refs
    }

    async def published(session, text):
        del session, text
        return True

    c._publish = published
    result = await c._present_entry(session, {
        "snapshot_ref": SNAPSHOT_REF,
        "fields": [{
            "ref": refs[0],
            "label": "Verification code",
            "type": "tel",
            "required": True,
            "strategy": "keyboard",
            "component": {"kind": "segmented_code", "length": 6, "alphabet": "digits"},
            "binding": {"mode": "split_chars", "refs": refs[1:]},
        }],
    })
    assert result == {"status": "waiting_for_handoff"}
    assert [item.get("value_index") for item in session.execution_plan] == list(range(6))

    receipt = await callback(c, session, {"values": {"f0": "123456"}})
    assert_mechanical(receipt, requested=6, returned=6)
    assert [control.calls for control in controls] == [[("keyboard", digit)] for digit in "123456"]


@pytest.mark.asyncio
async def test_present_entry_rejects_more_than_twenty_four_browser_operations(tmp_path):
    c = controller(tmp_path, Page())
    session = attached(c)
    refs: list[str] = []
    controls: dict[str, Control] = {}
    for ordinal in range(25):
        ref = f"fr_{ordinal:032d}"
        refs.append(ref)
        controls[ref] = Control(SimpleNamespace())
        session.inventory_meta[ref] = {"capabilities": ["keyboard"]}
    session.inventory_refs = dict(controls)
    session.control_refs = dict(controls)

    async def published(session, text):
        del session, text
        raise AssertionError("oversized execution plan must reject before publication")

    c._publish = published
    fields = []
    for offset in (0, 12):
        fields.append({
            "ref": refs[offset],
            "label": f"Code {offset}",
            "type": "tel",
            "required": True,
            "strategy": "keyboard",
            "component": {"kind": "segmented_code", "length": 12, "alphabet": "digits"},
            "binding": {"mode": "split_chars", "refs": refs[offset + 1:offset + 12]},
        })
    fields.append({
        "ref": refs[24], "label": "Extra", "type": "text", "required": True, "strategy": "keyboard"
    })

    result = await c._present_entry(session, {"snapshot_ref": SNAPSHOT_REF, "fields": fields})
    assert result == {"status": "rejected", "reason": "invalid_fields"}


@pytest.mark.asyncio
async def test_browser_operation_timeout_is_bounded_and_reported(tmp_path, monkeypatch):
    import plugin.secure_handoff as secure_handoff_module

    class SlowControl(Control):
        async def apply(self, strategy, value=None):
            await asyncio.sleep(0.05)

    monkeypatch.setattr(secure_handoff_module, "BROWSER_OPERATION_TIMEOUT_SECONDS", 0.01)
    c = controller(tmp_path, Page())
    session = attached(c)
    slow = SlowControl(SimpleNamespace())
    request, key = make_entry_request("https://fixture.example", [{
        "ref": FIELD_REF, "label": "Value", "type": "text", "required": True, "strategy": "keyboard"
    }])
    session.request = request
    session.key = key
    session.mode = "entry"
    session.status = "waiting_for_handoff"
    session.execution_plan = [{
        "field_id": "f0", "ref": FIELD_REF, "strategy": "keyboard", "target": slow
    }]
    session.refs = {FIELD_REF: slow}

    receipt = await callback(c, session, {"values": {"f0": "synthetic"}})

    assert receipt == {
        "status": "execution_complete",
        "request_kind": "entry",
        "operations_requested": 1,
        "browser_calls_returned": 0,
        "browser_errors": 1,
        "browser_error_categories": ["timeout"],
    }


def test_public_tool_accepts_and_forwards_session_ref_for_present_calls(tmp_path, monkeypatch):
    c = controller(tmp_path)
    monkeypatch.setattr(c, "_identity", lambda: IDENT)

    def fake_submit(coroutine):
        coroutine.close()
        return {"status": "forwarded"}

    monkeypatch.setattr(c, "_submit", fake_submit)
    payloads = [
        {
            "action": "present_entry", "session_ref": SESSION_REF,
            "snapshot_ref": SNAPSHOT_REF, "fields": [],
            "view": {"kind": "stack", "children": []},
        },
        {
            "action": "present_action", "session_ref": SESSION_REF,
            "snapshot_ref": SNAPSHOT_REF, "action_ref": ACTION_REF,
            "summary": "Run the selected synthetic action",
        },
    ]
    for payload in payloads:
        assert json.loads(c.tool(payload)) == {"status": "forwarded"}


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["present_entry", "present_action"])
async def test_present_calls_require_the_exact_session_ref(tmp_path, action):
    c = controller(tmp_path)
    attached(c)
    result = await c._run(action, {"session_ref": "ss_" + "Z" * 32}, IDENT)
    assert result == {"status": "rejected", "reason": "invalid_session"}


@pytest.mark.asyncio
async def test_attach_binds_exact_target_without_navigation_or_dom_judgment(tmp_path):
    page = Page()
    c = controller(tmp_path, page)
    result = await c._run("attach", {"origin": ORIGIN, "ref": TARGET_ID}, IDENT)
    assert result["status"] == "attached"
    assert result["session_ref"].startswith("ss_")
    assert c.sessions[result["session_ref"]].page is page
    assert page.goto_calls == 0


@pytest.mark.asyncio
async def test_attach_never_guesses_between_targets(tmp_path):
    c = controller(tmp_path, Page("A" * 32), Page("B" * 32))
    result = await c._run("attach", {"origin": ORIGIN}, IDENT)
    assert result == {"status": "rejected", "reason": "ambiguous_target"}
    assert not c.sessions


@pytest.mark.asyncio
async def test_inventory_returns_only_generic_opaque_refs_without_values(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    c.executor = InventoryExecutor([
        {"target": Control("top"), "category": "editable", "capabilities": ["keyboard", "fill"],
         "frame_origin": ORIGIN, "frame_ordinal": 0, "ordinal": 1, "visible": True,
         "enabled": True, "editable": True, "value": "private-current-value", "selector": "#account"},
        {"target": Control("child"), "category": "action", "capabilities": ["click"],
         "frame_origin": "https://child.example", "frame_ordinal": 1, "ordinal": 1,
         "visible": True, "enabled": True, "editable": False},
    ])
    result = await c._run("inventory", {"action": "inventory", "session_ref": session.session_ref}, IDENT)
    assert result["status"] == "inventory_available"
    assert result["snapshot_ref"].startswith("sn_")
    assert len(result["refs"]) == 2
    assert all(item["ref"].startswith(("fr_", "ar_")) for item in result["refs"])
    assert all(set(item) <= {"ref", "category", "capabilities", "frame_origin", "frame_ordinal",
                                    "ordinal", "visible", "enabled", "editable"} for item in result["refs"])
    assert "private-current-value" not in json.dumps(result)
    assert "selector" not in json.dumps(result).lower()


@pytest.mark.asyncio
async def test_present_entry_publishes_agent_authored_v4_fields_and_strategies(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    session.inventory_refs = {FIELD_REF: Control("top")}
    session.control_refs = session.inventory_refs
    fields = [{"ref": FIELD_REF, "label": "Recovery phrase", "type": "password",
               "required": True, "strategy": "keyboard"}]
    view = {
        "schema": "secure-handoff.ui/1",
        "kind": "stack",
        "children": [
            {"kind": "text", "text": "Enter it only in the encrypted Mini App.", "tone": "muted"},
            {"kind": "field", "ref": FIELD_REF},
        ],
    }
    result = await c._run("present_entry", {
        "action": "present_entry", "session_ref": SESSION_REF,
        "snapshot_ref": SNAPSHOT_REF, "fields": fields, "view": view,
    }, IDENT)
    assert result["status"] == "waiting_for_handoff"
    assert session.request is not None
    assert session.request["v"] == 4 and session.request["kind"] == "entry"
    assert session.request["fields"] == [{
        "id": "f0", "label": "Recovery phrase", "type": "password",
        "required": True, "strategy": "keyboard",
    }]
    assert session.request["view"] == {
        "schema": "secure-handoff.ui/1",
        "kind": "stack",
        "children": [
            {"kind": "text", "text": "Enter it only in the encrypted Mini App.", "tone": "muted"},
            {"kind": "field", "field": "f0"},
        ],
    }
    assert session.execution_plan[0]["ref"] == FIELD_REF
    assert session.execution_plan[0]["strategy"] == "keyboard"
    assert "private-current-value" not in json.dumps(session.request)


@pytest.mark.asyncio
async def test_entry_callback_attempts_top_and_child_operations_without_readback(tmp_path):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    result = await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    assert top.calls == [("keyboard", "synthetic-a")]
    assert child.calls == [("fill", "synthetic-b")]
    assert_mechanical(result)
    assert session.request is None and session.key is None and not session.refs
    assert "synthetic" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["rerender", "form", "action", "route", "unrelated"])
async def test_dom_or_route_mutation_cannot_cause_semantic_rejection(tmp_path, mutation):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)

    async def obsolete_semantic_guard(*_args, **_kwargs):
        raise ValueError("obsolete semantic rejection: " + mutation)

    c._refresh_same_stage = obsolete_semantic_guard
    c._preflight = obsolete_semantic_guard
    result = await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    assert len(top.calls) + len(child.calls) == 2
    assert_mechanical(result)


@pytest.mark.asyncio
async def test_browser_exceptions_are_mechanical_counts_not_rejection(tmp_path):
    class TargetClosedError(RuntimeError):
        pass

    c = controller(tmp_path)
    session, top, child = seed_entry(c, errors=(TargetClosedError("detached PRIVATE DOM"), RuntimeError("PRIVATE page body")))
    result = await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    assert len(top.calls) == len(child.calls) == 1
    assert_mechanical(result, returned=0, errors=2)
    assert set(result["browser_error_categories"]) <= {"detached", "timeout", "browser_error"}
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("identity", [(9, 8, 42), (7, 9, 42), (7, 8, 43)])
async def test_wrong_owner_chat_or_topic_rejects_before_browser_operations(tmp_path, identity):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}}, identity=identity)
    assert top.calls == child.calls == []
    assert session.status == "waiting_for_handoff"


@pytest.mark.asyncio
async def test_topicless_callback_accepts_unique_request_id(tmp_path):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    result = await callback(
        c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}},
        identity=(IDENT[0], IDENT[1], None),
    )
    assert len(top.calls) == len(child.calls) == 1
    assert_mechanical(result)


@pytest.mark.asyncio
async def test_topicless_callbacks_route_parallel_same_topic_flows_by_request_id(tmp_path):
    c = controller(tmp_path)
    first, first_top, first_child = seed_entry(
        c, page=Page("A" * 32), session_ref="ss_" + "A" * 32, request_id="sh_" + "A" * 32,
    )
    second, second_top, second_child = seed_entry(
        c, page=Page("B" * 32), session_ref="ss_" + "B" * 32, request_id="sh_" + "B" * 32,
    )
    topicless = (IDENT[0], IDENT[1], None)

    first_result = await callback(
        c, first, {"values": {"f0": "first-a", "f1": "first-b"}}, identity=topicless,
    )
    second_result = await callback(
        c, second, {"values": {"f0": "second-a", "f1": "second-b"}}, identity=topicless,
    )

    assert first_top.calls == [("keyboard", "first-a")]
    assert first_child.calls == [("fill", "first-b")]
    assert second_top.calls == [("keyboard", "second-a")]
    assert second_child.calls == [("fill", "second-b")]
    assert_mechanical(first_result)
    assert_mechanical(second_result)


@pytest.mark.asyncio
async def test_duplicate_request_id_rejects_without_browser_operations(tmp_path):
    c = controller(tmp_path)
    first, first_top, first_child = seed_entry(
        c, page=Page("A" * 32), session_ref="ss_" + "A" * 32, request_id="sh_" + "D" * 32,
    )
    second, second_top, second_child = seed_entry(
        c, page=Page("B" * 32), session_ref="ss_" + "B" * 32, request_id="sh_" + "D" * 32,
    )

    with pytest.raises(ApplicationHandlerStop):
        await c._web_data(
            update(envelope(first, {"values": {"f0": "x", "f1": "y"}}),
                   (IDENT[0], IDENT[1], None)),
            SimpleNamespace(bot=c.bot),
        )

    assert first_top.calls == first_child.calls == []
    assert second_top.calls == second_child.calls == []
    assert first.status == second.status == "waiting_for_handoff"


@pytest.mark.asyncio
@pytest.mark.parametrize("tamper", ["ciphertext", "aad"])
async def test_invalid_crypto_rejects_before_browser_operations(tmp_path, tamper):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    raw = envelope(session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}},
                   aad="wrong-aad" if tamper == "aad" else None)
    if tamper == "ciphertext":
        obj = json.loads(raw)
        obj["ciphertext"] = obj["ciphertext"][:-2] + "AA"
        raw = json.dumps(obj)
    result = await callback(c, session, {}, raw=raw)
    assert top.calls == child.calls == []
    assert result["status"] == "rejected"


@pytest.mark.asyncio
async def test_expiry_rejects_before_browser_operations(tmp_path):
    c = controller(tmp_path)
    session, top, child = seed_entry(c, expired=True)
    result = await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    assert top.calls == child.calls == []
    assert result["status"] in {"rejected", "expired"}


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [
    {"values": {"f0": "synthetic-a", "f1": "synthetic-b", "unknown": "x"}},
    {"values": {"f0": "x" * 513, "f1": "synthetic-b"}},
])
async def test_invalid_field_payload_rejects_before_browser_operations(tmp_path, body):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    result = await callback(c, session, body)
    assert top.calls == child.calls == []
    assert result["status"] == "rejected"


@pytest.mark.asyncio
async def test_changed_replay_never_runs_browser_operations_twice(tmp_path):
    c = controller(tmp_path)
    session, top, child = seed_entry(c)
    raw = envelope(session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    changed = envelope(session, {"values": {"f0": "changed-a", "f1": "changed-b"}})
    first = await callback(c, session, {}, raw=raw)
    assert_mechanical(first)
    await callback(c, session, {}, raw=changed)
    assert len(top.calls) == len(child.calls) == 1


@pytest.mark.asyncio
async def test_present_action_creates_separate_encrypted_approval_request(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    session.inventory_refs = {ACTION_REF: Control("top")}
    session.control_refs = session.inventory_refs
    result = await c._run("present_action", {
        "action": "present_action", "session_ref": SESSION_REF, "snapshot_ref": SNAPSHOT_REF,
        "action_ref": ACTION_REF, "summary": "Run the selected synthetic action",
    }, IDENT)
    assert result["status"] == "waiting_for_handoff"
    assert session.request["v"] == 4 and session.request["kind"] == "action_approval"
    assert session.request["approvalNonce"].startswith("approve_")
    assert session.execution_plan == [{"ref": ACTION_REF, "strategy": "click"}]
    assert "fields" not in session.request


@pytest.mark.asyncio
async def test_approved_action_attempts_exact_click_once_and_never_retries(tmp_path):
    c = controller(tmp_path)
    session = attached(c)
    action = Control("top", error=RuntimeError("PRIVATE click failure"))
    session.request, session.key = v4_request("action_approval")
    session.status = "waiting_for_handoff"
    session.mode = "action_approval"
    session.execution_plan = [{"ref": ACTION_REF, "strategy": "click", "target": action}]
    session.refs = {ACTION_REF: action}

    async def click_once(_session, _candidate=None):
        await action.apply("click")

    c._commit_selected_action = click_once
    raw = envelope(session, {"approve": session.request["approvalNonce"]})
    result = await callback(c, session, {}, raw=raw)
    assert action.calls == [("click", None)]
    assert_mechanical(result, kind="action_approval", requested=1, returned=0, errors=1)
    await callback(c, session, {}, raw=raw)
    assert action.calls == [("click", None)]


def test_execution_wakeup_language_is_mechanical_and_requires_browser_inspection():
    c = object.__new__(SecureHandoffController)
    text = c._wake_text("execution_complete", ORIGIN).lower()
    assert "submission received" in text
    assert "execution attempt finished" in text
    assert "inspect the live browser" in text
    assert not any(claim in text for claim in ("fields filled", "action submitted", "purchase submitted", "authenticated", "succeeded"))


@pytest.mark.asyncio
async def test_execution_wake_uses_immutable_receipt_status_while_ack_waits(tmp_path):
    c = controller(tmp_path)
    session, _, _ = seed_entry(c)
    raw = envelope(session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    ack_started = asyncio.Event()
    release_ack = asyncio.Event()
    scheduled: list[dict[str, Any]] = []

    async def blocked_send(*_args, **_kwargs):
        ack_started.set()
        await release_ack.wait()
        return True

    c._send = blocked_send
    c._schedule_wake = lambda session, **values: scheduled.append(values)

    async def submit():
        with pytest.raises(ApplicationHandlerStop):
            await c._web_data(update(raw), SimpleNamespace(bot=c.bot))

    task = asyncio.create_task(submit())
    await ack_started.wait()
    session.status = "inventory_available"
    release_ack.set()
    await task

    assert scheduled == [{"status": "execution_complete", "origin": ORIGIN}]


@pytest.mark.asyncio
async def test_execution_ack_and_receipt_contain_only_mechanical_evidence(tmp_path):
    c = controller(tmp_path)
    session, _top, _child = seed_entry(c, errors=(RuntimeError("PRIVATE exception body"), None))
    result = await callback(c, session, {"values": {"f0": "synthetic-a", "f1": "synthetic-b"}})
    assert_mechanical(result, returned=1, errors=1)
    ack = c.adapter.sent[-1][1].lower()
    assert "submission received" in ack and "execution attempt finished" in ack
    assert "inspect the live browser" in ack
    assert "PRIVATE" not in ack and "synthetic" not in ack
    rows = [json.loads(line) for line in (tmp_path / "secure_handoff_receipts.jsonl").read_text().splitlines()]
    receipt = rows[-1]
    assert receipt["v"] == 4
    assert set(receipt) <= {"v", "id", "status", "thread", "time"} | (SAFE_RECEIPT_KEYS - {"status"})
    assert "PRIVATE" not in json.dumps(receipt) and "synthetic" not in json.dumps(receipt)
