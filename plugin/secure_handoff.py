"""Transport-only v4 secure handoff controller.

This controller binds an exact existing browser target, inventories generic
controls, transports encrypted user input, and attempts only the operations the
agent explicitly presented.  It makes no webpage, form, provider, stage, or
outcome judgments.
"""
from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

try:
    from .browser_executor import GenericBrowserExecutor
    from .config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from .connection_check import load_runtime_config
    from .protocol_v4 import (
        b64url_encode,
        decrypt_submission,
        make_action_request,
        make_entry_request,
        make_request,
        normalize_origin,
        origin_from_url,
        strict_json,
        validate_entry_fields,
    )
except ImportError:  # Standalone Hermes directory loader.
    from browser_executor import GenericBrowserExecutor
    from config import DEFAULT_CDP_URL, validate_browser_cdp_url
    from connection_check import load_runtime_config
    from protocol_v4 import (
        b64url_encode,
        decrypt_submission,
        make_action_request,
        make_entry_request,
        make_request,
        normalize_origin,
        origin_from_url,
        strict_json,
        validate_entry_fields,
    )

logger = logging.getLogger(__name__)
TTL = 600
IDLE_TTL = 1800
MAX_SESSIONS = 4
MAX_BROWSER_OPERATIONS = 24
BROWSER_OPERATION_TIMEOUT_SECONDS = 10.0
PLUGIN_HANDLER_GROUP = -100
_TARGET_ID_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_REQUEST_NAMESPACE_RE = re.compile(r"^sh_[A-Za-z0-9_-]{1,64}$")
_SESSION_REF_RE = re.compile(r"^ss_[A-Za-z0-9_-]{32}$")
_SNAPSHOT_REF_RE = re.compile(r"^sn_[A-Za-z0-9_-]{32}$")
_FIELD_REF_RE = re.compile(r"^fr_[A-Za-z0-9_-]{32}$")
_ACTION_REF_RE = re.compile(r"^ar_[A-Za-z0-9_-]{32}$")
_PUBLIC_INVENTORY_KEYS = (
    "category", "capabilities", "frame_origin", "frame_ordinal", "ordinal",
    "visible", "enabled", "editable",
)
_CAPABILITIES = frozenset({"keyboard", "fill", "select", "check", "click"})


class _AmbiguousTarget(ValueError):
    pass


def _mint(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(24)


@dataclass
class Session:
    user: int
    chat: int
    thread: int | None
    chat_type: str = "dm"
    page: Any = field(default=None, repr=False)
    context: Any = field(default=None, repr=False)
    wake: asyncio.Event | None = field(default=None, repr=False)
    request: dict[str, Any] | None = field(default=None, repr=False)
    key: Any = field(default=None, repr=False)
    status: str = "attached"
    mode: str = ""
    session_ref: str | None = None
    snapshot_ref: str | None = None
    inventory_snapshot: str | None = None
    inventory_refs: dict[str, Any] = field(default_factory=dict, repr=False)
    control_refs: dict[str, Any] = field(default_factory=dict, repr=False)
    inventory_meta: dict[str, dict[str, Any]] = field(default_factory=dict, repr=False)
    refs: dict[str, Any] = field(default_factory=dict, repr=False)
    execution_plan: list[dict[str, Any]] = field(default_factory=list, repr=False)
    used_ids: set[str] = field(default_factory=set, repr=False)
    receipt: dict[str, Any] | None = field(default=None, repr=False)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    updated: float = field(default_factory=time.monotonic)
    deadline: Any = field(default=None, repr=False)


class SecureHandoffController:
    def __init__(
        self,
        ctx: Any,
        *,
        browser: Any = None,
        playwright: Any = None,
        context: Any = None,
        owns_browser: bool = False,
        executor: Any = None,
    ) -> None:
        self.ctx = ctx
        self.config = load_runtime_config(ctx)
        self.loop = None
        self.bot = None
        self.adapter = None
        self._playwright = playwright
        self._browser = browser
        self._context = context
        self._owns_browser = owns_browser
        self._cdp_url = ""
        self.executor = executor or GenericBrowserExecutor()
        # session_ref is the per-flow capability and the primary session key.
        # Owner/chat/topic remain immutable authorization metadata on Session.
        self.sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        self._admission_lock = asyncio.Lock()

    def _identity(self):
        """Owner/chat/thread/chat-type tuple for the current tool-call session.

        Group and forum origins are accepted; the chat-id sign is checked against the
        chat type so a mislabeled or missing chat type fails closed instead of
        authorizing the wrong scope.
        """
        try:
            from gateway.session_context import get_session_env

            values = [
                get_session_env(key, "")
                for key in (
                    "HERMES_SESSION_PLATFORM", "HERMES_SESSION_USER_ID",
                    "HERMES_SESSION_CHAT_ID", "HERMES_SESSION_THREAD_ID",
                    "HERMES_SESSION_CHAT_TYPE",
                )
            ]
            if values[0] != "telegram" or not values[1] or not values[2]:
                return None
            user_id = int(values[1])
            chat_id = int(values[2])
            if chat_id == 0:
                return None
            thread = int(values[3]) if values[3] else None
            chat_type = (values[4] or "").strip().lower()
            if not chat_type and chat_id > 0:
                chat_type = "dm"
            if chat_type not in {"dm", "group", "forum"}:
                return None
            if (chat_type == "dm") != (chat_id > 0):
                return None
            if thread is not None and thread <= 0:
                return None
            return (user_id, chat_id, thread, chat_type)
        except Exception:
            return None

    def _owners(self) -> set[int]:
        return set(self.config.allowed_user_ids) if self.config is not None else set()

    @staticmethod
    def _origin_of(session: "Session"):
        return (session.user, session.chat, session.thread, session.chat_type)

    @staticmethod
    def _handoff_target(session: "Session"):
        """The private chat that receives the launch keyboard and whose callback is authorized.

        DM-origin flows publish to and submit from the same chat as the origin.
        Group-origin flows always publish to, and accept submissions only from, the
        owner's private chat; the origin chat stays recorded for wakeups and
        cancellation.
        """
        if session.chat_type == "dm":
            return session.chat, session.thread
        return session.user, None

    def _configured_cdp_url(self) -> str:
        try:
            value = self.ctx.get_config("browser_cdp_url")
        except Exception:
            value = None
        validated = validate_browser_cdp_url(value or DEFAULT_CDP_URL)
        if validated is None:
            raise ValueError("browser_cdp_url must be a loopback HTTP endpoint")
        return validated

    async def _ensure_runtime(self) -> None:
        if self._browser is not None:
            return
        from playwright.async_api import async_playwright

        self._cdp_url = self._configured_cdp_url()
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.connect_over_cdp(self._cdp_url)
        except Exception:
            await self._playwright.stop()
            self._playwright = None
            self._cdp_url = ""
            raise

    async def _shared_context(self):
        if self._context is not None:
            return self._context
        await self._ensure_runtime()
        contexts = list(getattr(self._browser, "contexts", []) or [])
        if not contexts:
            raise RuntimeError("browser context unavailable")
        return contexts[0]

    async def _page_target_id(self, page: Any) -> str | None:
        cdp = await page.context.new_cdp_session(page)
        try:
            info = await cdp.send("Target.getTargetInfo")
            return info.get("targetInfo", {}).get("targetId")
        finally:
            await cdp.detach()

    async def _existing_page(self, context: Any, origin: str, target_id: str | None = None):
        matches = []
        for page in list(getattr(context, "pages", []) or []):
            try:
                if page.is_closed() or origin_from_url(page.url) != origin:
                    continue
                if target_id is not None and await self._page_target_id(page) != target_id:
                    continue
                matches.append(page)
            except Exception:
                continue
        if len(matches) != 1:
            raise _AmbiguousTarget
        return matches[0]

    async def _attach_session(self, ident, origin: str, target_id: str | None = None) -> Session:
        self._expire()
        if len(self.sessions) >= MAX_SESSIONS:
            raise RuntimeError("session cap")
        context = await self._shared_context()
        page = await self._existing_page(context, origin, target_id)
        if any(other.page is page for other in self.sessions.values()):
            raise ValueError("target already attached")
        session = Session(*ident, page=page, context=context, wake=asyncio.Event())
        session.session_ref = _mint("ss_")
        self.sessions[session.session_ref] = session
        return session

    def _current(self, session: Session) -> bool:
        return session.session_ref is not None and self.sessions.get(session.session_ref) is session

    def _session_for_ref(self, session_ref: Any, ident) -> Session | None:
        if not isinstance(session_ref, str) or _SESSION_REF_RE.fullmatch(session_ref) is None:
            return None
        session = self.sessions.get(session_ref)
        if session is None or self._origin_of(session) != ident:
            return None
        return session

    def _scrub(self, session: Session, *, keep_receipt: bool = True) -> None:
        if session.deadline is not None:
            try:
                session.deadline.cancel()
            except Exception:
                pass
            session.deadline = None
        session.key = None
        session.request = None
        session.refs.clear()
        session.execution_plan.clear()
        session.inventory_refs.clear()
        session.control_refs.clear()
        session.inventory_meta.clear()
        session.inventory_snapshot = None
        session.snapshot_ref = None
        if not keep_receipt:
            session.receipt = None

    def _expire(self) -> None:
        now_ms = int(time.time() * 1000)
        for session_ref, session in list(self.sessions.items()):
            if session.request and session.request.get("expiresAt", 0) <= now_ms and not session.lock.locked():
                session.status = "expired"
                if isinstance(session.request.get("id"), str):
                    session.used_ids.add(session.request["id"])
                self._scrub(session)
                if session.wake:
                    session.wake.set()
            if time.monotonic() - session.updated > IDLE_TTL and not session.lock.locked():
                self._scrub(session)
                self.sessions.pop(session_ref, None)
                if session.wake:
                    session.wake.set()

    def _arm_deadline(self, session: Session) -> None:
        if session.deadline is not None:
            session.deadline.cancel()
        request = session.request
        if request is None:
            return
        request_id = request["id"]
        delay = max(0.0, (request["expiresAt"] - int(time.time() * 1000)) / 1000)
        loop = asyncio.get_running_loop()
        session.deadline = loop.call_later(
            delay,
            lambda: loop.create_task(self._deadline_expired(session, request_id)),
        )

    async def _deadline_expired(self, session: Session, request_id: str) -> None:
        async with session.lock:
            if not self._current(session) or not session.request or session.request.get("id") != request_id:
                return
            session.used_ids.add(request_id)
            session.status = "expired"
            self._scrub(session)
            if session.wake:
                session.wake.set()
        self._schedule_wake(session)

    def _safe_origin(self, session: Session) -> str:
        try:
            return origin_from_url(session.page.url)
        except Exception:
            return ""

    @staticmethod
    def _safe_capabilities(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return [item for item in value if isinstance(item, str) and item in _CAPABILITIES]

    async def _inventory(self, session: Session, snapshot_arg: str | None = None) -> dict[str, Any]:
        if not self._current(session):
            return {"status": "unavailable", "reason": "session_missing"}
        if session.request is not None or session.status == "waiting_for_handoff":
            return {"status": "rejected", "reason": "request_pending"}
        records = await self.executor.inventory(session.page)
        if not isinstance(records, list) or len(records) > 256:
            return {"status": "rejected", "reason": "inventory_invalid"}
        snapshot_ref = _mint("sn_")
        private_refs: dict[str, Any] = {}
        meta: dict[str, dict[str, Any]] = {}
        public_refs: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict) or record.get("target") is None:
                continue
            category = record.get("category")
            if category not in {"editable", "select", "checkable", "action"}:
                continue
            capabilities = self._safe_capabilities(record.get("capabilities"))
            if not capabilities:
                continue
            ref = _mint("ar_" if category == "action" else "fr_")
            item = {
                "ref": ref,
                "category": category,
                "capabilities": capabilities,
                "frame_origin": record.get("frame_origin") if isinstance(record.get("frame_origin"), str) else "",
                "frame_ordinal": record.get("frame_ordinal") if type(record.get("frame_ordinal")) is int else 0,
                "ordinal": record.get("ordinal") if type(record.get("ordinal")) is int else 0,
                "visible": record.get("visible") is True,
                "enabled": record.get("enabled") is True,
                "editable": record.get("editable") is True,
            }
            private_refs[ref] = record["target"]
            meta[ref] = {key: item[key] for key in _PUBLIC_INVENTORY_KEYS}
            public_refs.append(item)
        session.snapshot_ref = snapshot_ref
        session.inventory_snapshot = snapshot_ref
        session.inventory_refs = private_refs
        session.control_refs = session.inventory_refs
        session.inventory_meta = meta
        session.status = "inventory_available"
        session.receipt = None
        session.updated = time.monotonic()
        return {"status": "inventory_available", "snapshot_ref": snapshot_ref, "refs": public_refs}

    def _snapshot_matches(self, session: Session, value: Any) -> bool:
        return (
            isinstance(value, str)
            and _SNAPSHOT_REF_RE.fullmatch(value) is not None
            and value in {session.snapshot_ref, session.inventory_snapshot}
        )

    async def _publish(self, session: Session, text: str) -> bool:
        if self.config is None or session.request is None:
            return False
        try:
            from telegram import KeyboardButton, ReplyKeyboardMarkup, WebAppInfo

            encoded = json.dumps(session.request, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            if len(encoded) > 4096:
                return False
            launch = self.config.mini_app_url.rstrip("/") + "#request=" + b64url_encode(encoded)
            markup = ReplyKeyboardMarkup(
                [[KeyboardButton("Open secure handoff", web_app=WebAppInfo(url=launch))]],
                resize_keyboard=True,
            )
            handoff_chat, handoff_thread = self._handoff_target(session)
            return await self._send(SimpleNamespace(bot=self.bot), handoff_chat, handoff_thread, text, markup)
        except Exception:
            return False

    async def _present_entry(self, session: Session, args: dict[str, Any]) -> dict[str, Any]:
        if not self._snapshot_matches(session, args.get("snapshot_ref")):
            return {"status": "rejected", "reason": "stale_snapshot"}
        raw_fields = args.get("fields")
        try:
            fields = validate_entry_fields(raw_fields)
        except ValueError:
            return {"status": "rejected", "reason": "invalid_fields"}
        refs = session.control_refs or session.inventory_refs
        plan: list[dict[str, Any]] = []
        for raw, field in zip(raw_fields, fields):
            bound_refs = [raw["ref"], *raw.get("binding", {}).get("refs", [])]
            split = "binding" in raw
            for value_index, ref in enumerate(bound_refs):
                target = refs.get(ref)
                metadata = session.inventory_meta.get(ref)
                if target is None or _FIELD_REF_RE.fullmatch(ref) is None:
                    return {"status": "rejected", "reason": "invalid_ref"}
                if metadata is not None and raw["strategy"] not in metadata.get("capabilities", []):
                    return {"status": "rejected", "reason": "invalid_strategy"}
                operation = {
                    "field_id": field["id"],
                    "ref": ref,
                    "strategy": raw["strategy"],
                    "target": target,
                }
                if split:
                    operation["value_index"] = value_index
                plan.append(operation)
        if len(plan) > MAX_BROWSER_OPERATIONS:
            return {"status": "rejected", "reason": "invalid_fields"}
        try:
            request, key = make_entry_request(self._safe_origin(session), raw_fields, args.get("view"))
        except ValueError:
            return {"status": "rejected", "reason": "invalid_request"}
        if session.request and isinstance(session.request.get("id"), str):
            session.used_ids.add(session.request["id"])
        if session.deadline is not None:
            session.deadline.cancel()
            session.deadline = None
        session.receipt = None
        session.request = request
        session.key = key
        session.mode = "entry"
        session.execution_plan = plan
        session.refs = {item["ref"]: item["target"] for item in plan}
        session.status = "waiting_for_handoff"
        session.updated = time.monotonic()
        published = await self._publish(session, "Encrypted browser entry is ready.")
        if not self._current(session):
            self._scrub(session)
            return {"status": "unavailable", "reason": "session_replaced"}
        if not published:
            session.status = "publication_failed"
            self._scrub(session)
            return {"status": "publication_failed"}
        self._arm_deadline(session)
        return {"status": "waiting_for_handoff"}

    async def _present_action(self, session: Session, args: dict[str, Any]) -> dict[str, Any]:
        if not self._snapshot_matches(session, args.get("snapshot_ref")):
            return {"status": "rejected", "reason": "stale_snapshot"}
        ref = args.get("action_ref")
        refs = session.control_refs or session.inventory_refs
        target = refs.get(ref) if isinstance(ref, str) else None
        metadata = session.inventory_meta.get(ref) if isinstance(ref, str) else None
        if target is None or _ACTION_REF_RE.fullmatch(ref) is None:
            return {"status": "rejected", "reason": "invalid_ref"}
        if metadata is not None and "click" not in metadata.get("capabilities", []):
            return {"status": "rejected", "reason": "invalid_strategy"}
        try:
            request, key = make_action_request(self._safe_origin(session), args.get("summary"))
        except ValueError:
            return {"status": "rejected", "reason": "invalid_summary"}
        if session.request and isinstance(session.request.get("id"), str):
            session.used_ids.add(session.request["id"])
        if session.deadline is not None:
            session.deadline.cancel()
            session.deadline = None
        session.receipt = None
        session.request = request
        session.key = key
        session.mode = "action_approval"
        session.execution_plan = [{"ref": ref, "strategy": "click"}]
        # Keep the exact handle private; the public plan remains ref + strategy.
        session.refs = {ref: target}
        session.status = "waiting_for_handoff"
        session.updated = time.monotonic()
        published = await self._publish(session, "Encrypted one-shot browser action approval is ready.")
        if not self._current(session):
            self._scrub(session)
            return {"status": "unavailable", "reason": "session_replaced"}
        if not published:
            session.status = "publication_failed"
            self._scrub(session)
            return {"status": "publication_failed"}
        self._arm_deadline(session)
        return {"status": "waiting_for_handoff"}

    async def _close(self, session_ref: Any, ident) -> dict[str, Any]:
        async with self._admission_lock:
            session = self._session_for_ref(session_ref, ident)
            if session is None:
                return {"status": "rejected", "reason": "invalid_session"}
            async with session.lock:
                if not self._current(session):
                    return {"status": "unavailable", "reason": "session_missing"}
                if session.request and isinstance(session.request.get("id"), str):
                    session.used_ids.add(session.request["id"])
                session.status = "closed"
                self._scrub(session)
                self.sessions.pop(session_ref, None)
                if session.wake:
                    session.wake.set()
        await self._dispose_if_idle()
        return {"status": "closed"}

    async def _dispose_if_idle(self) -> None:
        if self.sessions or self._playwright is None:
            return
        if self._owns_browser and self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                pass
        try:
            await self._playwright.stop()
        except Exception:
            pass
        self._playwright = None
        self._browser = None
        self._context = None
        self._cdp_url = ""

    async def _run(self, action: str, args: dict[str, Any], ident) -> dict[str, Any]:
        self._expire()
        if action == "attach":
            try:
                origin = normalize_origin(args.get("origin"))
            except ValueError:
                return {"status": "rejected", "reason": "invalid_origin"}
            target_id = args.get("ref")
            if target_id is not None and (
                not isinstance(target_id, str) or _TARGET_ID_RE.fullmatch(target_id) is None
            ):
                return {"status": "rejected", "reason": "invalid_ref"}
            try:
                async with self._admission_lock:
                    session = await self._attach_session(ident, origin, target_id)
            except _AmbiguousTarget:
                return {"status": "rejected", "reason": "ambiguous_target"}
            except Exception:
                return {"status": "rejected", "reason": "attach_failed"}
            return {"status": "attached", "session_ref": session.session_ref}
        if action == "close":
            return await self._close(args.get("session_ref"), ident)
        session = self._session_for_ref(args.get("session_ref"), ident)
        if session is None:
            return {"status": "rejected", "reason": "invalid_session"}
        session.updated = time.monotonic()
        if action == "read":
            async with session.lock:
                if not self._current(session):
                    return {"status": "unavailable", "reason": "session_missing"}
                if session.receipt is not None:
                    return dict(session.receipt)
                result = {"status": session.status}
                if session.status in {"attached", "inventory_available"} and session.session_ref:
                    result["session_ref"] = session.session_ref
                return result
        if action == "inventory":
            if args.get("session_ref") != session.session_ref:
                return {"status": "rejected", "reason": "invalid_session"}
            async with session.lock:
                return await self._inventory(session)
        if action == "present_entry":
            if args.get("session_ref") != session.session_ref:
                return {"status": "rejected", "reason": "invalid_session"}
            async with session.lock:
                return await self._present_entry(session, args)
        if action == "present_action":
            if args.get("session_ref") != session.session_ref:
                return {"status": "rejected", "reason": "invalid_session"}
            async with session.lock:
                return await self._present_action(session, args)
        return {"status": "invalid"}

    async def _fill_bound_field(
        self,
        session: Session,
        field: dict[str, Any],
        value: str,
        operation: dict[str, Any] | None = None,
    ) -> None:
        operation = operation or next(
            item for item in session.execution_plan if item.get("field_id") == field["id"]
        )
        target = operation.get("target") or session.refs.get(operation["ref"])
        if target is None:
            raise RuntimeError("detached control")
        value_index = operation.get("value_index")
        operation_value = value[value_index] if type(value_index) is int else value
        await target.apply(operation["strategy"], operation_value)

    async def _commit_selected_action(self, session: Session, candidate: dict[str, Any] | None = None) -> None:
        operation = candidate or (session.execution_plan[0] if session.execution_plan else None)
        if not operation:
            raise RuntimeError("detached control")
        target = operation.get("target") or session.refs.get(operation.get("ref"))
        if target is None:
            raise RuntimeError("detached control")
        await target.apply("click")

    @staticmethod
    def _browser_error_category(error: Exception) -> str:
        name = type(error).__name__.casefold()
        if "timeout" in name:
            return "timeout"
        if any(token in name for token in ("targetclosed", "detached", "contextdestroyed", "closed")):
            return "detached"
        return "browser_error"

    def _record_receipt(self, session: Session, request_id: str, result: dict[str, Any]) -> None:
        row = {
            "v": 4,
            "id": request_id,
            "status": result["status"],
            "thread": session.thread,
            "time": int(time.time() * 1000),
            "request_kind": result["request_kind"],
            "operations_requested": result["operations_requested"],
            "browser_calls_returned": result["browser_calls_returned"],
            "browser_errors": result["browser_errors"],
            "browser_error_categories": list(result["browser_error_categories"]),
        }
        try:
            data_dir = getattr(self.ctx, "data_dir", None) or getattr(
                getattr(self.ctx, "state", None), "data_dir", None
            )
            if not data_dir:
                return
            path = Path(data_dir) / "secure_handoff_receipts.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            encoded = json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n"
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(encoded)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except (OSError, TypeError, ValueError):
            pass

    async def _reject_submission(self, session: Session, status: str = "rejected") -> None:
        session.status = status
        self._scrub(session, keep_receipt=False)
        if session.wake:
            session.wake.set()

    async def _web_data(self, update: Any, context: Any) -> None:
        from telegram.ext import ApplicationHandlerStop

        raw = getattr(
            getattr(getattr(update, "effective_message", None), "web_app_data", None),
            "data",
            None,
        )
        try:
            outer = strict_json(raw, limit=4096)
            request_id = outer.get("id") if isinstance(outer, dict) else None
        except ValueError:
            request_id = None
        if not isinstance(request_id, str) or not _REQUEST_NAMESPACE_RE.fullmatch(request_id):
            return
        matches = [
            item for item in self.sessions.values()
            if item.request is not None and item.request.get("id") == request_id
        ]
        if len(matches) != 1:
            raise ApplicationHandlerStop
        session = matches[0]

        result: dict[str, Any] | None = None
        wake_status = "execution_complete"
        wake_origin = ""
        async with session.lock:
            identity = self._authorized(update)
            if not self._callback_scope_matches(session, identity) or not self._current(session):
                raise ApplicationHandlerStop
            if request_id in session.used_ids:
                raise ApplicationHandlerStop
            request = session.request
            if request is None or request.get("id") != request_id:
                raise ApplicationHandlerStop
            if request.get("expiresAt", 0) <= int(time.time() * 1000):
                session.used_ids.add(request_id)
                await self._reject_submission(session, "expired")
                raise ApplicationHandlerStop

            payload: dict[str, Any] | None = None
            try:
                payload = decrypt_submission(raw, request, session.key)
            except ValueError:
                await self._reject_submission(session)
                raise ApplicationHandlerStop

            kind = request["kind"]
            request_fields = tuple(dict(item) for item in request.get("fields", []))
            plan = [dict(item) for item in session.execution_plan]
            if kind == "action_approval" and plan:
                plan[0]["target"] = session.refs.get(plan[0].get("ref"))
            # A valid request is consumed before the first browser operation.
            session.used_ids.add(request_id)
            session.request = None
            session.key = None
            session.refs.clear()
            if session.deadline is not None:
                session.deadline.cancel()
                session.deadline = None

            requested = len(plan) if kind == "entry" else 1
            returned = 0
            categories: list[str] = []
            try:
                if kind == "entry":
                    for field in request_fields:
                        value = payload.pop(field["id"])
                        operations = [item for item in plan if item.get("field_id") == field["id"]]
                        for operation in operations:
                            try:
                                if len(operations) == 1 and "value_index" not in operation:
                                    await asyncio.wait_for(
                                        self._fill_bound_field(session, field, value),
                                        timeout=BROWSER_OPERATION_TIMEOUT_SECONDS,
                                    )
                                else:
                                    await asyncio.wait_for(
                                        self._fill_bound_field(session, field, value, operation),
                                        timeout=BROWSER_OPERATION_TIMEOUT_SECONDS,
                                    )
                                returned += 1
                            except Exception as error:
                                categories.append(self._browser_error_category(error))
                        value = None
                else:
                    try:
                        await asyncio.wait_for(
                            self._commit_selected_action(session, plan[0] if plan else None),
                            timeout=BROWSER_OPERATION_TIMEOUT_SECONDS,
                        )
                        returned += 1
                    except Exception as error:
                        categories.append(self._browser_error_category(error))
            finally:
                if payload is not None:
                    payload.clear()
                payload = None
                request_fields = ()
                plan.clear()
                session.execution_plan.clear()
                session.inventory_refs.clear()
                session.control_refs.clear()
                session.inventory_meta.clear()
                session.inventory_snapshot = None
                session.snapshot_ref = None

            result = {
                "status": "execution_complete",
                "request_kind": kind,
                "operations_requested": requested,
                "browser_calls_returned": returned,
                "browser_errors": len(categories),
                "browser_error_categories": categories,
            }
            session.status = "execution_complete"
            session.receipt = dict(result)
            self._record_receipt(session, request_id, result)
            wake_status = result["status"]
            wake_origin = self._safe_origin(session)
            if session.wake:
                session.wake.set()

        self._schedule_wake(session, status=wake_status, origin=wake_origin)
        await self._send(
            context,
            session.chat,
            session.thread,
            self._wake_text(wake_status, wake_origin),
        )
        raise ApplicationHandlerStop

    def _authorized(self, update: Any):
        user = getattr(update, "effective_user", None)
        chat = getattr(update, "effective_chat", None)
        user_id = getattr(user, "id", None)
        chat_id = getattr(chat, "id", None)
        if (
            type(user_id) is not int
            or type(chat_id) is not int
            or getattr(chat, "type", None) != "private"
            or user_id not in self._owners()
        ):
            return None
        message = getattr(update, "effective_message", None)
        thread = getattr(message, "message_thread_id", None)
        if type(thread) is not int or thread <= 0:
            topic = getattr(message, "direct_messages_topic", None)
            topic_id = getattr(topic, "topic_id", None)
            if topic_id is None and isinstance(topic, dict):
                topic_id = topic.get("topic_id")
            thread = topic_id if type(topic_id) is int and topic_id > 0 else None
        return user_id, chat_id, thread

    def _callback_scope_matches(self, session: Session, identity) -> bool:
        """Match the owner and the exact private handoff chat (and any supplied topic)."""
        if identity is None:
            return False
        user, chat, thread = identity
        handoff_chat, handoff_thread = self._handoff_target(session)
        if (user, chat) != (session.user, handoff_chat):
            return False
        # A topicless Web App callback is correlated by its unique request ID.
        return thread is None or thread == handoff_thread

    @staticmethod
    def _safe_send_reason(error: Exception | None) -> str:
        name = type(error).__name__.casefold() if error is not None else "unknown"
        return "timeout" if "timeout" in name else "send_error"

    async def _send(self, context: Any, chat: int, thread: int | None, text: str, markup: Any = None) -> bool:
        if markup is None:
            routed = getattr(self.adapter, "send", None)
            if callable(routed):
                metadata = {"thread_id": str(thread)} if thread is not None else None
                try:
                    outcome = routed(chat, text, metadata=metadata)
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                    success = getattr(outcome, "success", None)
                    return bool(success) if success is not None else outcome is not False
                except Exception as error:
                    logger.warning(
                        "[Telegram] Secure handoff status send failed (%s)",
                        self._safe_send_reason(error),
                    )
                    return False
        sender = getattr(getattr(context, "bot", None) or self.bot, "send_message", None)
        if not callable(sender):
            return False
        kwargs = {"chat_id": chat, "text": text}
        if thread is not None:
            kwargs["message_thread_id"] = thread
        if markup is not None:
            kwargs["reply_markup"] = markup
        try:
            outcome = sender(**kwargs)
            if inspect.isawaitable(outcome):
                outcome = await outcome
            return outcome is not False
        except Exception as error:
            logger.warning(
                "[Telegram] Secure handoff publication send failed (%s)",
                self._safe_send_reason(error),
            )
            return False

    def _wake_text(self, status: str, origin: str, *_args, **_kwargs) -> str:
        return (
            "[secure-handoff wakeup] Submission received; execution attempt finished. "
            f"Status: {status}. Target origin: {origin or 'unknown'}. "
            "Inspect the live browser to determine the resulting state. "
            "No authentication, provider, form, action, or outcome success is claimed."
        )

    def _schedule_wake(
        self,
        session: Session,
        *,
        status: str | None = None,
        origin: str | None = None,
    ) -> None:
        if self.adapter is None or self.loop is None or not self.loop.is_running():
            return
        immutable_status = session.status if status is None else status
        immutable_origin = self._safe_origin(session) if origin is None else origin
        try:
            self.loop.create_task(
                self._wake_session(
                    immutable_status,
                    session.user,
                    session.chat,
                    session.thread,
                    session.chat_type,
                    immutable_origin,
                )
            )
        except Exception:
            pass

    async def _wake_session(self, status, user, chat, thread, chat_type, origin) -> None:
        if status != "execution_complete" or self.adapter is None:
            return
        source = SimpleNamespace(
            chat_id=str(chat),
            user_id=str(user),
            thread_id=str(thread) if thread is not None else None,
            chat_type=str(chat_type or "dm"),
        )
        try:
            await self._deliver_wake(self.adapter, self._wake_text(status, origin), source)
        except Exception as error:
            logger.warning(
                "[Telegram] Secure handoff status wake failed (%s)",
                self._safe_send_reason(error),
            )

    async def _deliver_wake(self, adapter: Any, text: str, source: Any) -> None:
        from gateway.config import Platform
        from gateway.session import SessionSource
        from gateway.wake import deliver_wake

        real_source = SessionSource(
            platform=Platform.TELEGRAM,
            chat_id=str(source.chat_id),
            chat_type=str(getattr(source, "chat_type", None) or "dm"),
            user_id=str(source.user_id) if source.user_id else None,
            thread_id=str(source.thread_id) if source.thread_id is not None else None,
        )
        await deliver_wake(adapter, text=text, source=real_source)

    def _origin_identity(self, update: Any):
        """Owner-scoped origin identity (DM, group, or forum topic) from a command update.

        Mirrors the Telegram adapter's routable-thread rules so the value matches the
        session vars captured when the flow was attached; anything ambiguous fails
        closed.
        """
        user = getattr(update, "effective_user", None)
        chat = getattr(update, "effective_chat", None)
        user_id = getattr(user, "id", None)
        chat_id = getattr(chat, "id", None)
        if type(user_id) is not int or type(chat_id) is not int or user_id not in self._owners():
            return None
        raw_chat_type = getattr(chat, "type", None)
        chat_type = str(getattr(raw_chat_type, "value", raw_chat_type) or "").strip().lower()
        if chat_type == "private":
            kind, is_group = "dm", False
        elif chat_type in {"group", "supergroup"}:
            kind, is_group = "group", True
        else:
            return None
        message = getattr(update, "effective_message", None)
        raw_thread = getattr(message, "message_thread_id", None)
        is_forum = is_group and getattr(chat, "is_forum", False) is True
        thread = None
        if raw_thread is not None:
            is_topic = bool(getattr(message, "is_topic_message", False))
            if (is_forum or is_topic) and type(raw_thread) is int and raw_thread > 0:
                thread = raw_thread
        elif is_forum:
            thread = 1
        return (user_id, chat_id, thread, kind)

    async def cancel_from_update(self, update: Any) -> bool:
        identity = self._origin_identity(update)
        if identity is None:
            return False
        cancelled = False
        async with self._admission_lock:
            sessions = [
                session for session in self.sessions.values()
                if self._origin_of(session) == identity
            ]
            for session in sessions:
                async with session.lock:
                    if not self._current(session):
                        continue
                    session_ref = session.session_ref
                    if session_ref is None:
                        continue
                    if session.request and isinstance(session.request.get("id"), str):
                        session.used_ids.add(session.request["id"])
                    session.status = "cancelled"
                    self._scrub(session)
                    self.sessions.pop(session_ref, None)
                    if session.wake:
                        session.wake.set()
                    cancelled = True
        await self._dispose_if_idle()
        return cancelled

    def _owns_request_id(self, request_id: Any) -> bool:
        return isinstance(request_id, str) and _REQUEST_NAMESPACE_RE.fullmatch(request_id) is not None

    def wire(self, application: Any, adapter: Any = None) -> None:
        self.adapter = adapter
        try:
            self.loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        self.bot = getattr(application, "bot", None)
        from telegram.ext import MessageHandler, filters

        controller = self

        class Owned(filters.MessageFilter):
            def filter(_, message):
                raw = getattr(getattr(message, "web_app_data", None), "data", None)
                try:
                    value = strict_json(raw, limit=4096)
                    request_id = value.get("id") if isinstance(value, dict) else None
                except ValueError:
                    request_id = None
                return controller._owns_request_id(request_id)

        application.add_handler(
            MessageHandler(
                filters.StatusUpdate.WEB_APP_DATA & Owned(),
                self._web_data,
                block=True,
            ),
            group=PLUGIN_HANDLER_GROUP,
        )

    def _submit(self, coroutine):
        if self.loop is None or not self.loop.is_running():
            try:
                coroutine.close()
            except Exception:
                pass
            return {"status": "unavailable"}
        future = asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        try:
            return future.result(95)
        except TimeoutError:
            future.cancel()
            return {"status": "unavailable"}
        except Exception:
            return {"status": "unavailable"}

    def tool(self, args: Any = None, **kwargs: Any) -> str:
        if args is not None and not isinstance(args, dict):
            return '{"status":"invalid"}'
        payload = dict(args) if isinstance(args, dict) else dict(kwargs)
        action = payload.get("action")
        allowed = {
            "attach": {"action", "origin", "ref"},
            "inventory": {"action", "session_ref"},
            "present_entry": {"action", "session_ref", "snapshot_ref", "fields", "view"},
            "present_action": {"action", "session_ref", "snapshot_ref", "action_ref", "summary"},
            "read": {"action", "session_ref"},
            "close": {"action", "session_ref"},
        }
        ident = self._identity()
        if action not in allowed or set(payload) - allowed[action]:
            return '{"status":"invalid"}'
        if (
            ident is None
            or len(ident) != 4
            or type(ident[0]) is not int
            or type(ident[1]) is not int
            or ident[0] <= 0
            or ident[1] == 0
            or ident[3] not in {"dm", "group", "forum"}
            or (ident[3] == "dm") != (ident[1] > 0)
            or ident[0] not in self._owners()
            or (ident[2] is not None and (type(ident[2]) is not int or ident[2] <= 0))
        ):
            result = {"status": "rejected"}
        else:
            result = self._submit(self._run(action, payload, ident))
        return json.dumps(result, separators=(",", ":"))

    def close(self, session_ref: str | None = None):
        identity = self._identity()
        if identity is None or session_ref is None:
            return {"status": "unavailable", "reason": "invalid_session"}
        return self._submit(self._close(session_ref, identity))


_TOOL_FIELD_TYPES = [
    "text", "password", "email", "tel", "url", "number", "search",
    "textarea", "select", "checkbox", "radio", "date", "time",
    "datetime-local", "month", "week", "color", "range",
]
_TOOL_FIELD_REF_SCHEMA = {"type": "string", "pattern": "^fr_[A-Za-z0-9_-]{32}$"}
_TOOL_FIELD_BASE = {
    "ref": _TOOL_FIELD_REF_SCHEMA,
    "label": {"type": "string", "minLength": 1, "maxLength": 80},
    "type": {"type": "string", "enum": _TOOL_FIELD_TYPES},
    "required": {"type": "boolean"},
    "strategy": {"type": "string", "enum": ["keyboard", "fill", "select", "check"]},
}
_TOOL_BINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["mode", "refs"],
    "properties": {
        "mode": {"type": "string", "enum": ["split_chars"]},
        "refs": {
            "type": "array",
            "minItems": 1,
            "maxItems": 11,
            "uniqueItems": True,
            "items": _TOOL_FIELD_REF_SCHEMA,
        },
    },
}


def _segmented_tool_field(alphabet: str, field_type: str) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["ref", "label", "type", "required", "strategy", "component"],
        "properties": {
            **_TOOL_FIELD_BASE,
            "type": {"type": "string", "enum": [field_type]},
            "required": {"type": "boolean", "enum": [True]},
            "strategy": {"type": "string", "enum": ["keyboard"]},
            "component": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "length", "alphabet"],
                "properties": {
                    "kind": {"type": "string", "enum": ["segmented_code"]},
                    "length": {"type": "integer", "minimum": 4, "maximum": 12},
                    "alphabet": {"type": "string", "enum": [alphabet]},
                },
            },
            "binding": _TOOL_BINDING_SCHEMA,
        },
    }


_TOOL_FIELD_SCHEMA = {
    "oneOf": [
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["ref", "label", "type", "required", "strategy"],
            "properties": _TOOL_FIELD_BASE,
        },
        _segmented_tool_field("digits", "tel"),
        _segmented_tool_field("alphanumeric", "text"),
    ],
}
_TOOL_CHILDREN_SCHEMA = {
    "type": "array",
    "minItems": 1,
    "maxItems": 24,
    "items": {"$ref": "#/$defs/view_node"},
}
_TOOL_VIEW_NODE_SCHEMA = {
    "oneOf": [
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "children"],
            "properties": {
                "kind": {"type": "string", "enum": ["stack"]},
                "children": _TOOL_CHILDREN_SCHEMA,
            },
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "children"],
            "properties": {
                "kind": {"type": "string", "enum": ["row"]},
                "children": _TOOL_CHILDREN_SCHEMA,
            },
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "title", "children"],
            "properties": {
                "kind": {"type": "string", "enum": ["section"]},
                "title": {"type": "string", "minLength": 1, "maxLength": 80},
                "children": _TOOL_CHILDREN_SCHEMA,
            },
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "text", "tone"],
            "properties": {
                "kind": {"type": "string", "enum": ["text"]},
                "text": {"type": "string", "minLength": 1, "maxLength": 240},
                "tone": {"type": "string", "enum": ["normal", "muted"]},
            },
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind"],
            "properties": {"kind": {"type": "string", "enum": ["divider"]}},
        },
        {
            "type": "object",
            "additionalProperties": False,
            "required": ["kind", "ref"],
            "properties": {
                "kind": {"type": "string", "enum": ["field"]},
                "ref": _TOOL_FIELD_REF_SCHEMA,
            },
        },
    ],
}
_TOOL_VIEW_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema", "kind", "children"],
    "properties": {
        "schema": {"type": "string", "enum": ["secure-handoff.ui/1"]},
        "kind": {"type": "string", "enum": ["stack"]},
        "children": _TOOL_CHILDREN_SCHEMA,
    },
    "description": (
        "Optional secure-handoff.ui/1 bounded data-only layout AST. Every field appears exactly once; "
        "no HTML, URLs, code, styles, actions, network behavior, or conditional behavior."
    ),
}


SCHEMA = {
    "name": "telegram_secure_handoff",
    "description": (
        "Bind an exact existing browser target, inventory generic controls, and present "
        "encrypted v4 entry or a separate one-shot exact action approval for one "
        "session_ref-scoped flow. Results report mechanical execution counts only; inspect "
        "the live browser afterward."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "action": {
                "type": "string",
                "enum": ["attach", "inventory", "present_entry", "present_action", "read", "close"],
            },
            "origin": {"type": "string"},
            "ref": {"type": "string", "pattern": "^[0-9A-Fa-f]{32}$"},
            "session_ref": {"type": "string", "pattern": "^ss_[A-Za-z0-9_-]{32}$"},
            "snapshot_ref": {"type": "string", "pattern": "^sn_[A-Za-z0-9_-]{32}$"},
            "action_ref": {"type": "string", "pattern": "^ar_[A-Za-z0-9_-]{32}$"},
            "summary": {"type": "string", "minLength": 1, "maxLength": 160},
            "fields": {
                "type": "array",
                "minItems": 1,
                "maxItems": 24,
                "items": _TOOL_FIELD_SCHEMA,
            },
            "view": _TOOL_VIEW_SCHEMA,
        },
        "$defs": {"view_node": _TOOL_VIEW_NODE_SCHEMA},
        "allOf": [
            {
                "if": {"required": ["action"], "properties": {"action": {"enum": [action]}}},
                "then": {
                    "required": required,
                    "not": {"anyOf": [{"required": [name]} for name in forbidden]},
                },
            }
            for action, required, forbidden in (
                (
                    "attach",
                    ["action", "origin"],
                    ["session_ref", "snapshot_ref", "action_ref", "summary", "fields", "view"],
                ),
                (
                    "inventory",
                    ["action", "session_ref"],
                    ["origin", "ref", "snapshot_ref", "action_ref", "summary", "fields", "view"],
                ),
                (
                    "present_entry",
                    ["action", "session_ref", "snapshot_ref", "fields"],
                    ["origin", "ref", "action_ref", "summary"],
                ),
                (
                    "present_action",
                    ["action", "session_ref", "snapshot_ref", "action_ref", "summary"],
                    ["origin", "ref", "fields", "view"],
                ),
                (
                    "read",
                    ["action", "session_ref"],
                    ["origin", "ref", "snapshot_ref", "action_ref", "summary", "fields", "view"],
                ),
                (
                    "close",
                    ["action", "session_ref"],
                    ["origin", "ref", "snapshot_ref", "action_ref", "summary", "fields", "view"],
                ),
            )
        ],
        "required": ["action"],
    },
}


def register(ctx: Any):
    controller = SecureHandoffController(ctx)
    if controller.config is None or len(controller.config.allowed_user_ids) != 1:
        return None
    try:
        controller._configured_cdp_url()
    except ValueError:
        return None
    ctx.register_tool(
        name="telegram_secure_handoff",
        toolset="telegram_secure_handoff",
        schema=SCHEMA,
        handler=controller.tool,
    )
    ctx.register_telegram_handler(controller.wire)
    return controller


def wire(controller: SecureHandoffController, application: Any, adapter: Any = None) -> None:
    controller.wire(application, adapter)


__all__ = [
    "SecureHandoffController", "Session", "SCHEMA", "decrypt_submission",
    "make_request", "register", "wire",
]
